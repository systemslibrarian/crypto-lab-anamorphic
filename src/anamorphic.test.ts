import { describe, expect, it } from 'vitest';
import {
  CIPHERTEXT_BYTES,
  GROUP_ORDER,
  Point,
  PRF_DOMAIN,
  createDoubleKey,
  decryptAnamorphic,
  decryptOrdinary,
  decryptOrdinaryPoint,
  doubleKeyFingerprint,
  encryptAnamorphic,
  encryptNormal,
  encryptNormalWithScalar,
  formatBound,
  isCanonicalWireCiphertext,
  generateKeyPair,
  pointHex,
  prfScalar,
  publicKeyFingerprint,
  randomScalar,
  robustnessBoundBits,
  robustnessBoundNumerator,
  sameCiphertextShape,
  SCALAR_DRAW_LIMIT,
  scalarHex,
  serializeCiphertext,
  type Rng
} from './anamorphic.ts';
import { COVERT_MESSAGES, OVERT_MESSAGES } from './messages.ts';

function scalarBytes(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, '0');
  return Uint8Array.from({ length: 32 }, (_, index) => (
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  ));
}

function sequenceRng(values: readonly bigint[]): Rng {
  let index = 0;
  return (length) => {
    expect(length).toBe(32);
    const value = values[index];
    if (value === undefined) throw new Error('test RNG exhausted');
    index += 1;
    return scalarBytes(value);
  };
}

describe('ristretto255 scalar and PRF layer', () => {
  it('pins the group order and the construction domain', () => {
    expect(GROUP_ORDER).toBe(2n ** 252n + 27742317777372353535851937790883648493n);
    expect(PRF_DOMAIN).toBe('CRYPTO-LAB-ANAMORPHIC-SYNC-ELGAMAL-v1');
    expect(Point.BASE.multiply(GROUP_ORDER - 1n).add(Point.BASE).is0()).toBe(true);
  });

  it('samples exactly in the scalar field and rejects an out-of-range candidate', () => {
    const sampled = randomScalar(sequenceRng([GROUP_ORDER, 17n]));
    expect(sampled).toBe(17n);
  });

  it('can admit zero for encryption randomness and reject it for a secret key', () => {
    expect(randomScalar(sequenceRng([0n]), true)).toBe(0n);
    expect(randomScalar(sequenceRng([0n, 9n]), false)).toBe(9n);
  });

  it('rejects an RNG with the wrong byte count', () => {
    expect(() => randomScalar(() => new Uint8Array(31))).toThrow(/32 bytes/);
  });

  it('gives up on a stuck RNG instead of looping forever', () => {
    // 0x1a exceeds the group order's leading 0x10, so every draw is rejected.
    let draws = 0;
    const stuck: Rng = () => {
      draws += 1;
      return new Uint8Array(32).fill(0x5a);
    };
    expect(() => randomScalar(stuck)).toThrow(/RNG is not sound/);
    expect(draws).toBe(SCALAR_DRAW_LIMIT);

    // allowZero=false must also terminate when the RNG only ever yields zero.
    expect(() => randomScalar(() => new Uint8Array(32), false)).toThrow(/RNG is not sound/);
  });

  it('pins HMAC-SHA-512 rejection mapping for one declared key and counter', () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => index);
    const output = prfScalar(key, 7);
    expect(output).toBe(5833353461038148736584295747526768296391010744945752022159451592399175615393n);
    expect(scalarHex(output)).toBe('0ce58fa15e4008c854616a7465020d36101457962bff5886a72ed8f668fd03a1');
    expect(prfScalar(key, 8)).not.toBe(output);
  });

  it('rejects invalid PRF keys and counters', () => {
    expect(() => prfScalar(new Uint8Array(31), 0)).toThrow(/32 bytes/);
    expect(() => prfScalar(new Uint8Array(32), -1)).toThrow(/Counter/);
    expect(() => prfScalar(new Uint8Array(32), 0x1_0000_0000)).toThrow(/Counter/);
  });
});

describe('synchronized robust anamorphic ElGamal', () => {
  const receiver = generateKeyPair(sequenceRng([123456789n]));
  const doubleKey = createDoubleKey(receiver.publicKey, new Uint8Array(32).fill(0x42));

  it('generates the public key as sk·G and keeps sk out of the double key', () => {
    expect(pointHex(receiver.publicKey)).toBe(pointHex(Point.BASE.multiply(receiver.secretKey)));
    expect('secretKey' in doubleKey).toBe(false);
    expect(Object.keys(doubleKey).sort()).toEqual(['covertTable', 'prfKey', 'publicKey']);
  });

  it('builds one injective lookup entry for every bounded covert symbol', () => {
    expect(doubleKey.covertTable.size).toBe(COVERT_MESSAGES.length);
    expect(new Set(COVERT_MESSAGES.map((message) => message.scalar)).size).toBe(COVERT_MESSAGES.length);
  });

  it('round-trips every overt message through normal ElGamal', () => {
    for (const [index, overt] of OVERT_MESSAGES.entries()) {
      const encrypted = encryptNormalWithScalar(receiver.publicKey, overt, BigInt(index + 20));
      expect(decryptOrdinary(receiver.secretKey, encrypted.ciphertext)).toEqual(overt);
    }
  });

  it('supports zero as the paper-defined encryption randomness without breaking correctness', () => {
    const overt = OVERT_MESSAGES[0]!;
    const encrypted = encryptNormalWithScalar(receiver.publicKey, overt, 0n);
    expect(encrypted.ciphertext.c2.is0()).toBe(true);
    expect(decryptOrdinary(receiver.secretKey, encrypted.ciphertext)).toEqual(overt);
  });

  it('fresh normal randomness changes both ciphertext points', () => {
    const overt = OVERT_MESSAGES[0]!;
    const left = encryptNormal(receiver.publicKey, overt, sequenceRng([40n]));
    const right = encryptNormal(receiver.publicKey, overt, sequenceRng([41n]));
    expect(pointHex(left.ciphertext.c1)).not.toBe(pointHex(right.ciphertext.c1));
    expect(pointHex(left.ciphertext.c2)).not.toBe(pointHex(right.ciphertext.c2));
  });

  it('recovers every overt/covert combination from its corresponding key view', () => {
    let counter = 100;
    for (const overt of OVERT_MESSAGES) {
      for (const covert of COVERT_MESSAGES) {
        const encrypted = encryptAnamorphic(doubleKey, overt, covert, counter);
        expect(decryptOrdinary(receiver.secretKey, encrypted.ciphertext)).toEqual(overt);
        expect(decryptAnamorphic(doubleKey, encrypted.ciphertext, counter)).toEqual(covert);
        expect(encrypted.randomness).toBe((encrypted.mask + covert.scalar) % GROUP_ORDER);
        counter += 1;
      }
    }
  });

  it('puts no mode or counter field into the two-point ciphertext', () => {
    const encrypted = encryptAnamorphic(doubleKey, OVERT_MESSAGES[1]!, COVERT_MESSAGES[2]!, 4);
    expect(Object.keys(encrypted.ciphertext).sort()).toEqual(['c1', 'c2']);
    expect(serializeCiphertext(encrypted.ciphertext)).toHaveLength(CIPHERTEXT_BYTES);
    expect('counter' in encrypted.ciphertext).toBe(false);
    expect('mode' in encrypted.ciphertext).toBe(false);
  });

  it('keeps normal and anamorphic ciphertexts structurally identical', () => {
    const overt = OVERT_MESSAGES[0]!;
    const normal = encryptNormalWithScalar(receiver.publicKey, overt, 55n);
    const anamorphic = encryptAnamorphic(doubleKey, overt, COVERT_MESSAGES[0]!, 55);
    expect(sameCiphertextShape(normal.ciphertext, anamorphic.ciphertext)).toBe(true);
    expect(serializeCiphertext(normal.ciphertext)).toHaveLength(64);
    expect(serializeCiphertext(anamorphic.ciphertext)).toHaveLength(64);
  });

  it('the wire-shape check is falsifiable: it rejects what is not two canonical points', () => {
    const honest = encryptAnamorphic(doubleKey, OVERT_MESSAGES[0]!, COVERT_MESSAGES[1]!, 31).ciphertext;
    expect(isCanonicalWireCiphertext(honest)).toBe(true);

    // A third field on the wire object: exactly what the construction forbids.
    const tagged = { ...honest, mode: 'anamorphic' } as unknown as typeof honest;
    expect(isCanonicalWireCiphertext(tagged)).toBe(false);
    expect(sameCiphertextShape(honest, tagged)).toBe(false);

    // A component that does not re-decode to the point it claims to encode.
    const forged = {
      c1: honest.c1,
      c2: { ...honest.c2, toBytes: () => new Uint8Array(32).fill(0xff) }
    } as unknown as typeof honest;
    expect(isCanonicalWireCiphertext(forged)).toBe(false);

    // A short encoding is not a 64-byte two-point ciphertext.
    const truncated = {
      c1: { ...honest.c1, toBytes: () => new Uint8Array(16) },
      c2: honest.c2
    } as unknown as typeof honest;
    expect(isCanonicalWireCiphertext(truncated)).toBe(false);
  });

  it('returns bottom for an ordinary ciphertext in the declared deterministic control', () => {
    const normal = encryptNormalWithScalar(receiver.publicKey, OVERT_MESSAGES[0]!, 42n);
    expect(decryptAnamorphic(doubleKey, normal.ciphertext, 7)).toBeNull();
  });

  it('returns bottom under a wrong counter and an independent double key', () => {
    const encrypted = encryptAnamorphic(doubleKey, OVERT_MESSAGES[0]!, COVERT_MESSAGES[0]!, 77);
    const independent = createDoubleKey(receiver.publicKey, new Uint8Array(32).fill(0x24));
    expect(decryptAnamorphic(doubleKey, encrypted.ciphertext, 78)).toBeNull();
    expect(decryptAnamorphic(independent, encrypted.ciphertext, 77)).toBeNull();
  });

  it('exposes counter reuse as repeated C2 for the same covert symbol', () => {
    const left = encryptAnamorphic(doubleKey, OVERT_MESSAGES[0]!, COVERT_MESSAGES[4]!, 91);
    const right = encryptAnamorphic(doubleKey, OVERT_MESSAGES[1]!, COVERT_MESSAGES[4]!, 91);
    const advanced = encryptAnamorphic(doubleKey, OVERT_MESSAGES[0]!, COVERT_MESSAGES[4]!, 92);
    expect(pointHex(left.ciphertext.c2)).toBe(pointHex(right.ciphertext.c2));
    expect(pointHex(left.ciphertext.c2)).not.toBe(pointHex(advanced.ciphertext.c2));
  });

  it('makes plain ElGamal malleability visible without changing the covert C2 view', () => {
    const encrypted = encryptAnamorphic(doubleKey, OVERT_MESSAGES[0]!, COVERT_MESSAGES[6]!, 121);
    const altered = {
      c1: encrypted.ciphertext.c1.add(Point.BASE),
      c2: encrypted.ciphertext.c2
    };
    expect(decryptOrdinary(receiver.secretKey, altered)).toEqual(OVERT_MESSAGES[1]);
    expect(decryptAnamorphic(doubleKey, altered, 121)).toEqual(COVERT_MESSAGES[6]);
    expect(pointHex(decryptOrdinaryPoint(receiver.secretKey, altered)))
      .not.toBe(pointHex(decryptOrdinaryPoint(receiver.secretKey, encrypted.ciphertext)));
  });

  it('derives display fingerprints from the actual key material', () => {
    const alternate = createDoubleKey(receiver.publicKey, new Uint8Array(32).fill(0x43));
    const alternateReceiver = generateKeyPair(sequenceRng([987654321n]));
    const alternatePublicKey = createDoubleKey(
      alternateReceiver.publicKey,
      new Uint8Array(32).fill(0x42)
    );
    expect(publicKeyFingerprint(receiver.publicKey)).toMatch(/^[0-9a-f]{24}$/);
    expect(doubleKeyFingerprint(doubleKey)).toMatch(/^[0-9a-f]{24}$/);
    expect(doubleKeyFingerprint(alternate)).not.toBe(doubleKeyFingerprint(doubleKey));
    expect(doubleKeyFingerprint(alternatePublicKey)).not.toBe(doubleKeyFingerprint(doubleKey));
  });

  it('states the paper-style robustness term for the eight-symbol table', () => {
    expect(robustnessBoundNumerator()).toBe(8n);
    expect(robustnessBoundNumerator(3)).toBe(24n);
    expect(robustnessBoundBits()).toBe(249);
    expect(formatBound()).toBe(`8/${GROUP_ORDER} < 2^-249`);
    expect(robustnessBoundNumerator(Number.MAX_SAFE_INTEGER))
      .toBe(BigInt(Number.MAX_SAFE_INTEGER) * 8n);
    expect(() => robustnessBoundNumerator(0)).toThrow(/positive/);
  });

  it('rejects malformed double-key inputs and undeclared covert messages', () => {
    expect(() => createDoubleKey(receiver.publicKey, new Uint8Array(1))).toThrow(/32 bytes/);
    expect(() => encryptAnamorphic(
      doubleKey,
      OVERT_MESSAGES[0]!,
      { id: 'outside', label: 'outside', scalar: 99n },
      1
    )).toThrow(/outside/);
    expect(() => encryptAnamorphic(
      doubleKey,
      OVERT_MESSAGES[0]!,
      { ...COVERT_MESSAGES[0]!, scalar: 99n },
      1
    )).toThrow(/outside/);
    expect(() => encryptNormalWithScalar(
      receiver.publicKey,
      { id: 'outside', label: 'outside', scalar: 101n },
      1n
    )).toThrow(/outside/);
  });
});
