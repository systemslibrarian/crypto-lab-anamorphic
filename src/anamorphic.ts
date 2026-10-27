import { ristretto255 } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import {
  bytesToHex,
  concatBytes,
  randomBytes,
  utf8ToBytes
} from '@noble/hashes/utils.js';
import {
  COVERT_MESSAGES,
  OVERT_MESSAGES,
  type MessageChoice
} from './messages.ts';

/**
 * Banfi, Gegier, Hirt, Maurer & Rito, "Anamorphic Encryption, Revisited",
 * EUROCRYPT 2024 — Construction 6 / Figure 11 (SyncAnamElGamal), the
 * pre-computation form of Construction 2 / Figure 8 (Sigma-2'), instantiated
 * on the ElGamal PKE scheme of Construction 5.
 *
 * The paper writes a generic cyclic group G of prime order q multiplicatively.
 * This file writes ristretto255 additively. The transcription, line for line:
 *
 *   Construction 5 / Figure 11            This implementation
 *   ---------------------------------     ------------------------------------
 *   sk <-$ Z_q ; pk := g^sk               generateKeyPair: PK = sk·G
 *   c1 := m · pk^r                        encryptPoint:    C1 = M + r·PK
 *   c2 := g^r                             encryptPoint:    C2 = r·G
 *   Dec: c1 · c2^-sk                      decryptOrdinary: M  = C1 - sk·C2
 *   aGen: T[g^m̂] := m̂ ; dk := (K,T,pk)    createDoubleKey: covertTable, prfKey,
 *                                                          publicKey
 *   aEnc: t := F(K,ctr)                   encryptAnamorphic: mask = prfScalar
 *   aEnc: r := m̂ (+) t                    encryptAnamorphic: r = m̂ + t mod q
 *   aDec: s := c2 · g^-t                  decryptAnamorphic: S = C2 - t·G
 *   aDec: m̂ := T[s]  (absent => ⊥)        decryptAnamorphic: table lookup, null
 *
 * Lemma 5.1 establishes that ElGamal is SRR with (+) = addition modulo q,
 * which is why `r = m̂ + t mod q` is the paper's operation and not a stand-in.
 *
 * Declared adaptations (see docs/source-map.md):
 *   A1 ristretto255 transcription — a concrete prime-order group and encoding
 *      (RFC 9496) in place of the paper's abstract G.
 *   A2 bounded message spaces — M̂ = {1..8} ⊂ Z_q with ℓ = 8, and four declared
 *      overt group elements, in place of arbitrary M̂ ⊆ Z_q and m ∈ G.
 *   A3 external counter synchronization — the paper's aEnc/aDec return ctr+1
 *      and carry that state; here the counter is supplied per call, so
 *      uniqueness is the caller's duty and reuse is demonstrated, not blocked.
 *      F: K × [2^32] → Z_q, so τ = 2^32 for this profile.
 *   A4 browser implementation — TypeScript over @noble/curves; no constant-time,
 *      interoperability, or production-custody claim is made anywhere.
 *   A5 aGen narrowing — the paper's aGen(sk, pk) is given sk but places only
 *      (K, T, pk) in dk, so createDoubleKey takes the public key alone. The
 *      double key provably cannot contain the ordinary secret.
 *
 * The ciphertext is exactly two canonical ristretto255 points. It contains no
 * mode bit, hidden-message slot, counter, or role label.
 */

export const Point = ristretto255.Point;
export type GroupPoint = InstanceType<typeof Point>;
export const GROUP_ORDER = Point.Fn.ORDER;
export const CIPHERTEXT_BYTES = 64;
export const PRF_DOMAIN = 'CRYPTO-LAB-ANAMORPHIC-SYNC-ELGAMAL-v1';

export type Rng = (length: number) => Uint8Array;
export const defaultRng: Rng = (length) => randomBytes(length);

export interface KeyPair {
  secretKey: bigint;
  publicKey: GroupPoint;
}

export interface DoubleKey {
  prfKey: Uint8Array;
  publicKey: GroupPoint;
  covertTable: ReadonlyMap<string, MessageChoice>;
}

/** Deliberately has no mode, role, message, or counter field. */
export interface Ciphertext {
  c1: GroupPoint;
  c2: GroupPoint;
}

export interface EncryptionResult {
  ciphertext: Ciphertext;
  randomness: bigint;
}

export interface AnamorphicEncryptionResult extends EncryptionResult {
  mask: bigint;
  covertScalar: bigint;
  counter: number;
}

function mod(value: bigint): bigint {
  const reduced = value % GROUP_ORDER;
  return reduced < 0n ? reduced + GROUP_ORDER : reduced;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  const hex = bytesToHex(bytes);
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

function u32(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError('Counter must be an integer in [0, 2^32-1]');
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function scalarBytes(value: bigint): Uint8Array {
  let hex = mod(value).toString(16).padStart(64, '0');
  if (hex.length > 64) hex = hex.slice(-64);
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function scalarPoint(scalar: bigint): GroupPoint {
  const reduced = mod(scalar);
  return reduced === 0n ? Point.ZERO : Point.BASE.multiply(reduced);
}

function multiplyPoint(point: GroupPoint, scalar: bigint): GroupPoint {
  const reduced = mod(scalar);
  return reduced === 0n || point.is0() ? Point.ZERO : point.multiply(reduced);
}

export function pointHex(point: GroupPoint): string {
  return bytesToHex(point.toBytes());
}

export function scalarHex(scalar: bigint): string {
  return bytesToHex(scalarBytes(scalar));
}

/**
 * Exact rejection sampling in Z_q; no modulo-reduction bias.
 *
 * Each draw is accepted with probability q/2^253 > 0.46, so SCALAR_DRAW_LIMIT
 * draws fail with probability below 2^-200 for a sound RNG. The loop is bounded
 * anyway: an unbounded one hangs forever on a stuck or constant RNG instead of
 * reporting that the RNG is broken, and prfScalar already bounds its retries.
 */
export const SCALAR_DRAW_LIMIT = 256;

export function randomScalar(
  rng: Rng = defaultRng,
  allowZero = true
): bigint {
  for (let draw = 0; draw < SCALAR_DRAW_LIMIT; draw += 1) {
    const bytes = Uint8Array.from(rng(32));
    if (bytes.length !== 32) throw new RangeError('RNG must return exactly 32 bytes');
    bytes[0] = bytes[0]! & 0x1f; // Uniform candidate in [0, 2^253).
    const candidate = bytesToBigInt(bytes);
    if (candidate < GROUP_ORDER && (allowZero || candidate !== 0n)) return candidate;
  }
  throw new Error(
    `Rejection sampling found no scalar in ${SCALAR_DRAW_LIMIT} draws; the RNG is not sound`
  );
}

/**
 * HMAC-SHA-512 PRF mapped to Z_q by deterministic rejection sampling.
 * The retry label is part of the framed domain, so accepted outputs are
 * uniform in the random-function model rather than reduced modulo q.
 */
export function prfScalar(prfKey: Uint8Array, counter: number): bigint {
  if (prfKey.length !== 32) throw new RangeError('Double-key PRF key must be 32 bytes');
  for (let attempt = 0; attempt <= 0xffff_ffff; attempt += 1) {
    const digest = hmac(
      sha512,
      prfKey,
      concatBytes(utf8ToBytes(PRF_DOMAIN), u32(counter), u32(attempt))
    );
    const candidateBytes = Uint8Array.from(digest.slice(0, 32));
    candidateBytes[0] = candidateBytes[0]! & 0x1f;
    const candidate = bytesToBigInt(candidateBytes);
    if (candidate < GROUP_ORDER) return candidate;
  }
  throw new Error('PRF rejection sampling exhausted its 32-bit retry domain');
}

export function generateKeyPair(rng: Rng = defaultRng): KeyPair {
  const secretKey = randomScalar(rng, false);
  return { secretKey, publicKey: scalarPoint(secretKey) };
}

export function createDoubleKey(
  publicKey: GroupPoint,
  key: Uint8Array = defaultRng(32)
): DoubleKey {
  if (key.length !== 32) throw new RangeError('Double-key PRF key must be 32 bytes');
  const table = new Map<string, MessageChoice>();
  for (const message of COVERT_MESSAGES) {
    table.set(pointHex(scalarPoint(message.scalar)), message);
  }
  return {
    prfKey: Uint8Array.from(key),
    publicKey,
    covertTable: table
  };
}

function assertDeclaredMessage(
  choice: MessageChoice,
  choices: readonly MessageChoice[],
  kind: 'Overt' | 'Covert'
): void {
  const declared = choices.find((candidate) => candidate.id === choice.id);
  if (!declared || declared.label !== choice.label || declared.scalar !== choice.scalar) {
    throw new RangeError(`${kind} message is outside the declared bounded message space`);
  }
}

function encryptPoint(
  publicKey: GroupPoint,
  messagePoint: GroupPoint,
  randomness: bigint
): Ciphertext {
  const r = mod(randomness);
  return {
    c1: messagePoint.add(multiplyPoint(publicKey, r)),
    c2: scalarPoint(r)
  };
}

export function encryptNormal(
  publicKey: GroupPoint,
  overt: MessageChoice,
  rng: Rng = defaultRng
): EncryptionResult {
  assertDeclaredMessage(overt, OVERT_MESSAGES, 'Overt');
  const randomness = randomScalar(rng);
  return {
    ciphertext: encryptPoint(publicKey, scalarPoint(overt.scalar), randomness),
    randomness
  };
}

export function encryptNormalWithScalar(
  publicKey: GroupPoint,
  overt: MessageChoice,
  randomness: bigint
): EncryptionResult {
  assertDeclaredMessage(overt, OVERT_MESSAGES, 'Overt');
  return {
    ciphertext: encryptPoint(publicKey, scalarPoint(overt.scalar), randomness),
    randomness: mod(randomness)
  };
}

export function encryptAnamorphic(
  doubleKey: DoubleKey,
  overt: MessageChoice,
  covert: MessageChoice,
  counter: number
): AnamorphicEncryptionResult {
  assertDeclaredMessage(overt, OVERT_MESSAGES, 'Overt');
  assertDeclaredMessage(covert, COVERT_MESSAGES, 'Covert');
  const mask = prfScalar(doubleKey.prfKey, counter);
  const randomness = mod(covert.scalar + mask);
  return {
    ciphertext: encryptPoint(doubleKey.publicKey, scalarPoint(overt.scalar), randomness),
    randomness,
    mask,
    covertScalar: covert.scalar,
    counter
  };
}

export function decryptOrdinaryPoint(
  secretKey: bigint,
  ciphertext: Ciphertext
): GroupPoint {
  return ciphertext.c1.subtract(multiplyPoint(ciphertext.c2, secretKey));
}

export function decryptOrdinary(
  secretKey: bigint,
  ciphertext: Ciphertext
): MessageChoice | null {
  const recovered = pointHex(decryptOrdinaryPoint(secretKey, ciphertext));
  return OVERT_MESSAGES.find((message) => pointHex(scalarPoint(message.scalar)) === recovered) ?? null;
}

export function decryptAnamorphic(
  doubleKey: DoubleKey,
  ciphertext: Ciphertext,
  counter: number
): MessageChoice | null {
  const mask = prfScalar(doubleKey.prfKey, counter);
  const candidate = ciphertext.c2.subtract(scalarPoint(mask));
  return doubleKey.covertTable.get(pointHex(candidate)) ?? null;
}

export function serializeCiphertext(ciphertext: Ciphertext): Uint8Array {
  return concatBytes(ciphertext.c1.toBytes(), ciphertext.c2.toBytes());
}

export function ciphertextFingerprint(ciphertext: Ciphertext): string {
  return bytesToHex(sha256(serializeCiphertext(ciphertext))).slice(0, 24);
}

export function publicKeyFingerprint(publicKey: GroupPoint): string {
  return bytesToHex(sha256(publicKey.toBytes())).slice(0, 24);
}

export function doubleKeyFingerprint(doubleKey: DoubleKey): string {
  return bytesToHex(
    sha256(concatBytes(
      utf8ToBytes('double-key-fingerprint-v1'),
      doubleKey.prfKey,
      doubleKey.publicKey.toBytes()
    ))
  ).slice(0, 24);
}

/**
 * True when the object really is two canonical ristretto255 encodings that
 * re-decode to the same points, and carries no third field.
 *
 * This is a SYNTACTIC claim about the wire object. It is not evidence that
 * anamorphic and ordinary ciphertexts are distributed alike: Definition 3.3 is
 * a computational notion and Lemma 4.3 reduces it to the PRF, which no sample
 * drawn in a browser can establish.
 */
export function isCanonicalWireCiphertext(ciphertext: Ciphertext): boolean {
  if (Object.keys(ciphertext).sort().join(',') !== 'c1,c2') return false;
  const bytes = serializeCiphertext(ciphertext);
  if (bytes.length !== CIPHERTEXT_BYTES) return false;
  try {
    return Point.fromBytes(bytes.slice(0, 32)).equals(ciphertext.c1)
      && Point.fromBytes(bytes.slice(32)).equals(ciphertext.c2);
  } catch {
    return false;
  }
}

export function sameCiphertextShape(left: Ciphertext, right: Ciphertext): boolean {
  return isCanonicalWireCiphertext(left)
    && isCanonicalWireCiphertext(right)
    && serializeCiphertext(left).length === serializeCiphertext(right).length;
}

/**
 * Lemma 4.4: Adv^rob <= Adv^prf(D') + q·ℓ/ρ, where q is the distinguisher's
 * query count, ℓ = |M̂| and ρ = |R|. For ElGamal, R = Z_q so ρ is the group
 * order. These helpers compute ONLY the q·ℓ/ρ term; the PRF term is not
 * derivable here and is always reported alongside it in words.
 */
export function robustnessBoundNumerator(queries = 1): bigint {
  if (!Number.isSafeInteger(queries) || queries < 1) {
    throw new RangeError('Queries must be a positive safe integer');
  }
  return BigInt(queries) * BigInt(COVERT_MESSAGES.length);
}

export function robustnessBoundBits(queries = 1): number {
  const numerator = robustnessBoundNumerator(queries);
  const quotient = GROUP_ORDER / numerator;
  return Math.max(0, quotient.toString(2).length - 1);
}

/** Renders the q·ℓ/ρ term as a strict power-of-two upper bound. */
export function formatBound(queries = 1): string {
  return `${robustnessBoundNumerator(queries)}/${GROUP_ORDER} < 2^-${robustnessBoundBits(queries)}`;
}
