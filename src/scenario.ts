import {
  CIPHERTEXT_BYTES,
  GROUP_ORDER,
  createDoubleKey,
  ciphertextFingerprint,
  decryptAnamorphic,
  decryptOrdinary,
  doubleKeyFingerprint,
  encryptAnamorphic,
  encryptNormal,
  formatBound,
  generateKeyPair,
  pointHex,
  publicKeyFingerprint,
  sameCiphertextShape,
  scalarHex,
  serializeCiphertext,
  type Rng
} from './anamorphic.ts';
import {
  choiceById,
  COVERT_MESSAGES,
  OVERT_MESSAGES
} from './messages.ts';

export interface ScenarioResult {
  selected: {
    overt: string;
    covert: string;
    counter: number;
  };
  publicKey: string;
  ordinarySecretKey: string;
  doubleKey: string;
  independentDoubleKey: string;
  ciphertext: string;
  ciphertextBytes: number;
  ordinaryRecovered: string | null;
  covertRecovered: string | null;
  wrongCounterRecovered: string | null;
  wrongDoubleKeyRecovered: string | null;
  normalControlRecovered: string | null;
  normalControlCovert: string | null;
  sameShapeAsNormal: boolean;
  repeatedCounterReusesC2: boolean;
  freshCounterChangesC2: boolean;
  robustnessBound: string;
  audit: {
    relationHolds: boolean;
    maskHex: string;
    covertScalarHex: string;
    randomnessHex: string;
  };
}

export function runScenario(
  overtId: string,
  covertId: string,
  counter: number,
  rng?: Rng
): ScenarioResult {
  const overt = choiceById(OVERT_MESSAGES, overtId);
  const covert = choiceById(COVERT_MESSAGES, covertId);
  const receiver = generateKeyPair(rng);
  const doubleKey = createDoubleKey(receiver.publicKey, rng?.(32));
  const anamorphic = encryptAnamorphic(doubleKey, overt, covert, counter);
  const normal = encryptNormal(receiver.publicKey, overt, rng);

  const wrongKey = createDoubleKey(receiver.publicKey, rng?.(32));
  // A negative control that silently used the SAME key would report a pass for
  // the wrong reason. Refuse rather than render a vacuous control.
  if (doubleKeyFingerprint(wrongKey) === doubleKeyFingerprint(doubleKey)) {
    throw new Error('Independent-double-key control is vacuous: both double keys coincide');
  }
  const otherOvert = OVERT_MESSAGES.find((candidate) => candidate.id !== overt.id)!;
  const reused = encryptAnamorphic(doubleKey, otherOvert, covert, counter);
  const fresh = encryptAnamorphic(doubleKey, overt, covert, counter + 1);
  const ordinaryRecovered = decryptOrdinary(receiver.secretKey, anamorphic.ciphertext);
  const covertRecovered = decryptAnamorphic(doubleKey, anamorphic.ciphertext, counter);
  const normalControlRecovered = decryptOrdinary(receiver.secretKey, normal.ciphertext);

  if (!ordinaryRecovered || !covertRecovered || !normalControlRecovered) {
    throw new Error('Construction correctness invariant failed');
  }

  const relationHolds = anamorphic.randomness
    === (anamorphic.mask + anamorphic.covertScalar) % GROUP_ORDER;

  return {
    selected: { overt: overt.label, covert: covert.label, counter },
    publicKey: publicKeyFingerprint(receiver.publicKey),
    ordinarySecretKey: scalarHex(receiver.secretKey),
    doubleKey: doubleKeyFingerprint(doubleKey),
    independentDoubleKey: doubleKeyFingerprint(wrongKey),
    ciphertext: ciphertextFingerprint(anamorphic.ciphertext),
    ciphertextBytes: serializeCiphertext(anamorphic.ciphertext).length,
    ordinaryRecovered: ordinaryRecovered.label,
    covertRecovered: covertRecovered.label,
    wrongCounterRecovered:
      decryptAnamorphic(doubleKey, anamorphic.ciphertext, counter + 1)?.label ?? null,
    wrongDoubleKeyRecovered:
      decryptAnamorphic(wrongKey, anamorphic.ciphertext, counter)?.label ?? null,
    normalControlRecovered: normalControlRecovered.label,
    normalControlCovert: decryptAnamorphic(doubleKey, normal.ciphertext, counter)?.label ?? null,
    sameShapeAsNormal: sameCiphertextShape(anamorphic.ciphertext, normal.ciphertext)
      && CIPHERTEXT_BYTES === serializeCiphertext(normal.ciphertext).length,
    repeatedCounterReusesC2: pointHex(reused.ciphertext.c2) === pointHex(anamorphic.ciphertext.c2),
    freshCounterChangesC2: pointHex(fresh.ciphertext.c2) !== pointHex(anamorphic.ciphertext.c2),
    robustnessBound: formatBound(),
    audit: {
      relationHolds,
      maskHex: scalarHex(anamorphic.mask),
      covertScalarHex: scalarHex(anamorphic.covertScalar),
      randomnessHex: scalarHex(anamorphic.randomness)
    }
  };
}
