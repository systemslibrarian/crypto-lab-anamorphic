import { describe, expect, it } from 'vitest';
import { runScenario } from './scenario.ts';

describe('learner coercion scenario', () => {
  it('derives every positive and negative verdict from one fresh run', () => {
    const result = runScenario('maintenance', 'archive', 19);
    expect(result.selected).toEqual({
      overt: 'Routine maintenance approved',
      covert: 'Copy reached the archive',
      counter: 19
    });
    expect(result.ordinaryRecovered).toBe(result.selected.overt);
    expect(result.covertRecovered).toBe(result.selected.covert);
    expect(result.wrongCounterRecovered).toBeNull();
    expect(result.wrongDoubleKeyRecovered).toBeNull();
    expect(result.normalControlRecovered).toBe(result.selected.overt);
    expect(result.normalControlCovert).toBeNull();
    expect(result.sameShapeAsNormal).toBe(true);
    expect(result.ciphertextBytes).toBe(64);
    expect(result.repeatedCounterReusesC2).toBe(true);
    expect(result.freshCounterChangesC2).toBe(true);
    expect(result.audit.relationHolds).toBe(true);
    expect(result.robustnessBound).toContain('< 2^-249');
  });

  it('reveals the complete ordinary key but only a double-key fingerprint', () => {
    const result = runScenario('nominal', 'north', 7);
    expect(result.ordinarySecretKey).toMatch(/^[0-9a-f]{64}$/);
    expect(result.doubleKey).toMatch(/^[0-9a-f]{24}$/);
    expect(result.publicKey).toMatch(/^[0-9a-f]{24}$/);
    expect(result.ciphertext).toMatch(/^[0-9a-f]{24}$/);
  });

  it('proves the independent-double-key control used a genuinely different key', () => {
    const result = runScenario('delivery', 'cancel', 42);
    expect(result.independentDoubleKey).toMatch(/^[0-9a-f]{24}$/);
    expect(result.independentDoubleKey).not.toBe(result.doubleKey);
    expect(result.wrongDoubleKeyRecovered).toBeNull();
  });

  it('refuses to render a vacuous independent-key control', () => {
    // A constant RNG hands the scenario the same bytes for both double keys.
    const constant = (length: number) => new Uint8Array(length).fill(0x01);
    expect(() => runScenario('nominal', 'north', 3, constant))
      .toThrow(/vacuous/);
  });

  it('rejects unknown learner choices', () => {
    expect(() => runScenario('not-overt', 'north', 1)).toThrow(/Unknown message choice/);
    expect(() => runScenario('nominal', 'not-covert', 1)).toThrow(/Unknown message choice/);
  });
});
