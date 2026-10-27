import { describe, expect, it } from 'vitest';
import { COMPARISON_ROWS } from './comparison.ts';

describe('comparison boundary', () => {
  it('keeps the anamorphic, subliminal, and decoy-container claims distinct', () => {
    expect(COMPARISON_ROWS.map((row) => row.system)).toEqual([
      'This lab: synchronized anamorphic ElGamal',
      'Subliminal Channels',
      'Shadow Vault'
    ]);
    expect(COMPARISON_ROWS[0]!.carrier).toContain('no mode or role field');
    expect(COMPARISON_ROWS[1]!.boundary).toBe('Not encryption and not anamorphic security');
    expect(COMPARISON_ROWS[2]!.boundary).toContain('not anamorphic encryption');
  });

  it('names the exact disclosed and double-key views', () => {
    const row = COMPARISON_ROWS[0]!;
    expect(row.disclosedView).toContain('surrendered ordinary secret key');
    expect(row.hiddenView).toContain('double key');
    expect(row.boundary).toContain('PRF hides the covert symbol');
    expect(row.boundary).toContain('DDH protects ordinary ElGamal from outsiders');
    expect(row.boundary).toContain('synchronized counters must never repeat');
  });
});
