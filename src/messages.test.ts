import { describe, expect, it } from 'vitest';
import { choiceById, COVERT_MESSAGES, OVERT_MESSAGES } from './messages.ts';

describe('bounded group-coded messages', () => {
  it('uses unique ids and non-overlapping scalar ranges', () => {
    const all = [...OVERT_MESSAGES, ...COVERT_MESSAGES];
    expect(new Set(all.map((choice) => choice.id)).size).toBe(all.length);
    expect(new Set(all.map((choice) => choice.scalar)).size).toBe(all.length);
    expect(COVERT_MESSAGES).toHaveLength(8);
    expect(OVERT_MESSAGES).toHaveLength(4);
  });

  it('finds declared choices and rejects missing ones', () => {
    expect(choiceById(OVERT_MESSAGES, 'nominal')).toEqual(OVERT_MESSAGES[0]);
    expect(() => choiceById(COVERT_MESSAGES, 'missing')).toThrow(/Unknown/);
  });
});
