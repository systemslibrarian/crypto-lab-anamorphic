export interface MessageChoice {
  id: string;
  label: string;
  scalar: bigint;
}

// The paper encrypts a group element. This bounded lesson therefore maps a
// small, visible message vocabulary to distinct scalars and then to scalar·G.
// It does not pretend arbitrary browser strings are native ElGamal messages.
export const OVERT_MESSAGES: readonly MessageChoice[] = [
  { id: 'nominal', label: 'Routine status: all systems nominal', scalar: 101n },
  { id: 'maintenance', label: 'Routine maintenance approved', scalar: 102n },
  { id: 'delivery', label: 'Public delivery moved to Friday', scalar: 103n },
  { id: 'closed', label: 'Office closed for inventory', scalar: 104n }
];

export const COVERT_MESSAGES: readonly MessageChoice[] = [
  { id: 'north', label: 'Use the north entrance', scalar: 1n },
  { id: 'delay', label: 'Delay the handoff', scalar: 2n },
  { id: 'archive', label: 'Copy reached the archive', scalar: 3n },
  { id: 'unsafe', label: 'Channel may be watched', scalar: 4n },
  { id: 'cancel', label: 'Cancel the meeting', scalar: 5n },
  { id: 'rotate', label: 'Rotate the double key', scalar: 6n },
  { id: 'fallback', label: 'Use the fallback route', scalar: 7n },
  { id: 'ack', label: 'Receipt confirmed', scalar: 8n }
];

export function choiceById(
  choices: readonly MessageChoice[],
  id: string
): MessageChoice {
  const choice = choices.find((candidate) => candidate.id === id);
  if (!choice) throw new RangeError(`Unknown message choice: ${id}`);
  return choice;
}
