export interface ComparisonRow {
  system: string;
  carrier: string;
  disclosedView: string;
  hiddenView: string;
  boundary: string;
  href?: string;
}

export const COMPARISON_ROWS: readonly ComparisonRow[] = [
  {
    system: 'This lab: synchronized anamorphic ElGamal',
    carrier: 'One ordinary two-point ElGamal ciphertext; no mode or role field',
    disclosedView: 'The surrendered ordinary secret key recovers the prescribed overt group message',
    hiddenView: 'The separate PRF double key plus the synchronized counter recovers one bounded covert symbol',
    boundary: 'Receiver-anamorphic model; relies on DDH/PRF assumptions, a secret double key, and never-reused synchronized counters'
  },
  {
    system: 'Subliminal Channels',
    carrier: 'A valid ECDSA signature selected by public r parity',
    disclosedView: 'Anyone who knows the documented rule reads the extra bit directly',
    hiddenView: 'None: the bit is a public selection signal, not encrypted plaintext',
    boundary: 'Not encryption and not anamorphic security',
    href: 'https://systemslibrarian.github.io/crypto-lab-subliminal-channels/'
  },
  {
    system: 'Shadow Vault',
    carrier: 'A fixed-size container with two independently encrypted slots',
    disclosedView: 'A disclosed passphrase authenticates its configured real/decoy role to a format-aware reader',
    hiddenView: 'The other independently protected slot is not automatically decrypted',
    boundary: 'No role privacy; an extra role-revealing AEAD slot is not anamorphic encryption',
    href: 'https://systemslibrarian.github.io/crypto-lab-shadow-vault/'
  }
];
