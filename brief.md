# A-D-15 design record — synchronized robust anamorphic ElGamal

Date: 2026-10-27

## A-D-15 scope

The roadmap entry (`docs/encyclopedia-roadmap.md` in the Hub, "A-D-15 — Anamorphic
encryption under ordinary key disclosure", P3 specialist, Research extensions) states three
acceptance criteria. This lab addresses them as follows.

| Roadmap criterion | How this lab meets it |
| --- | --- |
| "Implement one explicitly named anamorphic construction/model or label an initial exhibit conceptual." | Banfi et al. Construction 6 / Figure 11 (`SyncAnamElGamal`) is implemented and executed, not described. The exhibit is **not** labelled conceptual. Five adaptations are declared on the page and in `docs/source-map.md`. |
| "Separate ordinary receiver/coercer and double-key receiver views, reveal the ordinary key and prescribed overt message, and compute the hidden receiver's additional result." | Three distinct cards render per run: sender, ordinary receiver/coercer, double-key receiver. The coercer card prints the complete 32-byte ordinary scalar secret key and the overt message recovered under it. The double-key card recovers the covert symbol from the same ciphertext using only `(K, ctr)`. |
| "Compare with the existing public subliminal bit and role-revealing decoy container without attributing anamorphic security to either." | The comparison table keeps three separate boundaries and is pinned by unit and browser tests. The note beneath it grounds the distinction in PPY22's own rejection of the append-a-string construction. |

Out of scope for this milestone and stated as such: the unsynchronized construction
(Sigma-3), the Cramer-Shoup and RSA-OAEP instantiations, multiple double keys per key pair,
and any Hub, corpus or catalog integration.

## Decision

Implement the synchronized robust anamorphic ElGamal extension `SyncAnamElGamal` from Banfi et al., EUROCRYPT 2024, Construction 6. Use the precomputed double-key form inherited from Construction 2 / Figure 8, instantiated additively over `ristretto255`.

This selection directly exercises the roadmap's coercion model: the ordinary receiver reveals the full ElGamal secret key and the prescribed overt message, while a receiver holding a separate double key recovers an additional bounded result from the same conventional two-point ciphertext. It avoids presenting a hidden field, parity signal or second AEAD slot as anamorphic security.

Do not implement the paper's unsynchronized construction or its Cramer–Shoup and RSA-OAEP routes in this milestone. The synchronized ElGamal construction is the smallest model that exposes the two receiver views, robustness behavior and counter-state limitation without substituting a toy format for the cited construction.

## Primary sources read

- Banfi, Gegier, Hirt, Maurer and Rito, “Anamorphic Encryption, Revisited,” EUROCRYPT 2024. The implemented route follows Definition 4.1, Construction 2 and its precomputation optimization, Lemmas 4.3–4.4, Lemma 5.1, and Construction 6 / Figure 11.
- Persiano, Phan and Yung, “Anamorphic Encryption: Private Communication against a Dictator,” EUROCRYPT 2022, for the foundational ordinary-key-disclosure model and terminology.
- RFC 9496 for the `ristretto255` group encoding used by the concrete browser profile.

## Executable profile

- The ordinary encryption scheme is textbook ElGamal in a prime-order group. In additive notation, `PK=sk G`, `C1=M+r PK`, `C2=r G`, and ordinary decryption returns `C1-sk C2`.
- The group is `ristretto255` as implemented by pinned `@noble/curves` 2.4.0. Ciphertexts serialize as two canonical 32-byte points.
- The double key is `(K,T,PK)`: a 32-byte HMAC key, an eight-entry `covertScalar G -> label` lookup table, and the ordinary public key. It contains no ordinary `sk`.
- The PRF is domain-separated HMAC-SHA-512 with the 32-bit counter and a 32-bit rejection-attempt label. Its first 32 output bytes are mapped into `Z_q` by rejection sampling. A known-answer test pins the exact framing and result.
- Anamorphic encryption derives `t=F(K,counter)` and uses `r=covertScalar+t mod q`. Anamorphic decryption derives the same `t`, computes `C2-t G`, and performs one lookup.
- Overt labels map to four small declared nonzero scalars and covert labels to the eight scalars 1 through 8. This keeps discrete-log recovery bounded and explicit; arbitrary text encoding is not claimed.
- Fresh key material comes from browser cryptographic randomness through the pinned noble utilities. Deterministic injected randomness is available only for tests.

## Security and robustness boundary

The cited security hybrid replaces the PRF with a random function. With unique counters,
adding a uniform mask makes the ElGamal randomness uniform, so the anamorphic and ordinary
encryption distributions are related by the PRF advantage. The browser does not empirically
prove that argument.

Lemma 4.3 is an **equality**, `Adv^sec = Adv^prf`, and it needs **no DDH**. That matters for
how this lab states its assumptions: the PRF is what keeps the covert symbol from a coercer
who holds `sk`, while DDH is what makes ordinary ElGamal IND-CPA and therefore protects the
*overt* message from an outsider who holds neither key. In the modeled coercion event the
coercer is handed `sk`, so DDH protects nothing from them. An earlier draft of this repo's
README said the argument "depends on the PRF hybrid and the ordinary ElGamal assumptions",
which conflates the two; the page, the README and `docs/source-map.md` now separate them.

For an ordinary ciphertext and a fixed counter, false recognition occurs if the recovered group element lands in the bounded covert table. Lemma 4.4 contributes `queries * covertSpaceSize / randomnessSpaceSize`, plus the PRF term. The profile therefore prints `8/q < 2^-249` for one query. It never prints “zero probability.”

Counter uniqueness is essential. Repeating a counter with the same double key and covert scalar repeats `r` and therefore `C2`, even when the overt message changes. The interface executes and labels this linkability control.

## Explicit non-claims

- No unsynchronized counter recovery, sender authentication, ciphertext integrity, CCA security, hybrid KEM/DEM, arbitrary plaintext codec, traffic-analysis defense or operational coercion protocol.
- No claim that HMAC-SHA-512, Ristretto arithmetic or this TypeScript implementation has been formally verified, independently audited, made constant-time or supplied with production key custody.
- No inference that one successful browser run proves distributional indistinguishability or real-world deniability.
- No claim that the public parity channel in Subliminal Channels or the two-slot AEAD format in Shadow Vault meets an anamorphic definition.

## Acceptance and negative evidence

1. The ciphertext object contains only `C1` and `C2`, and both ordinary and anamorphic executions serialize to 64 bytes.
2. The learner sees the complete ordinary `sk`, the overt decryption under that key, and a separate double-key recovery of the chosen covert symbol.
3. A normal ciphertext, wrong counter and independent double key provide explicit negative controls; the robustness term remains visible.
4. Counter reuse provides a positive linkability failure control, while a fresh counter changes `C2`.
5. The comparison table retains the exact public-bit and role-revealing-container boundaries of the adjacent labs.
6. The double key is derived from the public key alone, so it provably cannot contain the ordinary secret; a unit test asserts its field set.
7. The independent-double-key negative control carries the fingerprint of the key it actually used, and the scenario refuses to run rather than render a control in which both keys coincide.
8. The wire-shape verdict is a check that can fail: it rejects a third field, a component that does not re-decode, and a short encoding.
9. Unit, coverage, browser-claim, accessibility/reflow and named mutation gates own these claims and must all pass before any publication decision.

