# Source map: primary sources to code, and claims to tests

Every equation this lab executes is traced here to the line that executes it, and
every learner-visible claim to the test that owns it. Line anchors are stated as
`file:line` against the commit that introduced this document; they rot, so if one
does not land where it says, re-derive it before concluding the claim moved.

## Primary sources

| Key | Work |
| --- | --- |
| **BGHMR24** | Banfi, Gegier, Hirt, Maurer & Rito, *Anamorphic Encryption, Revisited*, EUROCRYPT 2024. <https://eprint.iacr.org/2023/249> · <https://crypto.ethz.ch/publications/files/BGHMR24.pdf> |
| **PPY22** | Persiano, Phan & Yung, *Anamorphic Encryption: Private Communication against a Dictator*, EUROCRYPT 2022. <https://eprint.iacr.org/2022/639> |
| **RFC 9496** | Nick, Hamburg, Ladd & Valsorda, *The ristretto255 and decaf448 Groups*. <https://www.rfc-editor.org/rfc/rfc9496> |

Both BGHMR24 copies were read for this lab and carry identical numbering: Construction 5
and 6 in Section 5.1, Figure 11, Lemmas 4.3 and 4.4 in Section 4.3.

## Construction to code

BGHMR24 Construction 6 / Figure 11 is `SyncAnamElGamal`, the **pre-computation** form
(Construction 2 / Figure 8, Sigma-2') of the generic synchronized extension, instantiated
on the ElGamal PKE scheme of Construction 5. It inherits security and robustness from
Lemmas 4.3 and 4.4, which are stated for Construction 2.

The paper writes a generic prime-order group multiplicatively; this lab writes
ristretto255 additively. `G` is the generator, `ℓ` the group order, `·` scalar
multiplication.

| BGHMR24 | Paper statement | Code |
| --- | --- | --- |
| Construction 5, Gen | `sk <-$ Z_q`, `pk := g^sk` | `PK = sk·G` — `src/anamorphic.ts:191` |
| Construction 5, Enc | `c1 := m · pk^r`, `c2 := g^r` | `C1 = M + r·PK`, `C2 = r·G` — `src/anamorphic.ts:223` |
| Construction 5, Dec | `c1 · c2^-sk` | `M = C1 - sk·C2` — `src/anamorphic.ts:279` |
| Lemma 5.1, item 1 | randomness space `<Z_q; ⊕>` with `⊕` addition mod `q` | `mod(covert.scalar + mask)` — `src/anamorphic.ts:260` |
| Lemma 5.1, item 2 | `α(pk,m,r) = m·pk^r`, `β(r) = g^r`, both injective | the two components of `encryptPoint` — `src/anamorphic.ts:223` |
| Lemma 5.1, item 3 | `γ(a,b) = a·g^-b`, `γ(β(a⊕b), b) = β(a)` | `C2 - t·G` — `src/anamorphic.ts:294` |
| Figure 11, aGen 01 | `K <-$ K` | 32-byte PRF key — `src/anamorphic.ts:196` |
| Figure 11, aGen 02–04 | `T[g^m̂] := m̂` for each `m̂ ∈ M̂` | `covertTable` keyed on `pointHex(m̂·G)` — `src/anamorphic.ts:196` |
| Figure 11, aGen 05 | `dk := (K, T, pk)` — note **no `sk`** | `{ prfKey, publicKey, covertTable }` — `src/anamorphic.ts:196` |
| Figure 11, aEnc 01 | `t := F(K, ctr)` | `prfScalar` — `src/anamorphic.ts:175` |
| Figure 11, aEnc 02 | `r := m̂ ⊕ t` | `randomness = mod(covert.scalar + mask)` — `src/anamorphic.ts:260` |
| Figure 11, aEnc 03–05 | `c := (m·pk^r, g^r)` | same `encryptPoint` the normal path uses — `src/anamorphic.ts:260` |
| Figure 11, aDec 01 | `t := F(K, ctr)` | `prfScalar` — `src/anamorphic.ts:294` |
| Figure 11, aDec 02 | `s := c2 · g^-t` | `C2 - t·G` — `src/anamorphic.ts:294` |
| Figure 11, aDec 03–04 | `m̂ := T[s]` | table lookup — `src/anamorphic.ts:294` |
| Figure 7, Sigma-2 aDec 06 | `return ⊥` when no `m̂` matches | `?? null` — `src/anamorphic.ts:294` |
| Definition 3.3 / Figure 3 | sec game: `Init` hands the distinguisher `(sk, pk)` | the coercer view discloses `sk` in full — `src/main.ts` coercer card |
| Lemma 4.3 | `Adv^sec = Adv^prf` | stated, not executed — limits section, `src/main.ts` |
| Definition 3.4 / Figure 4 | rob game: normal `Enc` then `aDec`, win if not `⊥` | `normalControlCovert` — `src/scenario.ts:56` |
| Lemma 4.4 | `Adv^rob ≤ Adv^prf + q·ℓ/ρ` | `q·ℓ/ρ` term only — `src/anamorphic.ts:359`, `src/anamorphic.ts:373` |
| Section 5.1 note | `ρ = |R| = q` for ElGamal | denominator is the group order — `src/anamorphic.ts:359` |

PPY22 supplies the model rather than the construction: the normal/anamorphic key pair,
the double key, and the dictator who may force surrender of the normal secret key
(PPY22 §1, "A Normal public key … An Anamorphic public key"). PPY22 also raises and
discards the append-a-random-string construction ("A simple solution that does not
work"), which is the reason the comparison table keeps an added AEAD slot outside the
definition — `src/comparison.ts`, and the note under the comparison table in `src/main.ts`.

## Declared adaptations

These are narrowings of the cited construction, not part of it. Each is named on the
page itself under "Where this page departs from the paper".

| # | Adaptation | Paper | This lab | Where |
| --- | --- | --- | --- | --- |
| A1 | ristretto255 transcription | abstract cyclic `G` of prime order `q`, multiplicative | one concrete prime-order group, RFC 9496 encoding, additive | `src/anamorphic.ts` header |
| A2 | bounded message spaces | `M̂ ⊆ Z_q` arbitrary with `ℓ = |M̂|`; `m ∈ G` arbitrary | `M̂ = {1,…,8}` so `ℓ = 8`; four declared overt group elements | `src/messages.ts:10`, `src/messages.ts:17` |
| A3 | external counter synchronization | `aEnc`/`aDec` carry `ctr` as state and return `ctr+1` | counter supplied per call; uniqueness is the caller's duty, reuse demonstrated | `src/anamorphic.ts:260`, `src/scenario.ts:56` |
| A4 | browser implementation | none | TypeScript on `@noble/curves`; no constant-time, interoperability or custody claim | whole repo |
| A5 | aGen narrowed to the public key | `aGen(sk, pk)`, but `dk := (K, T, pk)` | `createDoubleKey(publicKey, key)` | `src/anamorphic.ts:196` |

A2 is the one with a numeric consequence: `ℓ = 8` is exactly the `ℓ` in Lemma 4.4's
`q·ℓ/ρ` term, so shrinking the covert space is also what makes the printed robustness
bound as small as it is.

## Assumptions, stated separately because they do different jobs

- **PRF security of `F`.** Lemma 4.3 is an equality: `Adv^sec = Adv^prf`. Anamorphic-vs-normal
  indistinguishability reduces to the PRF **alone**, with no DDH, provided counters never
  repeat. This is what keeps the covert symbol from a coercer who holds `sk`.
- **DDH in the group.** This is what makes ordinary ElGamal IND-CPA, protecting the *overt*
  message from an outsider. It protects nothing from the coercer in this model, because the
  coercer is given `sk`.
- Both are computational. Neither is established by running this page.

## Claims to tests

| Claim | Owned by |
| --- | --- |
| group order, PRF domain, and the ristretto255 identity law | `src/anamorphic.test.ts` — "pins the group order and the construction domain" |
| HMAC-SHA-512 framing, exact known answer | `src/anamorphic.test.ts` — "pins HMAC-SHA-512 rejection mapping…" |
| exact rejection sampling, no modulo bias, bounded on a stuck RNG | `src/anamorphic.test.ts` — "samples exactly in the scalar field…", "gives up on a stuck RNG…" |
| ordinary ElGamal round-trip for every overt message, including `r = 0` | `src/anamorphic.test.ts` — "round-trips every overt message…", "supports zero as the paper-defined encryption randomness…" |
| `dk` contains no ordinary secret key | `src/anamorphic.test.ts` — "generates the public key as sk·G and keeps sk out of the double key" |
| every overt×covert pair recovers in both views, and `r = m̂ + t` | `src/anamorphic.test.ts` — "recovers every overt/covert combination…" |
| two-point, 64-byte wire object with no mode or counter field | `src/anamorphic.test.ts` — "puts no mode or counter field…", "the wire-shape check is falsifiable…" |
| `⊥` on a normal ciphertext, a wrong counter, and an independent double key | `src/anamorphic.test.ts` — "returns bottom for an ordinary ciphertext…", "returns bottom under a wrong counter…" |
| counter reuse repeats `C₂`; a fresh counter does not | `src/anamorphic.test.ts` — "exposes counter reuse as repeated C2…" |
| ElGamal malleability is real and does not disturb the covert view | `src/anamorphic.test.ts` — "makes plain ElGamal malleability visible…" |
| the `q·ℓ/ρ` term for `ℓ = 8` | `src/anamorphic.test.ts` — "states the paper-style robustness term…" |
| bounded message space is enforced, not decorative | `src/anamorphic.test.ts` — "rejects malformed double-key inputs…" |
| the independent-key control used a genuinely different key, and cannot be vacuous | `src/scenario.test.ts` — "proves the independent-double-key control…", "refuses to render a vacuous…" |
| the three receiver views render, `sk` is disclosed in full | `e2e/claims.spec.ts` — "one ciphertext supports the separately derived…" |
| every negative control renders `⊥` from the run | `e2e/claims.spec.ts` — "negative controls and synchronization failure…" |
| each run is fresh; changed input retires the verdict; bad counter fails closed | `e2e/claims.spec.ts` — "fresh execution…", "changing an input retires…", "an invalid counter fails closed…" |
| all five adaptations are named on the page | `e2e/claims.spec.ts` — "every declared adaptation is named on the page…" |
| PRF and DDH are separated; robustness stays a bound | `e2e/claims.spec.ts` — "the limits separate the PRF from DDH…" |
| the wire-shape verdict is qualified as syntactic | `e2e/claims.spec.ts` — "the wire-shape verdict is qualified…" |
| the three comparison boundaries, and the PPY22 grounding | `e2e/claims.spec.ts` — "the comparison table preserves all three claim boundaries" |
| WCAG A/AA at 1280, 390 and 320 px, no sideways scroll, no console errors | `e2e/a11y.spec.ts` |
| keyboard operability end to end | `e2e/a11y.spec.ts` — "the complete experiment is operable from the keyboard" |

## Mutation gate

`npm run test:mutations` asserts a clean baseline, then applies 15 named corruptions one
at a time. Each must be caught by the single named test that owns it, must still build,
and must change the production bundle — a mutation that never reaches `dist/` would prove
nothing. Sources and the bundle are restored and re-hashed byte for byte afterwards.

The list is in `scripts/mutations.mjs`. Five of the fifteen exist because of this audit:
unenforced message space, a covert table built over the wrong space, a wire-shape check
degraded into a claim that cannot fail, a dropped RNG byte-count check, and an
independent-key control allowed to be vacuous.

## What no test here establishes

Distributional indistinguishability (Definition 3.3), the PRF advantage term in Lemma 4.4,
constant-time behavior, side-channel resistance, interoperability with any deployed system,
and operational coercion resistance. These are named in the page's limits section and are
not inferable from any green run in this repository.
