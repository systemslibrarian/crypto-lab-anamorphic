# Anamorphic Channel

Anamorphic Channel is a bounded, executable lesson for ordinary-key disclosure in receiver-anamorphic public-key encryption. It implements Banfi, Gegier, Hirt, Maurer and Rito's synchronized robust anamorphic ElGamal extension (`SyncAnamElGamal`, Construction 6 / Figure 11) over the real `ristretto255` prime-order group. Construction 6 is the pre-computation form of the generic Construction 2 instantiated on the ElGamal scheme of Construction 5, and it inherits Lemmas 4.3 and 4.4 from that generic construction. One ordinary two-point ElGamal ciphertext opens to a prescribed overt group message under the surrendered ordinary secret key, while a separate PRF double key and synchronized counter recover one bounded covert symbol from the same ciphertext.

This is a mechanism lesson, not a deployment system. It does not establish coercion resistance by running a browser sample, and it does not add integrity, CCA security, metadata protection, key exchange, counter recovery or production key custody.

## What the lesson executes

The implementation writes the paper's multiplicative ElGamal construction additively:

```text
PK = sk G
C1 = M + r PK
C2 = r G
M  = C1 - sk C2
```

For anamorphic encryption, the sender and double-key receiver share a 32-byte PRF key `K` and a unique synchronized counter. The sender computes

```text
t = F(K, counter)
r = covertScalar + t mod groupOrder
```

and runs ordinary ElGamal with that `r`. The double-key receiver computes `C2 - t G = covertScalar G` and looks the result up in an eight-entry precomputed table. The double key contains the PRF key, public key and table, but not the ordinary ElGamal secret key. The on-wire object remains exactly `{ C1, C2 }`: two canonical Ristretto points, 64 bytes total, with no mode, role, counter or extra payload field.

The PRF is domain-separated HMAC-SHA-512 mapped into the scalar field by deterministic rejection sampling. Random scalar generation also uses exact rejection sampling rather than modulo reduction. Overt labels map to four declared group elements and covert labels map to eight declared scalars; the page does not pretend arbitrary strings are native ElGamal messages.

## Declared adaptations

Five narrowings of the cited construction. All five are named on the page itself, not
only here, and `docs/source-map.md` ties each to the line that implements it.

| # | Adaptation | The paper | This lab |
| --- | --- | --- | --- |
| A1 | Ristretto255 transcription | an abstract cyclic group `G` of prime order `q`, written multiplicatively | one concrete prime-order group with one canonical encoding (RFC 9496), written additively |
| A2 | Bounded eight-message table | any `M̂ ⊆ Z_q` with `ℓ = |M̂|`; any `m ∈ G` | `M̂ = {1,…,8}` so `ℓ = 8`; four declared overt group elements |
| A3 | External counter synchronization | `aEnc` and `aDec` carry the counter and return `ctr+1` | the counter is an input, so uniqueness is the caller's duty and reuse is demonstrated rather than prevented; `F: K × [2³²] → Z_ℓ` |
| A4 | Browser implementation | none | TypeScript over pinned `@noble/curves`, in a tab |
| A5 | `aGen` narrowed to the public key | `aGen(sk, pk)`, but `dk := (K, T, pk)` | `createDoubleKey(publicKey, …)`, so the double key provably cannot hold `sk` |

A2 is the one with a numeric consequence: `ℓ = 8` is the same `ℓ` that appears in Lemma 4.4's
`q·ℓ/ρ` term, so the bounded table is also what makes the printed robustness bound as small
as it is.

## Coercion experiment

Each run generates fresh synthetic keys and renders three distinct views:

- The sender view shows the selected overt and covert inputs and the two-field ciphertext shape.
- The ordinary receiver/coercer view discloses the complete ordinary scalar secret key and recomputes the selected overt message.
- The double-key receiver view uses its separate secret and the synchronized counter to recover the bounded covert symbol without the ordinary secret key.

The result is retired as soon as an input changes. A fresh execution replaces the prior key material and ciphertext.

## Failure controls

- A normally randomized ElGamal ciphertext opens under the ordinary key but returns bottom under the double key in the deterministic control run.
- The anamorphic ciphertext returns bottom under the wrong counter and an independently generated double key.
- Reusing the same double key, counter and covert symbol across another overt message repeats `C2`; the page labels that event linkable. Advancing the counter changes `C2`.
- The classroom audit recomputes `r = covertScalar + F(K,counter) mod groupOrder` but explicitly sits outside either modeled receiver view.
- Tests expose ordinary ElGamal malleability: changing `C1` can change the overt plaintext without changing the `C2`-derived covert view.

Lemma 4.4 bounds robustness by `Adv^prf + q·ℓ/ρ`. For `ℓ = 8`, `ρ` the ristretto255 group order and one query, the second term is `8/ρ`, which is strictly less than `2^-249`. The page prints that term and says in words that the PRF term is not derivable there. It never prints zero: this is a bound, not a claim that false recognition is impossible.

## Comparison boundary

The final table keeps this construction separate from two existing labs:

- [Subliminal Channels](https://systemslibrarian.github.io/crypto-lab-subliminal-channels/) carries a public bit through ECDSA `r` parity. It is not encryption and makes no anamorphic-security claim.
- [Shadow Vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) has two independently encrypted AEAD slots in one container. A format-aware reader learns the configured role of a disclosed passphrase; the extra slot does not provide anamorphic role privacy.

## Primary sources

- Banfi, Gegier, Hirt, Maurer and Rito, “Anamorphic Encryption, Revisited,” EUROCRYPT 2024, especially Construction 6, Figure 11, and Lemmas 4.3–4.4: <https://crypto.ethz.ch/publications/files/BGHMR24.pdf>
- Persiano, Phan and Yung, “Anamorphic Encryption: Private Communication against a Dictator,” EUROCRYPT 2022: <https://eprint.iacr.org/2022/639>
- RFC 9496, “The ristretto255 and decaf448 Groups”: <https://www.rfc-editor.org/rfc/rfc9496>

The source-reading and design decisions are retained in [`brief.md`](brief.md).

## Retained limitations

**Computational, not empirical.** No number of browser runs establishes that anamorphic
ciphertexts are distributed like ordinary ones. That is Definition 3.3, and Lemma 4.3
settles it by reduction rather than by sampling. Every verdict the page renders is one
sample from one run.

**The two assumptions do different jobs, and only one of them hides the covert message.**
Lemma 4.3 is an equality, `Adv^sec = Adv^prf`: anamorphic-vs-normal indistinguishability
reduces to the **PRF alone**, with no DDH, provided counters never repeat. That is what
keeps the covert symbol from a coercer. **DDH** is what makes ordinary ElGamal IND-CPA and
protects the *overt* message from an outsider; it protects nothing here from the coercer,
who by assumption holds `sk`. Earlier drafts of this README blurred the two into "the PRF
hybrid and the ordinary ElGamal assumptions", which credits DDH with work it does not do
in this model.

**Double-key compromise is total and retroactive.** `K` and the lookup table are static, so
anyone who learns the double key recovers the covert symbol of every ciphertext at every
counter, past and future. Only the ordinary ElGamal key is surrendered in the modeled
coercion event; the double key must be shared out of band and must stay secret. The paper
permits several double keys per key pair; this lab issues one per run.

**Counter reuse is a demonstrated failure, not a supported mode.** The paper assumes counters
do not repeat. This page hands you the counter and shows what repeating one costs.

**No integrity, no CCA security, no interoperability.** Plain ElGamal is malleable and
unauthenticated; this page implements the IND-CPA scheme the paper instantiates and adds no
authentication, metadata protection or key custody. It is a teaching transcription, not an
implementation of any deployed anamorphic protocol or wire format, and nothing in it is
meant to speak to another implementation.

**No constant-time claim.** The browser code makes no constant-time, side-channel,
secure-memory, traffic-analysis, endpoint-compromise or deniable-key-exchange claim, and
has had no formal verification or concrete security estimate.

## Development commands

Use Node.js 22, 24 or 26 and npm 10.9 or newer. The pinned version is in `.nvmrc`.

| Command | What it does |
| --- | --- |
| `npm ci` | install the exact pinned dependency tree |
| `npm audit --audit-level=high` | fail on a high or critical dependency advisory |
| `npm run dev` | Vite dev server with hot reload |
| `npm run typecheck` | `tsc --noEmit` over `src`, `e2e` and the config files |
| `npm test` | unit tests |
| `npm run test:coverage` | unit tests plus the coverage gate |
| `npm run build` | typecheck, then the production bundle into `dist/` |
| `npm run preview` | serve the built bundle |
| `npm run test:claims` | learner-visible browser claim gate (port 4750, `--strictPort`) |
| `npm run test:a11y` | WCAG A/AA and reflow at 1280, 390 and 320 px |
| `npm run test:mutations` | clean baseline, 15 named corruptions, byte-for-byte restore |
| `npm run check` | every gate above in the order CI runs them |

## Local verification

```sh
npm ci
npm audit --audit-level=high
npm run test:coverage
npm run build
npm run test:e2e
npm run test:mutations
```

The coverage gate requires at least 95% statements, 90% branches, 95% functions and 95% lines. Browser claim tests exercise the disclosed-key and double-key views, negative controls, result retirement and comparison boundaries. Accessibility tests run WCAG A/AA checks in arrival and completed states at desktop, 390-pixel and 320-pixel widths. The mutation gate requires an unmodified baseline, proves fifteen named corruptions are caught, verifies each mutation reaches the production bundle and restores the source bytes exactly.

## Related labs

- [Subliminal Channels](https://systemslibrarian.github.io/crypto-lab-subliminal-channels/) — the public ECDSA `r`-parity bit, and why a documented selection signal is not encryption.
- [Shadow Vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — real and decoy AEAD slots in one container, and why an added slot is not anamorphic role privacy.
- [ElGamal Plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/) — the ordinary scheme this construction is an extension of.
- The full catalog: <https://crypto-lab.systemslibrarian.dev/>

## Documentation

- [`docs/source-map.md`](docs/source-map.md) — every paper equation traced to the line that executes it, every learner-visible claim traced to the test that owns it, the five declared adaptations, and the list of things no test here establishes.
- [`brief.md`](brief.md) — the A-D-15 scope decision and the source reading behind it.

## Repository scope

The app is entirely client-side and retains no learner data. It is MIT licensed. The lesson is educational software, not cryptographic advice or a production library.

