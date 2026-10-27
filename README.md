# Anamorphic Channel

## What It Is

Anamorphic Channel is a bounded, executable lesson for ordinary-key disclosure in receiver-anamorphic public-key encryption. It implements Banfi, Gegier, Hirt, Maurer and Rito's synchronized robust anamorphic ElGamal extension (`SyncAnamElGamal`, Construction 6 / Figure 11) over the real `ristretto255` prime-order group. One ordinary two-point ElGamal ciphertext opens to a prescribed overt group message under the surrendered ordinary secret key, while a separate PRF double key and synchronized counter recover one bounded covert symbol from that same ciphertext.

This is a mechanism lesson, not a deployment system. It does not establish coercion resistance by running a browser sample, and it does not add integrity, CCA security, metadata protection, key exchange, counter recovery or production key custody.

## Exhibits

1. **Fresh coercion experiment.** Choose one prescribed overt group message, one of eight covert symbols and a synchronized counter; the page generates fresh synthetic keys and one ciphertext.
2. **Three explicit views.** Compare what the sender knows, what a coercer learns after receiving the complete ordinary secret key, and what the double-key receiver recovers without that ordinary key.
3. **Construction 6 mechanics.** Inspect the paper's equations in additive notation and see the ordinary and covert openings computed from the same `C2` point.
4. **Falsifiable controls.** Try an ordinary ElGamal ciphertext, a wrong counter and an independently generated double key; each must return bottom in the bounded covert decoder.
5. **Counter-reuse failure.** Reuse the same double key, counter and covert symbol across another overt message and see `C2` repeat; advance the counter and see it change.
6. **Claim boundaries.** Compare receiver-anamorphic encryption with a public ECDSA subliminal signal and a two-slot decoy container without merging their security claims.

### Construction shown

The implementation writes the paper's multiplicative ElGamal construction additively:

```text
PK = sk G
C1 = M + r PK
C2 = r G
M  = C1 - sk C2
```

For anamorphic encryption, the sender and double-key receiver share a 32-byte PRF key `K` and a unique synchronized counter. The sender computes:

```text
t = F(K, counter)
r = covertScalar + t mod groupOrder
```

The double-key receiver computes `C2 - t G = covertScalar G` and looks the result up in an eight-entry precomputed table. The double key contains the PRF key, public key and table, but not the ordinary ElGamal secret key. The on-wire object remains exactly `{ C1, C2 }`: two canonical Ristretto points, 64 bytes total, with no mode, role, counter or extra payload field.

The PRF is domain-separated HMAC-SHA-512 mapped into the scalar field by deterministic rejection sampling. Random scalar generation also uses exact rejection sampling rather than modulo reduction. Overt labels map to four declared group elements and covert labels map to eight declared scalars; the page does not pretend arbitrary strings are native ElGamal messages.

### Declared adaptations

Five narrowings of the cited construction are named on the page itself. [`docs/source-map.md`](docs/source-map.md) ties each one to the implementation line that owns it.

| # | Adaptation | The paper | This lab |
| --- | --- | --- | --- |
| A1 | Ristretto255 transcription | an abstract cyclic group `G` of prime order `q`, written multiplicatively | one concrete prime-order group with one canonical encoding (RFC 9496), written additively |
| A2 | Bounded eight-message table | any `M̂ ⊆ Z_q` with `ℓ = |M̂|`; any `m ∈ G` | `M̂ = {1,…,8}` so `ℓ = 8`; four declared overt group elements |
| A3 | External counter synchronization | `aEnc` and `aDec` carry the counter and return `ctr+1` | the counter is an input, so uniqueness is the caller's duty and reuse is demonstrated rather than prevented; `F: K × [2³²] → Z_q` |
| A4 | Browser implementation | none | TypeScript over pinned `@noble/curves`, in a tab |
| A5 | `aGen` narrowed to the public key | `aGen(sk, pk)`, but `dk := (K, T, pk)` | `createDoubleKey(publicKey, …)`, so the double key provably cannot hold `sk` |

A2 has a numeric consequence: `ℓ = 8` is the same `ℓ` that appears in Lemma 4.4's `q·ℓ/ρ` term, so the bounded table is also what makes the printed robustness term as small as it is.

## When to Use It

Use this lab to study the receiver-anamorphic threat model, the exact synchronized ElGamal construction, ordinary-key disclosure, bounded covert recovery, and the robustness and counter-reuse boundaries that accompany it. It is also useful for distinguishing an anamorphic ciphertext from a public subliminal signal or a role-revealing decoy container.

Do **not** use this code as a covert-communications tool or production cryptosystem. It has no authenticated encryption, counter service, key exchange, secure storage, traffic-analysis defense or operational coercion protocol.

## Live Demo

Open <https://systemslibrarian.github.io/crypto-lab-anamorphic/>. Choose the overt message, covert symbol and synchronized counter, then inspect the sender, disclosed ordinary-key and double-key views alongside the negative controls.

## What Can Go Wrong

- A normally randomized ElGamal ciphertext opens under the ordinary key but returns bottom under the double key in the deterministic control run.
- The anamorphic ciphertext returns bottom under the wrong counter and an independently generated double key.
- Reusing the same double key, counter and covert symbol repeats `C2`; the page labels that event linkable. Advancing the counter changes `C2`.
- The classroom audit recomputes `r = covertScalar + F(K,counter) mod groupOrder` but explicitly sits outside either modeled receiver view.
- Tests expose ordinary ElGamal malleability: changing `C1` can change the overt plaintext without changing the `C2`-derived covert view.

Lemma 4.4 bounds robustness by `Adv^prf + q·ℓ/ρ`. For `ℓ = 8`, `ρ` the ristretto255 group order and one query, the second term is `8/ρ`, which is strictly less than `2^-249`. The page prints that term and says in words that the PRF term is not derivable there. It never prints zero: this is a bound, not a claim that false recognition is impossible.

### Retained limitations

- **Computational, not empirical.** Browser samples do not establish that anamorphic ciphertexts are distributed like ordinary ones. Definition 3.3 and Lemma 4.3 make a reduction claim; every on-page verdict is one sample from one run.
- **The PRF and DDH do different jobs.** Lemma 4.3 is the equality `Adv^sec = Adv^prf`: anamorphic-vs-normal indistinguishability reduces to the PRF alone, with no DDH, provided counters never repeat. DDH makes ordinary ElGamal IND-CPA and protects the overt message from an outsider; it protects nothing from a coercer who holds `sk`.
- **Double-key compromise is total and retroactive.** Anyone who learns the static PRF key and lookup table can recover the covert symbol of every captured ciphertext at every known counter, past and future.
- **Counter reuse is a demonstrated failure, not a supported mode.** The paper assumes counters do not repeat. The page hands the counter to the learner specifically to expose the consequence of reuse.
- **No integrity, CCA security, interoperability or constant-time claim.** Plain ElGamal is malleable and unauthenticated; the lab adds no authentication, metadata protection, secure memory, traffic-analysis defense, endpoint-compromise defense or deployed wire format.

## Real-World Usage

Anamorphic encryption is research about communication under compelled ordinary-key disclosure. The construction does not make coercion safe in practice: endpoint compromise, traffic analysis, counter desynchronization, disclosure of the double key, authentication and human operational behavior remain outside the algebra. The page therefore presents one bounded mechanism and its assumptions, not deployment advice.

### Primary sources and versions

- Banfi, Gegier, Hirt, Maurer and Rito, “Anamorphic Encryption, Revisited,” EUROCRYPT 2024, especially Construction 6, Figure 11 and Lemmas 4.3–4.4: <https://crypto.ethz.ch/publications/files/BGHMR24.pdf>
- Persiano, Phan and Yung, “Anamorphic Encryption: Private Communication against a Dictator,” EUROCRYPT 2022: <https://eprint.iacr.org/2022/639>
- RFC 9496, “The ristretto255 and decaf448 Groups”: <https://www.rfc-editor.org/rfc/rfc9496>

The source-reading and design decisions are retained in [`brief.md`](brief.md).

## How to Run Locally

Use Node.js 22, 24 or 26 and npm 10.9 or newer. The pinned version is in `.nvmrc`.

| Command | What it does |
| --- | --- |
| `npm ci` | install the exact pinned dependency tree |
| `npm audit --audit-level=high` | fail on a high or critical dependency advisory |
| `npm run dev` | run the Vite development server |
| `npm run typecheck` | run `tsc --noEmit` over source, browser tests and configuration |
| `npm test` | run unit tests |
| `npm run test:coverage` | run unit tests plus the coverage gate |
| `npm run build` | type-check and build the production bundle into `dist/` |
| `npm run preview` | serve the built bundle |
| `npm run test:claims` | build, then run the learner-visible browser claim gate on assigned port 4750 |
| `npm run test:a11y` | build, then run WCAG A/AA and reflow checks at 1280, 390 and 320 pixels |
| `npm run test:mutations` | run a clean baseline, 15 named corruptions and byte-for-byte restoration |
| `npm run check` | run every gate in CI order |

## Related Demos

- [Subliminal Channels](https://systemslibrarian.github.io/crypto-lab-subliminal-channels/) carries a public bit through ECDSA `r` parity. It is not encryption and makes no anamorphic-security claim.
- [Shadow Vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) has two independently encrypted AEAD slots in one container. A format-aware reader learns the configured role of a disclosed passphrase; the extra slot does not provide anamorphic role privacy.
- [ElGamal Plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/) demonstrates the ordinary public-key scheme extended here.
- The full catalog: <https://crypto-lab.systemslibrarian.dev/>

## Build & Verify

```sh
npm ci
npm audit --audit-level=high
npm run check
```

The verified baseline contains 32 unit tests, 11 learner-claim browser checks, four accessibility/reflow/keyboard checks, and 15 named source mutations. Coverage must reach at least 95% statements, 90% branches, 95% functions and 95% lines. The paper publishes no byte-level known-answer file for Construction 6; [`src/anamorphic.test.ts`](src/anamorphic.test.ts) instead pins a deterministic HMAC-SHA-512 rejection-mapping fixture and exercises all declared overt/covert combinations. Browser tests cover the disclosed-key and double-key views, exact construction notation, shared Crypto Lab frame, negative controls, result retirement and comparison boundaries. The mutation runner requires every named corruption to reach a changed production bundle, fail its owning test and restore the source bytes exactly.

Additional audit material:

- [`docs/source-map.md`](docs/source-map.md) maps paper equations, learner-visible claims, adaptations and non-claims to their implementation and tests.
- [`brief.md`](brief.md) records the A-D-15 scope decision and primary-source reading.

The app is entirely client-side and retains no learner data. It is MIT licensed. The lesson is educational software, not cryptographic advice or a production library.

## Performance

The covert lookup is deliberately bounded to eight precomputed entries. No runtime, memory, throughput or concrete-security measurement here estimates a production deployment; browser timings would primarily measure this teaching implementation and device, not the construction's security.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
