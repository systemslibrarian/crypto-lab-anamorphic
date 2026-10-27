import './style.css';
import { CIPHERTEXT_BYTES, GROUP_ORDER } from './anamorphic.ts';
import { COMPARISON_ROWS } from './comparison.ts';
import { COVERT_MESSAGES, OVERT_MESSAGES } from './messages.ts';
import { runScenario, type ScenarioResult } from './scenario.ts';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('Missing #app');

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function options(
  choices: readonly { id: string; label: string }[],
  selected: string
): string {
  return choices.map((choice) => (
    `<option value="${escapeHtml(choice.id)}"${choice.id === selected ? ' selected' : ''}>${escapeHtml(choice.label)}</option>`
  )).join('');
}

function comparisonRows(): string {
  return COMPARISON_ROWS.map((row) => {
    const label = row.href
      ? `<a href="${row.href}" target="_blank" rel="noopener">${escapeHtml(row.system)}</a>`
      : escapeHtml(row.system);
    return `<tr>
      <th scope="row">${label}</th>
      <td>${escapeHtml(row.carrier)}</td>
      <td>${escapeHtml(row.disclosedView)}</td>
      <td>${escapeHtml(row.hiddenView)}</td>
      <td>${escapeHtml(row.boundary)}</td>
    </tr>`;
  }).join('');
}

app.innerHTML = `
  <header class="site-header">
    <a class="brand" href="https://crypto-lab.systemslibrarian.dev/">CRYPTO LAB</a>
    <span class="header-tag">A-D-15 · research extension</span>
  </header>

  <main id="main">
    <section class="hero" aria-labelledby="page-title">
      <p class="eyebrow">Receiver-anamorphic encryption · ordinary key disclosure</p>
      <h1 id="page-title">One ciphertext. Two keys. Two different messages.</h1>
      <p class="lede">Execute Banfi et al.’s synchronized robust ElGamal extension over the real
        <code>ristretto255</code> prime-order group. The ordinary key is surrendered and opens the
        prescribed overt message. A separate double key recovers one bounded covert symbol from
        the very same two-point ciphertext.</p>
      <div class="hero-badges" aria-label="Implementation scope">
        <span>real ristretto255 arithmetic</span>
        <span>HMAC-SHA-512 PRF</span>
        <span>bounded message dictionaries</span>
        <span>not a deployment system</span>
      </div>
    </section>

    <section class="lesson" aria-labelledby="experiment-title">
      <div class="section-heading">
        <p class="step">01 · execute</p>
        <h2 id="experiment-title">Run the coercion experiment</h2>
        <p>The ciphertext has no mode tag. The two receiver views differ only because one party
          holds the ordinary ElGamal secret and the other holds the PRF double key.</p>
      </div>

      <div class="control-grid">
        <label>Prescribed overt group message
          <select id="overt-select">${options(OVERT_MESSAGES, 'nominal')}</select>
        </label>
        <label>Covert symbol known to double-key parties
          <select id="covert-select">${options(COVERT_MESSAGES, 'north')}</select>
        </label>
        <label>Synchronized counter
          <input id="counter-input" type="number" min="0" max="1000000" step="1" value="7" inputmode="numeric" />
        </label>
        <button id="run-button" type="button">Generate keys, encrypt, and disclose</button>
      </div>

      <div id="result" class="result-shell" role="status" aria-live="polite">
        <p class="placeholder">Choose the two messages, then run one fresh experiment.</p>
      </div>
    </section>

    <section class="lesson" aria-labelledby="mechanics-title">
      <div class="section-heading">
        <p class="step">02 · inspect</p>
        <h2 id="mechanics-title">The exact Construction 6 mechanics</h2>
      </div>
      <div class="equation-grid">
        <article>
          <h3>Ordinary ElGamal</h3>
          <p><code>PK = sk·G</code></p>
          <p><code>C₁ = M + r·PK</code></p>
          <p><code>C₂ = r·G</code></p>
          <p><code>M = C₁ − sk·C₂</code></p>
        </article>
        <article>
          <h3>Anamorphic randomness</h3>
          <p><code>t = F(K, counter)</code></p>
          <p><code>r = m̂ + t mod ℓ</code></p>
          <p><code>S = C₂ − t·G = m̂·G</code></p>
          <p>Look up <code>S</code> in the bounded covert table.</p>
        </article>
      </div>
      <p class="scope-note">This is the paper’s Construction 6 / Figure 11 written additively.
        Ristretto’s group order is <code>${GROUP_ORDER}</code>. Lemma 5.1 is what licenses
        <code>+</code> as the paper’s own <code>⊕</code>: it proves ElGamal is selective-randomness
        recoverable with addition modulo <code>ℓ</code> as the randomness-space group operation.</p>
    </section>

    <section class="lesson" aria-labelledby="adapt-title">
      <div class="section-heading">
        <p class="step">03 · declare the adaptations</p>
        <h2 id="adapt-title">Where this page departs from the paper, and how far</h2>
        <p>Everything below is a deliberate narrowing of the cited construction. None of it is
          part of Banfi et al.’s statement, and none of it is hidden in prose elsewhere.</p>
      </div>
      <dl class="adaptations" data-testid="adaptations">
        <div><dt data-adaptation="group">Ristretto255 transcription</dt>
          <dd>The paper fixes an abstract cyclic group <code>G</code> of prime order <code>q</code> and
            writes it multiplicatively. This page fixes one concrete group with one canonical
            encoding (RFC 9496) and writes it additively. The equations are the same equations.</dd></div>
        <div><dt data-adaptation="bounded-table">Bounded eight-message table</dt>
          <dd>The paper allows any <code>M̂ ⊆ Z_q</code> with <code>ℓ = |M̂|</code>. This page pins
            <code>M̂ = {1,…,8}</code>, so <code>ℓ = 8</code>, and pins four declared overt group
            elements where the paper allows any <code>m ∈ G</code>. Both bounds are visible in the
            selectors above, and <code>ℓ = 8</code> is the number the robustness term uses.</dd></div>
        <div><dt data-adaptation="counter">External counter synchronization</dt>
          <dd>The paper’s <code>aEnc</code> and <code>aDec</code> carry the counter as state and return
            <code>ctr + 1</code>. Here the counter is an input you choose, so uniqueness is your
            responsibility — which is why reuse is demonstrated below as a failure rather than
            prevented. The PRF domain is <code>F: K × [2³²] → Z_ℓ</code>.</dd></div>
        <div><dt data-adaptation="browser">Browser implementation</dt>
          <dd>TypeScript over pinned <code>@noble/curves</code>, running in your tab. Not constant-time,
            not audited, not interoperable with any deployed anamorphic system, and not a library.</dd></div>
        <div><dt data-adaptation="agen">Double-key generation narrowed to the public key</dt>
          <dd>The paper writes <code>aGen(sk, pk)</code> but places only <code>(K, T, pk)</code> in the
            double key. This page therefore derives the double key from the public key alone, so
            the double key provably cannot contain the ordinary secret.</dd></div>
      </dl>
    </section>

    <section class="lesson" aria-labelledby="compare-title">
      <div class="section-heading">
        <p class="step">04 · distinguish</p>
        <h2 id="compare-title">Three superficially similar channels are not the same claim</h2>
      </div>
      <div class="table-wrap" role="region" aria-label="Comparison with subliminal and decoy-container lessons" tabindex="0">
        <table>
          <thead><tr>
            <th>System</th><th>Carrier</th><th>Disclosed view</th><th>Additional view</th><th>Honest boundary</th>
          </tr></thead>
          <tbody>${comparisonRows()}</tbody>
        </table>
      </div>
      <p class="scope-note" data-testid="ppy-note">Persiano, Phan and Yung reject the second and
        third shapes in the paper that introduced this model. Appending a separately encrypted
        string to an ordinary ciphertext is the construction they raise and then discard, because
        a user with nothing to hide has no reason to attach one, so attaching one is itself the
        signal. The point of the construction above is that the ciphertext is the ordinary
        ciphertext — no field is added, and the covert symbol lives in randomness the scheme was
        always going to sample.</p>
    </section>

    <section class="lesson limits" aria-labelledby="limits-title">
      <div class="section-heading">
        <p class="step">05 · retain the boundary</p>
        <h2 id="limits-title">What this run does not prove</h2>
      </div>
      <ul>
        <li><strong>Computational, not empirical.</strong> No number of browser runs can establish that
          anamorphic ciphertexts are distributed like ordinary ones. That is Definition 3.3, and
          Lemma 4.3 settles it by reduction: <code>Adv<sup>sec</sup> = Adv<sup>prf</sup></code>.
          Every verdict on this page is one sample from one run.</li>
        <li><strong>The two assumptions do different jobs, and only one of them hides the covert
          message.</strong> Lemma 4.3 needs the <em>PRF</em> alone — no DDH — plus counters that never
          repeat; that is what keeps the covert symbol from a coercer. <em>DDH</em> is what makes
          ordinary ElGamal IND-CPA, and it protects the overt message from an outsider. It
          protects nothing here from the coercer, who by assumption holds <code>sk</code>.</li>
        <li><strong>Double-key compromise is total and retroactive.</strong> <code>K</code> and the table
          are static, so anyone who learns the double key recovers the covert symbol of every
          ciphertext at every counter, past and future. Only the ordinary ElGamal key is
          surrendered in the modeled coercion event; the double key must already be shared out of
          band and must stay secret.</li>
        <li><strong>Counter reuse is a demonstrated failure, not a supported mode.</strong> The same
          double key, counter and covert symbol repeat the derived randomness and therefore
          <code>C₂</code>, which is linkable across different overt messages. The paper assumes
          counters do not repeat; this page gives you the counter and shows what happens when
          you break that assumption.</li>
        <li><strong>No integrity and no CCA security.</strong> Plain ElGamal is malleable; this page
          implements the IND-CPA scheme the paper instantiates and adds no authentication,
          metadata protection, constant-time behavior, secure memory, or production key custody.</li>
        <li><strong>No interoperability claim.</strong> This is a teaching transcription, not an
          implementation of any deployed anamorphic protocol or wire format, and nothing here is
          meant to speak to another implementation.</li>
        <li><strong>Robustness is a bound, never zero.</strong> Lemma 4.4 gives
          <code>Adv<sup>rob</sup> ≤ Adv<sup>prf</sup> + q·ℓ/ρ</code>. With <code>ℓ = 8</code> and
          <code>ρ</code> the group order, one query contributes the term printed above; the PRF term
          is not derivable on this page and is reported in words rather than silently dropped.</li>
      </ul>
      <p class="citations"><strong>Primary construction:</strong> Banfi, Gegier, Hirt, Maurer &amp; Rito,
        <a href="https://crypto.ethz.ch/publications/files/BGHMR24.pdf">Anamorphic Encryption, Revisited</a>,
        EUROCRYPT 2024, Construction 6 and Lemmas 4.3–4.4.
        <strong>Foundational model:</strong> Persiano, Phan &amp; Yung,
        <a href="https://eprint.iacr.org/2022/639">Anamorphic Encryption: Private Communication against a Dictator</a>, EUROCRYPT 2022.
        <strong>Group encoding:</strong> <a href="https://www.rfc-editor.org/rfc/rfc9496">RFC 9496</a>.</p>
    </section>
  </main>

  <footer>
    <span>All keys and experiment values are synthetic and processed locally in this page.</span>
    <span>Source publication pending review</span>
  </footer>
`;

function resultMarkup(result: ScenarioResult): string {
  const overt = escapeHtml(result.selected.overt);
  const covert = escapeHtml(result.selected.covert);
  const ordinaryRecovered = escapeHtml(result.ordinaryRecovered ?? 'UNRECOGNIZED');
  const covertRecovered = escapeHtml(result.covertRecovered ?? '⊥');
  const ordinaryPass = result.ordinaryRecovered === result.selected.overt;
  const covertPass = result.covertRecovered === result.selected.covert;
  const normalPass = result.normalControlRecovered === result.selected.overt;
  const normalCovertPass = result.normalControlCovert === null;
  const wrongCounterPass = result.wrongCounterRecovered === null;
  const wrongKeyPass = result.wrongDoubleKeyRecovered === null;
  return `
    <p class="run-title">Fresh run · ciphertext <code>${result.ciphertext}</code></p>
    <div class="view-grid">
      <article class="view-card sender" data-testid="sender-view">
        <p class="card-label">Sender / ciphertext</p>
        <h3>One ${result.ciphertextBytes}-byte object</h3>
        <dl>
          <div><dt>Overt input</dt><dd>${overt}</dd></div>
          <div><dt>Covert input</dt><dd>${covert}</dd></div>
          <div><dt>Fields on wire</dt><dd><code>C₁, C₂</code> only</dd></div>
          <div><dt>Two canonical points, nothing else <span class="qualifier">(wire shape only)</span></dt><dd data-claim="same-shape" class="${result.sameShapeAsNormal ? 'pass' : 'fail'}">${result.sameShapeAsNormal ? 'YES' : 'NO'}</dd></div>
        </dl>
      </article>

      <article class="view-card coercer" data-testid="coercer-view">
        <p class="card-label">Ordinary receiver / coercer</p>
        <h3>Ordinary key disclosed</h3>
        <dl>
          <div><dt>Public-key fingerprint</dt><dd><code>${result.publicKey}</code></dd></div>
          <div><dt>Disclosed <code>sk</code></dt><dd class="break"><code>${result.ordinarySecretKey}</code></dd></div>
          <div><dt><code>C₁ − sk·C₂</code></dt><dd data-claim="ordinary-recovery" class="${ordinaryPass ? 'pass' : 'fail'}">${ordinaryRecovered}</dd></div>
          <div><dt>Double key disclosed?</dt><dd>NO</dd></div>
        </dl>
        <p data-verdict="ordinary" class="verdict ${ordinaryPass ? 'pass' : 'fail'}">${ordinaryPass ? 'PASS — prescribed overt message opens with the surrendered key.' : 'FAIL — ordinary-key recovery did not match the prescribed overt message.'}</p>
      </article>

      <article class="view-card double" data-testid="double-view">
        <p class="card-label">Double-key receiver</p>
        <h3>Separate secret, same ciphertext</h3>
        <dl>
          <div><dt>Double-key fingerprint</dt><dd><code>${result.doubleKey}</code></dd></div>
          <div><dt>Counter</dt><dd><code>${result.selected.counter}</code></dd></div>
          <div><dt><code>C₂ − F(K,ctr)·G</code></dt><dd data-claim="covert-recovery" class="${covertPass ? 'pass' : 'fail'}">${covertRecovered}</dd></div>
          <div><dt>Ordinary <code>sk</code> needed?</dt><dd>NO</dd></div>
        </dl>
        <p data-verdict="covert" class="verdict ${covertPass ? 'pass' : 'fail'}">${covertPass ? 'PASS — the bounded covert symbol is recovered only in this view.' : 'FAIL — double-key recovery did not match the selected covert symbol.'}</p>
      </article>
    </div>

    <p class="shape-caveat">The sender card’s verdict is a claim about the wire object — two
      canonically re-decodable Ristretto points and no third field. It is not evidence that the
      two ciphertext <em>distributions</em> are alike; that is Lemma 4.3 and it is computational.</p>

    <div class="control-results" aria-label="Negative controls">
      <h3>Negative controls derived from this run</h3>
      <ul>
        <li><strong>Ordinary ciphertext → ordinary key:</strong> <span data-claim="normal-overt" class="${normalPass ? 'pass' : 'fail'}">${escapeHtml(result.normalControlRecovered ?? 'UNRECOGNIZED')}</span></li>
        <li><strong>Ordinary ciphertext → double key:</strong> <span data-claim="normal-covert" class="${normalCovertPass ? 'pass' : 'fail'}">${escapeHtml(result.normalControlCovert ?? '⊥')}</span> (expected <code>⊥</code>)</li>
        <li><strong>Wrong synchronized counter:</strong> <span data-claim="wrong-counter" class="${wrongCounterPass ? 'pass' : 'fail'}">${escapeHtml(result.wrongCounterRecovered ?? '⊥')}</span> (expected <code>⊥</code>)</li>
        <li><strong>Independent double key</strong> <code>${result.independentDoubleKey}</code>, which is not this run’s <code>${result.doubleKey}</code>: <span data-claim="wrong-key" class="${wrongKeyPass ? 'pass' : 'fail'}">${escapeHtml(result.wrongDoubleKeyRecovered ?? '⊥')}</span> (expected <code>⊥</code>)</li>
        <li><strong>One-query false-recognition term (Lemma 4.4, <code>q·ℓ/ρ</code>):</strong> <code>${result.robustnessBound}</code>, plus the PRF term, which this page cannot derive</li>
      </ul>
    </div>

    <div class="warning-grid">
      <article>
        <h3>Counter discipline</h3>
        <p>Same double key + same counter + same covert symbol repeats <code>C₂</code> across a different overt message:
          <strong class="${result.repeatedCounterReusesC2 ? 'fail' : 'pass'}">${result.repeatedCounterReusesC2 ? 'YES — LINKABLE' : 'NO'}</strong>.</p>
        <p>Advancing the counter changes <code>C₂</code> in this run:
          <strong class="${result.freshCounterChangesC2 ? 'pass' : 'fail'}">${result.freshCounterChangesC2 ? 'YES' : 'NO'}</strong>.</p>
      </article>
      <details>
        <summary>Omniscient classroom audit (not the coercer’s view)</summary>
        <p><code>r = m̂ + F(K,counter) mod ℓ</code> recomputed: <strong class="${result.audit.relationHolds ? 'pass' : 'fail'}">${result.audit.relationHolds ? 'YES' : 'NO'}</strong></p>
        <p>PRF mask: <code class="break">${result.audit.maskHex}</code></p>
        <p>Covert scalar: <code class="break">${result.audit.covertScalarHex}</code></p>
        <p>Derived randomness: <code class="break">${result.audit.randomnessHex}</code></p>
        <p>This teaching view intentionally knows both secrets. It is not evidence available to either modeled adversary.</p>
      </details>
    </div>
  `;
}

const result = document.querySelector<HTMLDivElement>('#result')!;
const runButton = document.querySelector<HTMLButtonElement>('#run-button')!;
const overtSelect = document.querySelector<HTMLSelectElement>('#overt-select')!;
const covertSelect = document.querySelector<HTMLSelectElement>('#covert-select')!;
const counterInput = document.querySelector<HTMLInputElement>('#counter-input')!;

function retireResult(): void {
  result.innerHTML = '<p class="placeholder">Inputs changed. Run a fresh experiment; the previous verdict has been retired.</p>';
  result.dataset.state = 'stale';
}

for (const input of [overtSelect, covertSelect, counterInput]) {
  input.addEventListener('input', retireResult);
}

runButton.addEventListener('click', () => {
  const counter = Number(counterInput.value);
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > 1_000_000) {
    result.innerHTML = '<p class="error">Use a whole-number counter between 0 and 1,000,000.</p>';
    result.dataset.state = 'error';
    return;
  }
  runButton.disabled = true;
  try {
    const run = runScenario(overtSelect.value, covertSelect.value, counter);
    result.innerHTML = resultMarkup(run);
    result.dataset.state = 'complete';
  } catch (error) {
    result.innerHTML = `<p class="error">Experiment failed closed: ${escapeHtml(error instanceof Error ? error.message : String(error))}</p>`;
    result.dataset.state = 'error';
  } finally {
    runButton.disabled = false;
  }
});

// Assert the learner-facing size claim against the core constant at startup.
document.documentElement.dataset.ciphertextBytes = String(CIPHERTEXT_BYTES);
