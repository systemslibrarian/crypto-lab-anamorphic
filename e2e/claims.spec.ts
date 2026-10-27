import { expect, test, type Page } from '@playwright/test';

async function runSelectedScenario(
  page: Page,
  overt = 'maintenance',
  covert = 'archive',
  counter = '19'
): Promise<void> {
  await page.locator('#overt-select').selectOption(overt);
  await page.locator('#covert-select').selectOption(covert);
  await page.locator('#counter-input').fill(counter);
  await page.locator('#run-button').click();
  await expect(page.locator('#result')).toHaveAttribute('data-state', 'complete');
}

test.beforeEach(async ({ page }) => {
  await page.goto('./');
  await expect(page.locator('#app')).not.toBeEmpty();
});

test('uses the exact Crypto Lab frame and states the randomness group exactly', async ({ page }) => {
  await expect(page.locator('.cl-topbar')).toHaveCount(1);
  await expect(page.locator('.cl-topbar')).toContainText('CRYPTO LAB');
  await expect(page.getByRole('link', { name: 'Crypto Lab menu' }))
    .toHaveAttribute('href', 'https://crypto-lab.systemslibrarian.dev/');
  await expect(page.getByRole('link', { name: 'View this project on GitHub' }))
    .toHaveAttribute('href', 'https://github.com/systemslibrarian/crypto-lab-anamorphic');

  const hero = page.locator('#app > main > header.cl-hero:first-child');
  await expect(hero).toHaveCount(1);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(hero.locator('.cl-hero-title')).toHaveText('Anamorphic Channel');
  await expect(hero.locator('.cl-hero-sub'))
    .toHaveText('Synchronized robust Anamorphic ElGamal · EUROCRYPT 2024');
  await expect(hero.locator('.cl-hero-desc')).toContainText('one real ristretto255 ciphertext');
  const titleSize = await hero.locator('.cl-hero-title').evaluate((element) => (
    Number.parseFloat(getComputedStyle(element).fontSize)
  ));
  expect(titleSize).toBeLessThanOrEqual(43.2);

  const why = page.locator('.cl-hero-why');
  await expect(why).toContainText('WHY IT MATTERS');
  await expect(why).toContainText('compelled or seized');
  await expect(why.locator('.cl-hero-why-text')).toHaveCount(1);
  await expect(page.locator('.scripture-footer')).toContainText('1 Corinthians 10:31');

  const mechanics = page.locator('section[aria-labelledby="mechanics-title"]');
  await expect(mechanics).toContainText('r = m̂ + t mod q');
  await expect(mechanics).toContainText('ℓ = 8');
  await expect(mechanics).not.toContainText('mod ℓ');

  const adaptations = page.getByTestId('adaptations');
  await expect(adaptations).toContainText('F: K × [2³²] → Z_q');
  await expect(adaptations).not.toContainText('Z_ℓ');

  await runSelectedScenario(page);
  await page.locator('details summary').click();
  await expect(page.locator('details')).toContainText('mod q');
  await expect(page.locator('details')).not.toContainText('mod ℓ');
});

test('one ciphertext supports the separately derived ordinary and double-key views', async ({ page }) => {
  await runSelectedScenario(page);

  const sender = page.getByTestId('sender-view');
  await expect(sender).toContainText('One 64-byte object');
  await expect(sender).toContainText('C₁, C₂ only');
  await expect(page.locator('[data-claim="same-shape"]')).toHaveText('YES');
  await expect(page.locator('[data-claim="same-shape"]')).toHaveClass(/pass/);

  const disclosedKey = page
    .getByTestId('coercer-view')
    .locator('dl div')
    .filter({ hasText: 'Disclosed sk' })
    .locator('dd code');
  await expect(disclosedKey).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.locator('[data-claim="ordinary-recovery"]'))
    .toHaveText('Routine maintenance approved');
  await expect(page.locator('[data-verdict="ordinary"]')).toHaveClass(/pass/);

  await expect(page.locator('[data-claim="covert-recovery"]'))
    .toHaveText('Copy reached the archive');
  await expect(page.locator('[data-verdict="covert"]')).toHaveClass(/pass/);
  await expect(page.getByTestId('double-view')).toContainText('Ordinary sk needed?');
  await expect(page.getByTestId('double-view')).toContainText('NO');
});

test('negative controls and synchronization failure are rendered from the run', async ({ page }) => {
  await runSelectedScenario(page);

  await expect(page.locator('[data-claim="normal-overt"]'))
    .toHaveText('Routine maintenance approved');
  for (const claim of ['normal-covert', 'wrong-counter', 'wrong-key']) {
    await expect(page.locator(`[data-claim="${claim}"]`)).toHaveText('⊥');
    await expect(page.locator(`[data-claim="${claim}"]`)).toHaveClass(/pass/);
  }
  await expect(page.locator('.control-results')).toContainText(/8\/\d+ < 2\^-249/);
  await expect(page.locator('.warning-grid')).toContainText('YES — LINKABLE');
  await expect(page.locator('.warning-grid')).toContainText('Advancing the counter changes C₂');

  await page.locator('details summary').click();
  await expect(page.locator('details')).toHaveAttribute('open', '');
  await expect(page.locator('details')).toContainText('recomputed: YES');
});

test('fresh execution replaces the prior keys and ciphertext', async ({ page }) => {
  await runSelectedScenario(page);
  const firstCiphertext = await page.locator('.run-title code').innerText();
  const firstKey = await page
    .getByTestId('coercer-view')
    .locator('dl div')
    .filter({ hasText: 'Disclosed sk' })
    .locator('dd code')
    .innerText();

  await page.locator('#run-button').click();
  const secondCiphertext = await page.locator('.run-title code').innerText();
  const secondKey = await page
    .getByTestId('coercer-view')
    .locator('dl div')
    .filter({ hasText: 'Disclosed sk' })
    .locator('dd code')
    .innerText();

  expect(secondCiphertext).not.toBe(firstCiphertext);
  expect(secondKey).not.toBe(firstKey);
});

test('changing an input retires all verdicts from the old experiment', async ({ page }) => {
  await runSelectedScenario(page);
  await expect(page.locator('[data-verdict]')).toHaveCount(2);

  await page.locator('#covert-select').selectOption('delay');
  await expect(page.locator('#result')).toHaveAttribute('data-state', 'stale');
  await expect(page.locator('#result')).toContainText('previous verdict has been retired');
  await expect(page.locator('[data-verdict]')).toHaveCount(0);
});

test('an invalid counter fails closed before a claim is shown', async ({ page }) => {
  await page.locator('#counter-input').fill('1000001');
  await page.locator('#run-button').click();
  await expect(page.locator('#result')).toHaveAttribute('data-state', 'error');
  await expect(page.locator('#result')).toContainText('whole-number counter');
  await expect(page.locator('[data-verdict]')).toHaveCount(0);
});

test('every declared adaptation is named on the page, not buried in prose', async ({ page }) => {
  const adaptations = page.getByTestId('adaptations');
  await expect(adaptations).toBeVisible();
  for (const name of ['group', 'bounded-table', 'counter', 'browser', 'agen']) {
    await expect(page.locator(`[data-adaptation="${name}"]`)).toBeVisible();
  }
  await expect(adaptations).toContainText('RFC 9496');
  await expect(adaptations).toContainText('ℓ = 8');
  await expect(adaptations).toContainText('not interoperable');
  await expect(adaptations).toContainText('cannot contain the ordinary secret');
});

test('the limits separate the PRF from DDH and keep robustness a bound', async ({ page }) => {
  const limits = page.locator('section[aria-labelledby="limits-title"]');
  await expect(limits).toContainText('needs the PRF alone');
  await expect(limits).toContainText('no DDH');
  await expect(limits).toContainText('makes ordinary ElGamal IND-CPA');
  await expect(limits).toContainText('total and retroactive');
  await expect(limits).toContainText('No interoperability claim');
  await expect(limits).toContainText('never zero');
  await expect(limits).not.toContainText('proves indistinguishability');
});

test('the independent-key control shows it used a different key', async ({ page }) => {
  await runSelectedScenario(page);
  const control = page.locator('[data-claim="wrong-key"]').locator('xpath=ancestor::li[1]');
  const fingerprints = await control.locator('code').allInnerTexts();
  expect(fingerprints.length).toBeGreaterThanOrEqual(2);
  expect(fingerprints[0]).toMatch(/^[0-9a-f]{24}$/);
  expect(fingerprints[0]).not.toBe(fingerprints[1]);
  await expect(page.locator('[data-claim="wrong-key"]')).toHaveText('⊥');
});

test('the wire-shape verdict is qualified as syntactic, not distributional', async ({ page }) => {
  await runSelectedScenario(page);
  await expect(page.getByTestId('sender-view')).toContainText('wire shape only');
  await expect(page.locator('.shape-caveat')).toContainText('not evidence');
  await expect(page.locator('.shape-caveat')).toContainText('computational');
});

test('the comparison table preserves all three claim boundaries', async ({ page }) => {
  const rows = page.locator('section[aria-labelledby="compare-title"] tbody tr');
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0)).toContainText('no mode or role field');
  await expect(rows.nth(0)).toContainText('surrendered ordinary secret key');
  await expect(rows.nth(1)).toContainText('Not encryption and not anamorphic security');
  await expect(rows.nth(2)).toContainText('No role privacy');
  await expect(rows.nth(2)).toContainText('not anamorphic encryption');
  await expect(page.getByTestId('ppy-note')).toContainText('raise and then discard');
});

