import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const VIEWPORTS = [
  { name: 'desktop', width: 1280, height: 900 },
  { name: 'phone', width: 390, height: 844 },
  { name: 'narrowest', width: 320, height: 760 }
] as const;

async function expectNoA11yViolations(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(
    results.violations,
    results.violations.map((violation) => (
      `${violation.id}: ${violation.help}\n${violation.nodes.map((node) => node.target.join(' ')).join('\n')}`
    )).join('\n\n')
  ).toEqual([]);
}

for (const viewport of VIEWPORTS) {
  test(`arrival and completed states pass WCAG checks without page overflow at ${viewport.name}`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text());
    });

    await page.setViewportSize(viewport);
    await page.goto('./');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expectNoA11yViolations(page);

    await page.locator('#run-button').click();
    await expect(page.locator('#result')).toHaveAttribute('data-state', 'complete');
    await page.locator('details summary').click();
    await expectNoA11yViolations(page);

    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(pageWidth).toBeLessThanOrEqual(viewport.width);
    expect(errors, errors.join('\n')).toEqual([]);
  });
}

test('the complete experiment is operable from the keyboard', async ({ page }) => {
  await page.goto('./');
  await page.keyboard.press('Tab');
  const skipLink = page.locator('.cl-skip-link');
  await expect(skipLink).toBeFocused();
  await expect(skipLink).toHaveAttribute('href', '#app');

  await page.locator('#overt-select').focus();
  await page.keyboard.press('ArrowDown');
  await page.locator('#run-button').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#result')).toHaveAttribute('data-state', 'complete');

  await page.locator('details summary').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('details')).toHaveAttribute('open', '');
});

