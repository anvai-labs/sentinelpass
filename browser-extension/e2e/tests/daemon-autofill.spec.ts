/**
 * Chromium + REAL daemon + REAL native-host E2E suite (WBS-719, TV-001).
 *
 * Covers the critical autofill flows against the actual trust boundary
 * (extension -> native host -> daemon -> vault):
 *   1. HTTPS autofill happy path (single match fills the bound field).
 *   2. HTTP autofill default-deny (WBS-711) with no grant.
 *   3. HTTP allow after an explicit per-site grant (WBS-712 daemon-side).
 *   4. Ambiguity chooser for multiple matches (WBS-715).
 *   5. Save flow end-to-end (capture -> resume prompt -> confirm -> vault).
 *   6. Locked-vault negative (no delivery).
 *
 * Prerequisites: cargo build -p sentinelpass-daemon -p sentinelpass-host
 * -p sentinelpass-cli, and `npx playwright install chromium`.
 */

import { test, expect, chromium, type BrowserContext, type Page } from '@playwright/test';
import { cpSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import {
  startDaemonHarness,
  installNativeHostManifest,
  grantInsecureViaHost,
  type DaemonHarness,
  CHROME_EXTENSION_ID,
  MASTER_PASSWORD,
} from './helpers/daemon-harness';

// The SHIPPED manifest uses optional_host_permissions (WBS-712): Chrome's
// optional-permission PROMPT is a browser-level dialog Playwright cannot
// drive, so the harness loads a copy with install-time hosts restored and
// exercises every DAEMON-side gate for real. The popup request flow itself
// remains covered by the popup unit path, not this suite.
const EXTENSION_PATH = mkdtempSync(path.join('/tmp', 'sp-e2e-ext-'));
const popupConsole = new Map<Page, string[]>();
const workerConsole: string[] = [];
function consoleLinesFor(page: Page): string[] {
  let lines = popupConsole.get(page);
  if (!lines) {
    lines = [];
    popupConsole.set(page, lines);
  }
  return lines;
}
const HEADLESS = process.env.E2E_HEADED !== '1';

const LOGIN_PAGE = {
  path: '/login',
  html: `<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Login</title></head>
  <body>
    <h1>Fixture Login</h1>
    <form id="login-form" action="/after" method="get">
      <label for="username">Username</label>
      <input id="username" name="username" type="email" value="" autocomplete="username" />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" value="" autocomplete="current-password" />
      <button id="submit" type="submit">Sign in</button>
    </form>
  </body>
</html>`,
};

const AFTER_PAGE = {
  path: '/after',
  html: `<!doctype html>
<html>
  <head><meta charset="utf-8"><title>After Login</title></head>
  <body>
    <h1>Fixture After</h1>
    <p>Post-login destination page.</p>
  </body>
</html>`,
};

let harness: DaemonHarness;
let context: BrowserContext;
let userDataDir: string;

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  harness = await startDaemonHarness({
    credentials: [
      // localhost single-entry host: the happy path host.
      { title: 'Solo Site', username: 'solo@fixture.test', password: 'solo-secret-111', url: 'https://localhost:8443' },
      // 127.0.0.1 two-entry host: ambiguity + HTTP policy tests.
      { title: 'Fixture Site', username: 'primary@fixture.test', password: 'primary-secret-123', url: 'https://127.0.0.1' },
      { title: 'Second Account', username: 'secondary@fixture.test', password: 'secondary-secret-456', url: 'https://127.0.0.1' },
    ],
    pages: [LOGIN_PAGE, AFTER_PAGE],
  });

  // Copy the extension and restore install-time host permissions for the
  // harness (see note above).
  {
    const sourceDir = path.resolve(__dirname, '..', '..', 'chrome');
    cpSync(sourceDir, EXTENSION_PATH, { recursive: true });
    const manifestPath = path.join(EXTENSION_PATH, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.host_permissions = manifest.optional_host_permissions;
    delete manifest.optional_host_permissions;
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  }

  userDataDir = mkdtempSync(path.join(tmpdir(), 'sentinelpass-e2e-profile-'));
  installNativeHostManifest(userDataDir, CHROME_EXTENSION_ID);
  // Belt and suspenders: also the HOME-scoped default locations that
  // Chromium derives from the overridden HOME.
  for (const rel of [
    path.join('Library', 'Application Support', 'Chromium', 'NativeMessagingHosts'),
    path.join('.config', 'chromium', 'NativeMessagingHosts'),
  ]) {
    const dir = path.join(harness.homeDir, rel);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, 'com.passwordmanager.host.json'),
      JSON.stringify(
        {
          name: 'com.passwordmanager.host',
          description: 'SentinelPass Native Messaging Host (e2e)',
          path: path.join(__dirname, '..', '..', '..', '..', 'target', 'debug', 'sentinelpass-host'),
          type: 'stdio',
          allowed_origins: [`chrome-extension://${CHROME_EXTENSION_ID}/`],
        },
        null,
        2
      )
    );
  }

  context = await chromium.launchPersistentContext(userDataDir, {
    headless: HEADLESS,
    ignoreHTTPSErrors: true,
    channel: process.env.CHROME_EXECUTABLE ? undefined : 'chromium',
    executablePath: process.env.CHROME_EXECUTABLE || undefined,
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      '--ignore-certificate-errors',
      '--no-first-run',
      '--no-default-browser-check',
    ],
    env: {
      ...process.env,
      HOME: harness.homeDir,
      XDG_RUNTIME_DIR: path.join(harness.homeDir, 'runtime'),
    },
  });

  // Confirm the unpacked extension loaded under the expected stable ID.
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  // Evaluated inside the service worker where the chrome namespace exists.
  const runtimeId = await worker.evaluate(() => (globalThis as any).chrome.runtime.id);
  expect(runtimeId).toBe(CHROME_EXTENSION_ID);
});

test.afterAll(async () => {
  await context?.close();
  await harness?.shutdown();
  if (userDataDir) {
    rmSync(userDataDir, { recursive: true, force: true });
  }
});

/** Open the popup's Settings view (site access lives there). */
async function openPopupSettings(): Promise<Page> {
  const popupPage = await context.newPage();
  popupPage.on('pageerror', (error) => consoleLinesFor(popupPage).push(`pageerror: ${error.message}`));
  popupPage.on('console', (message) => consoleLinesFor(popupPage).push(message.text()));
  await popupPage.goto(`chrome-extension://${CHROME_EXTENSION_ID}/popup.html`);
  // The async vault-status probe swaps views when it settles; wait for it
  // before opening Settings or the view gets hidden again under us.
  await expect(popupPage.locator('#unlockedView:not(.hidden), #lockedView:not(.hidden)')).toBeVisible({
    timeout: 15_000,
  });
  const worker = context.serviceWorkers()[0];
  if (worker) {
    const tabDump = await worker.evaluate(async () => {
      const webTabs = await (globalThis as any).chrome.tabs.query({
        url: ['http://*/*', 'https://*/*'],
      });
      return webTabs.map((t: any) => ({ id: t.id, url: t.url, active: t.active }));
    });
    console.log('[e2e] web tabs:', JSON.stringify(tabDump));
  }
  await popupPage.locator('#settingsBtn').click();
  try {
    await expect(popupPage.locator('#siteAccessToggle')).toBeVisible({ timeout: 10_000 });
  } catch (error) {
    const dump = await popupPage.evaluate(() => {
      const views: Record<string, string> = {};
      for (const v of document.querySelectorAll('.view')) {
        views[v.id] = v.className;
      }
      const toggle = document.getElementById('siteAccessToggle');
      return {
        views,
        toggleClass: toggle ? toggle.className : 'MISSING',
        settingsOpen: typeof (window as any).__openSettingsCalled !== 'undefined',
      };
    });
    throw new Error(`site access toggle not visible: ${JSON.stringify(dump)}`);
  }
  return popupPage;
}

/** Grant daemon-side plain-HTTP autofill for the site via the REAL host. */
async function grantHttpAutofill(host: string): Promise<void> {
  grantInsecureViaHost(harness.homeDir, host);
}

const pageConsole = new Map<Page, string[]>();

async function newPage(): Promise<Page> {
  const page = await context.newPage();
  const lines: string[] = [];
  pageConsole.set(page, lines);
  page.on('console', (message) => {
    const text = message.text();
    lines.push(`${message.type()}: ${text}`);
  });
  return page;
}

function pageLog(page: Page): string[] {
  return pageConsole.get(page) ?? [];
}

/**
 * Click a chooser row by rendered position (the rows live in a closed
 * shadow root; real mouse input stays a trusted user event). Walks the
 * candidate offsets until the expected account fills — the closed root
 * hides row geometry from the test by design.
 */
async function clickChooserRow(page: Page, rowIndex: number, expectedUsername: string): Promise<void> {
  const host = page.locator('.pm-credential-chooser-host');
  const box = await host.boundingBox();
  if (!box) {
    throw new Error('chooser has no bounding box');
  }
  const username = page.locator('#username');
  const baseY = box.y + 12 + 25 + 18;
  for (const offset of [rowIndex * 41, (rowIndex + 1) * 41, (rowIndex - 1) * 41, 0]) {
    if (offset < 0) {
      continue;
    }
    await page.mouse.click(box.x + box.width / 2, baseY + offset);
    try {
      await expect(username).toHaveValue(expectedUsername, { timeout: 3_000 });
      return;
    } catch {
      // Wrong row (or a stray area) — walk to the next candidate offset.
      // The chooser closes after a trusted pick, so re-open it via the
      // autofill button if it disappeared.
      const chooserGone = (await page.locator('.pm-credential-chooser-host').count()) === 0;
      if (chooserGone) {
        const passwordField = page.locator('#password');
        await passwordField.click();
        const button = page.locator('.pm-autofill-button').first();
        await expect(button).toBeVisible({ timeout: 5_000 });
        await button.click();
        await expect(page.locator('.pm-credential-chooser-host')).toBeVisible({ timeout: 10_000 });
        const refreshed = await page.locator('.pm-credential-chooser-host').boundingBox();
        if (refreshed) {
          // Re-base on the fresh box.
          box.x = refreshed.x;
          box.y = refreshed.y;
        }
      }
    }
  }
  await page.screenshot({ path: 'test-results/chooser-debug.png' });
  const boxAfter = await page.locator('.pm-credential-chooser-host').boundingBox();
  throw new Error(
    `chooser row for ${expectedUsername} never filled the form; box=${JSON.stringify(boxAfter)}`
  );
}

/** Focus the password field and click the injected autofill button. */
async function clickAutofill(page: Page): Promise<void> {
  const passwordField = page.locator('#password');
  await passwordField.click();
  const button = page.locator('.pm-autofill-button').first();
  try {
    await expect(button).toBeVisible({ timeout: 10_000 });
  } catch (error) {
    const worker = context.serviceWorkers()[0];
    const workerDump = worker
      ? await worker.evaluate(() => {
          const manifest = (globalThis as any).chrome.runtime.getManifest();
          return {
            version: manifest.version,
            permissions: manifest.permissions,
            host_permissions: manifest.host_permissions,
            optional_host_permissions: manifest.optional_host_permissions,
            content_scripts: manifest.content_scripts,
          };
        })
      : { worker: 'none' };
    const dump = await page.evaluate(() => ({
      runtimeId: (globalThis as any).chrome?.runtime?.id ?? null,
      url: location.href,
      passwordFields: document.querySelectorAll('input[type="password"]').length,
    }));
    throw new Error(`autofill button not injected: ${JSON.stringify({ dump, workerDump })}`);
  }
  await button.click();
}

test('HTTPS autofill fills the single matching credential', async () => {
  const page = await newPage();
  // The 'localhost' host has exactly ONE entry — no chooser, direct fill.
  await page.goto(`${harness.httpsBaseUrl.replace('127.0.0.1', 'localhost')}/login`, {
    waitUntil: 'domcontentloaded',
  });

  await page.reload({ waitUntil: 'domcontentloaded' });

  await clickAutofill(page);

  await expect(page.locator('#username')).toHaveValue('solo@fixture.test', { timeout: 15_000 });
  await expect(page.locator('#password')).toHaveValue('solo-secret-111');
  await page.close();
});

test('HTTP autofill is default-denied without an insecure grant (WBS-711)', async () => {
  const page = await newPage();
  await page.goto(`${harness.httpBaseUrl}/login`, { waitUntil: 'domcontentloaded' });

  // NO daemon-side insecure allowance exists: the 711 scheme gate must
  // refuse with its typed toast (the harness manifest carries install-time
  // hosts so the content script injects and the DAEMON gate is exercised).
  await page.reload({ waitUntil: 'domcontentloaded' });

  await clickAutofill(page);

  await expect(page.locator('text=Autofill is disabled on unencrypted HTTP sites')).toBeVisible({
    timeout: 10_000,
  });
  await expect(page.locator('#username')).toHaveValue('');
  await expect(page.locator('#password')).toHaveValue('');
  await page.close();
});

test('HTTP autofill delivers after an explicit per-site grant (WBS-712)', async () => {
  // The popup reads the most recent web tab; visit the fixture first so the
  // grant binds to 127.0.0.1.
  const page = await newPage();
  await page.goto(`${harness.httpBaseUrl}/login`, { waitUntil: 'domcontentloaded' });
  await grantHttpAutofill('127.0.0.1');

  await page.reload({ waitUntil: 'domcontentloaded' });
  await clickAutofill(page);

  // Two 127.0.0.1 credentials exist — the explicit chooser must appear and
  // the pick drives the fill (no silent first-match even after granting).
  try {
    await expect(page.locator('.pm-credential-chooser-host')).toBeVisible({ timeout: 10_000 });
  } catch (error) {
    const dump = await page.evaluate(() => ({
      floating: Array.from(document.querySelectorAll('body > div'))
        .filter((n) => (n.style.zIndex || '').length > 0)
        .map((n) => n.className),
    }));
    throw new Error(`chooser did not appear: ${JSON.stringify(dump)} (original: ${error})`);
  }
  // The chooser renders inside a CLOSED shadow root (page scripts can neither
  // read the candidates nor synthesize picks), so the test clicks the rows
  // by their rendered coordinates — real, trusted input events.
  await clickChooserRow(page, 0, 'primary@fixture.test');
  await expect(page.locator('#username')).toHaveValue('primary@fixture.test', { timeout: 15_000 });
  await expect(page.locator('#password')).toHaveValue('primary-secret-123');
  await page.close();
});

test('multiple matches surface the explicit chooser and fill the picked account (WBS-715)', async () => {
  const page = await newPage();
  await page.goto(`${harness.httpsBaseUrl}/login`, { waitUntil: 'domcontentloaded' });

  await clickAutofill(page);

  await expect(page.locator('.pm-credential-chooser-host')).toBeVisible({ timeout: 10_000 });
  await clickChooserRow(page, 1, 'secondary@fixture.test');

  await expect(page.locator('#username')).toHaveValue('secondary@fixture.test', {
    timeout: 15_000,
  });
  await expect(page.locator('#password')).toHaveValue('secondary-secret-456');
  await page.close();
});

test('submitting a login captures and saves through the daemon', async () => {
  const page = await newPage();
  await page.goto(`${harness.httpBaseUrl}/login`, { waitUntil: 'domcontentloaded' });

  await page.fill('#username', 'fresh@fixture.test');
  await page.fill('#password', 'fresh-secret-789');
  await page.evaluate(() => {
    document.addEventListener('submit', () => console.log('PROBE submit fired'), true);
    document.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      if (target.id === 'submit') {
        console.log('PROBE click fired, isTrusted=', (e as any).isTrusted);
      }
    }, true);
  });
  await page.click('#submit');
  await page.waitForURL('**/after*');

  // Diagnose: what did the background actually store at capture time?
  const worker = context.serviceWorkers()[0];
  const sessionDump = worker
    ? await worker.evaluate(async () => chrome.storage.session.get(null))
    : { worker: 'none' };
  console.log('[e2e] session after submit:', JSON.stringify(sessionDump));

  // The 2FA-page resume path shows the inline save prompt.
  const prompt = page.locator('.pm-save-prompt');
  try {
    await expect(prompt).toBeVisible({ timeout: 15_000 });
  } catch (error) {
    await page.waitForTimeout(4000);
    throw new Error(
      `inline save prompt never appeared: ${JSON.stringify({
        pageConsole: pageLog(page).slice(-40),
        daemonLog: harness.daemonLog.slice(-600),
      })} (original: ${error})`
    );
  }
  await page.locator('.pm-prompt-btn-save').click();

  // The vault now holds the submitted credential — verify through the CLI
  // against the same daemon.
  const deadline = Date.now() + 15_000;
  let listed = '';
  while (Date.now() < deadline) {
    listed = harness.cli(['list']).stdout;
    if (listed.includes('fresh@fixture.test') || listed.includes('127.0.0.1')) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  expect(listed).toContain('fresh@fixture.test');
  await page.close();
});

test('a locked vault delivers nothing', async () => {
  const lock = harness.cli(['lock']);
  expect(lock.status).toBe(0);

  const page = await newPage();
  await page.goto(`${harness.httpsBaseUrl}/login`, { waitUntil: 'domcontentloaded' });

  await clickAutofill(page);

  // No delivery either way — the credential fields stay untouched.
  await expect(page.locator('#username')).toHaveValue('', { timeout: 10_000 });
  await expect(page.locator('#password')).toHaveValue('');
  await page.close();

  // Re-unlock for any later tests.
  const unlock = harness.cli(['unlock'], `${MASTER_PASSWORD}\n`);
  expect(unlock.status).toBe(0);
});
