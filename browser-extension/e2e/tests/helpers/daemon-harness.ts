/**
 * Real daemon + native-host harness for the Chromium E2E suite
 * (WBS-719, TV-001).
 *
 * Provisions an ISOLATED SentinelPass installation (temp HOME /
 * XDG_RUNTIME_DIR), starts the REAL daemon and talks to the REAL native
 * messaging host from a real Chromium running the unpacked extension —
 * no mocks on the trust boundary.
 *
 * Isolation model: the `dirs` crate derives every data/config/runtime path
 * from HOME (macOS/Windows) or XDG_* (Linux), so overriding HOME +
 * XDG_RUNTIME_DIR for the daemon, CLI, native host, AND the Chromium
 * process confines the entire installation to a temp directory.
 */

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { mkdtempSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import selfsigned from 'selfsigned';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const MASTER_PASSWORD = 'e2e-master-password';
export const CHROME_EXTENSION_ID = 'nophfgfiiohedlodfeepjoioljbhggdd';
const HOST_NAME = 'com.passwordmanager.host';

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const BIN_DIR = path.join(REPO_ROOT, 'target', 'debug');
const DAEMON_BIN = path.join(BIN_DIR, 'sentinelpass-daemon');
const HOST_BIN = path.join(BIN_DIR, 'sentinelpass-host');
const CLI_BIN = path.join(BIN_DIR, 'sentinelpass');

export interface FixturePage {
  path: string;
  html: string;
}

export interface HarnessOptions {
  /** Entries the vault is provisioned with (URL host drives the binding). */
  credentials: Array<{ title: string; username: string; password: string; url: string }>;
  /** Fixture routes (served over BOTH http and https). */
  pages?: FixturePage[];
}

export interface HarnessCliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

export interface DaemonHarness {
  /** Register an additional fixture route at runtime (both http + https). */
  addFixturePage: (page: FixturePage) => void;
  homeDir: string;
  socketPath: string;
  httpBaseUrl: string;
  httpsBaseUrl: string;
  daemonProcess: ChildProcess;
  daemonLog: string;
  /** Run the CLI inside the harness HOME, with a pty for password prompts. */
  cli: (args: string[], stdin?: string) => HarnessCliResult;
  shutdown: () => Promise<void>;
}

function requireBinaries(): void {
  for (const bin of [DAEMON_BIN, HOST_BIN, CLI_BIN]) {
    if (!existsSync(bin)) {
      throw new Error(
        `Missing ${bin}. Build first: cargo build -p sentinelpass-daemon -p sentinelpass-host -p sentinelpass-cli`
      );
    }
  }
}

/**
 * Run a command inside the harness HOME with a pseudo-tty so the CLI's
 * rpassword prompts (echo disabled) receive piped input.
 */
/**
 * The ISOLATED environment for every spawned process (daemon, CLI, host,
 * browser): HOME pins the dirs-crate paths, and the XDG family is
 * overridden because on Linux the dirs crate PREFERS XDG_CONFIG_HOME /
 * XDG_DATA_HOME over HOME - without this a Linux developer's real vault
 * would be touched (review F10).
 */
export function isolatedEnv(homeDir: string): Record<string, string> {
  return {
    ...process.env,
    HOME: homeDir,
    XDG_RUNTIME_DIR: path.join(homeDir, 'runtime'),
    XDG_CONFIG_HOME: path.join(homeDir, '.config'),
    XDG_DATA_HOME: path.join(homeDir, '.local', 'share'),
    XDG_CACHE_HOME: path.join(homeDir, '.cache'),
    XDG_STATE_HOME: path.join(homeDir, '.local', 'state'),
  };
}

function runWithTty(
  homeDir: string,
  command: string,
  args: string[],
  stdin?: string
): HarnessCliResult {
  const shellQuote = (part: string): string => `'${part.replaceAll("'", `'\\''`)}'`;
  const commandLine = [command, ...args].map(shellQuote).join(' ');
  const stdinLiteral = stdin ?? '';
  const inner = `printf '%s' ${shellQuote(stdinLiteral)} | ${commandLine}`;
  const ptyDriver = path.join(__dirname, 'cli_pty.py');
  const result = spawnSync('python3', [ptyDriver, command, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: homeDir,
      // The FULL XDG family — matching isolatedEnv. On Linux the dirs
      // crate honors XDG_CONFIG_HOME/XDG_DATA_HOME over HOME; without
      // these the CLI resolves its config/token dir OUTSIDE the isolated
      // HOME and finds no daemon token (the CI-only unlock failure).
      XDG_CONFIG_HOME: path.join(homeDir, '.config'),
      XDG_DATA_HOME: path.join(homeDir, '.local', 'share'),
      XDG_CACHE_HOME: path.join(homeDir, '.cache'),
      XDG_STATE_HOME: path.join(homeDir, '.local', 'state'),
      XDG_RUNTIME_DIR: path.join(homeDir, 'runtime'),
      SENTINELPASS_CLI_STDIN: stdin ?? '',
    },
    timeout: 60_000,
  });
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

async function makeCertificate(): Promise<{ key: string; cert: string }> {
  const pem = await selfsigned.generate(
    [{ name: 'commonName', value: '127.0.0.1' }],
    {
      keySize: 2048,
      algorithm: 'sha256',
      extensions: [{ name: 'subjectAltName', altNames: [{ type: 7, ip: '127.0.0.1' }] }],
    }
  );
  return { key: pem.private, cert: pem.cert };
}

async function startFixtureServer(
  pages: FixturePage[],
  https: boolean
): Promise<{ server: Server; baseUrl: string }> {
  const handler = (
    req: import('node:http').IncomingMessage,
    res: import('node:http').ServerResponse
  ) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const page =
      pages.find((candidate) => candidate.path === url.pathname) ??
      pages.find((candidate) => candidate.path === '/');
    if (!page) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(page.html);
  };
  const server = https
    ? createHttpsServer(await makeCertificate(), handler)
    : createHttpServer(handler);
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('no fixture address'));
        return;
      }
      const port = address.port;
      resolve({ server, baseUrl: `${https ? 'https' : 'http'}://127.0.0.1:${port}` });
    });
  });
}

export async function startDaemonHarness(options: HarnessOptions): Promise<DaemonHarness> {
  requireBinaries();

  const pages: FixturePage[] = options.pages ?? [];
  const [{ server: httpServer, baseUrl: httpBaseUrl }, { server: httpsServer, baseUrl: httpsBaseUrl }] =
    await Promise.all([startFixtureServer(pages, false), startFixtureServer(pages, true)]);

  // The unix socket path (runtime dir + socket name) must fit sockaddr_un's
  // 104-byte sun_path on macOS — /var/folders/... temp dirs are too long,
  // so pin the short /tmp prefix there (review finding, daemon bind).
  const homeBase = process.platform === 'darwin' ? '/tmp' : tmpdir();
  const homeDir = mkdtempSync(path.join(homeBase, 'sp-daemon-e2e-'));
  mkdirSync(path.join(homeDir, 'runtime'), { recursive: true });
  const socketPath = path.join(homeDir, 'runtime', 'SentinelPass', 'sentinelpass.sock');

  const cli = (args: string[], stdin?: string) => runWithTty(homeDir, CLI_BIN, args, stdin);

  // 1. Provision the vault offline (no daemon yet — creation is exclusive).
  const initResult = cli(['init'], `${MASTER_PASSWORD}\n${MASTER_PASSWORD}\n`);
  if (initResult.status !== 0) {
    throw new Error(`CLI init failed: ${initResult.stdout}\n${initResult.stderr}`);
  }

  // 2. Start the REAL daemon inside the harness HOME. The daemon prompts
  // for the master password at startup unless --start-locked; the harness
  // unlocks through the CLI (the daemon-unlock path) instead.
  const daemonProcess = spawn(DAEMON_BIN, ['--start-locked'], {
    env: isolatedEnv(homeDir),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const daemonLog: string[] = [];
  daemonProcess.stdout?.on('data', (chunk) => daemonLog.push(String(chunk)));
  daemonProcess.stderr?.on('data', (chunk) => daemonLog.push(String(chunk)));

  const deadline = Date.now() + 30_000;
  while (!existsSync(socketPath)) {
    if (daemonProcess.exitCode !== null && daemonProcess.exitCode !== 0) {
      throw new Error(`daemon exited: ${daemonLog.join('')}`);
    }
    if (Date.now() > deadline) {
      throw new Error(`daemon socket never appeared: ${daemonLog.join('')}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  // 3. Unlock via the daemon, then seed credentials through it.
  const unlock = cli(['unlock'], `${MASTER_PASSWORD}\n`);
  if (unlock.status !== 0) {
    throw new Error(`CLI unlock failed: ${unlock.stdout}\n${unlock.stderr}`);
  }

  for (const credential of options.credentials) {
    const add = cli([
      'add',
      '--title', credential.title,
      '--username', credential.username,
      '--password', credential.password,
      '--url', credential.url,
    ]);
    if (add.status !== 0) {
      throw new Error(`CLI add failed for ${credential.title}: ${add.stdout}\n${add.stderr}`);
    }
  }

  const fixturePages = pages;
  const addFixturePage = (page: FixturePage) => {
    fixturePages.push(page);
  };

  const shutdown = async () => {
    try {
      httpServer.close();
      httpsServer.close();
    } catch {
      // already closed
    }
    daemonProcess.kill('SIGTERM');
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => resolve(), 2000);
      daemonProcess.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  };

  return {
    homeDir,
    socketPath,
    httpBaseUrl,
    httpsBaseUrl,
    daemonProcess,
    get daemonLog() {
      return daemonLog.join('');
    },
    addFixturePage,
    cli,
    shutdown,
  };
}

/**
 * Drive the REAL native host + daemon directly (the same stdio protocol the
 * browser speaks) for operations whose BROWSER-side UX (Chrome's optional
 * permission prompt, popup messaging races) is not automatable under
 * Playwright. Nothing here is mocked: the host process and the daemon
 * enforce every gate they enforce for the browser.
 */
export function grantInsecureViaHost(homeDir: string, host: string): void {
  const message = JSON.stringify({
    version: 1,
    type: 'grant_site_permission',
    domain: host,
    allow_insecure: true,
    request_id: `e2e-grant-${Date.now()}`,
  });
  const result = spawnSync(
    'python3',
    [path.join(__dirname, 'probe_host.py'), HOST_BIN, message],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        HOME: homeDir,
        // FULL XDG family — matching isolatedEnv. On Linux the dirs crate
        // honors XDG_CONFIG_HOME over HOME; without it the host resolves
        // its config/token dir OUTSIDE the isolated HOME and fails the
        // daemon handshake (CI-only; macOS ignores XDG_CONFIG_HOME).
        XDG_CONFIG_HOME: path.join(homeDir, '.config'),
        XDG_DATA_HOME: path.join(homeDir, '.local', 'share'),
        XDG_CACHE_HOME: path.join(homeDir, '.cache'),
        XDG_STATE_HOME: path.join(homeDir, '.local', 'state'),
        XDG_RUNTIME_DIR: path.join(homeDir, 'runtime'),
      },
      timeout: 30_000,
    }
  );
  const combined = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  // The daemon's "Site permission granted" line goes to the daemon's own
  // log, not the host probe's output — assert on the host response only.
  if (
    result.status !== 0 ||
    !combined.includes('"type":"credential_response"') ||
    !combined.includes('"success":true')
  ) {
    throw new Error(`host grant failed: ${combined.slice(0, 4000)}`);
  }
}

/**
 * Write the native-messaging host manifest into the Chromium profile so the
 * browser launches the REAL sentinelpass-host binary.
 */
export function installNativeHostManifest(userDataDir: string, extensionId: string): void {
  // Chromium profiles read <profile>/NativeMessagingHosts on macOS/Linux.
  const dir = path.join(userDataDir, 'NativeMessagingHosts');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    path.join(dir, `${HOST_NAME}.json`),
    JSON.stringify(
      {
        name: HOST_NAME,
        description: 'SentinelPass Native Messaging Host (e2e)',
        path: HOST_BIN,
        type: 'stdio',
        allowed_origins: [`chrome-extension://${extensionId}/`],
      },
      null,
      2
    )
  );
}
