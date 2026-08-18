#!/usr/bin/env node

// Live interoperability smoke test for secure-send-cli and secure-send-web.
//
// This deliberately uses the public Nostr relays and real WebRTC transports.
// It is therefore separate from `cargo test` and requires internet access,
// Node/npm, a Chrome-family browser, and the sibling secure-send-web checkout.

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import {
  dirname,
  join,
  resolve,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = resolve(SCRIPT_DIR, '..');
const WEB_ROOT = resolve(
  process.env.SECURE_SEND_WEB_ROOT ?? join(CLI_ROOT, '..', 'secure-send-web'),
);
const WEB_URL = new URL(
  process.env.SECURE_SEND_WEB_URL ?? 'http://127.0.0.1:4173',
);
const CLI = join(CLI_ROOT, 'target', 'debug', 'secure-send-cli');
const CACHE_ROOT = resolve(
  process.env.SECURE_SEND_E2E_CACHE
    ?? join(tmpdir(), 'secure-send-cli-live-e2e-cache'),
);
const PLAYWRIGHT_VERSION = process.env.SECURE_SEND_PLAYWRIGHT_VERSION ?? '1.55.0';
const ARTIFACTS = await mkdtemp(join(tmpdir(), 'secure-send-live-e2e-'));
const CONFIRMATION_CODE = /^[0-9A-HJKMNPQRSTVWXYZ]{8}$/;

const activeClis = new Set();
let browser;
let ownedWebServer;
let cleanupStarted = false;

function sleep(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

async function withTimeout(promise, timeoutMs, description) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Timed out waiting for ${description}`)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function runCommand(command, args, options = {}) {
  console.log(`[setup] ${command} ${args.join(' ')}`);
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: { ...process.env, ...options.env },
    stdio: 'inherit',
  });
  const result = await new Promise((resolvePromise, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolvePromise({ code, signal }));
  });
  if (result.code !== 0) {
    throw new Error(
      `${command} exited with code ${result.code ?? 'null'}, signal ${result.signal ?? 'none'}`,
    );
  }
}

async function assertProtocolVersionMatches() {
  const cargoToml = await readFile(join(CLI_ROOT, 'Cargo.toml'), 'utf8');
  const webPackage = JSON.parse(
    await readFile(join(WEB_ROOT, 'package.json'), 'utf8'),
  );
  const metadataMatch = cargoToml.match(
    /^secure-send-web-version\s*=\s*"([^"]+)"\s*$/m,
  );
  if (!metadataMatch) {
    throw new Error('Cargo.toml is missing package.metadata.secure-send-web-version');
  }
  if (metadataMatch[1] !== webPackage.version) {
    throw new Error(
      `Protocol version mismatch: CLI declares secure-send-web ${metadataMatch[1]}, `
      + `but ${WEB_ROOT}/package.json is ${webPackage.version}`,
    );
  }
  console.log(`[setup] protocol version secure-send-web ${webPackage.version}`);
}

async function isReachable(url) {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
    await response.body?.cancel();
    return true;
  } catch {
    return false;
  }
}

async function ensureWebServer() {
  if (await isReachable(WEB_URL)) {
    console.log(`[setup] using existing web server at ${WEB_URL.origin}`);
    return;
  }

  if (WEB_URL.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(WEB_URL.hostname)) {
    throw new Error(
      `Cannot start a local Vite server for ${WEB_URL.origin}; start that URL manually`,
    );
  }
  await access(join(WEB_ROOT, 'node_modules', '.bin', 'vite'), fsConstants.X_OK).catch(() => {
    throw new Error(`Missing web dependencies; run npm install in ${WEB_ROOT}`);
  });

  const port = WEB_URL.port || '80';
  console.log(`[setup] starting secure-send-web at ${WEB_URL.origin}`);
  ownedWebServer = spawn(
    'npm',
    [
      'run',
      'dev',
      '--',
      '--host',
      WEB_URL.hostname,
      '--port',
      port,
      '--strictPort',
    ],
    {
      cwd: WEB_ROOT,
      detached: true,
      env: process.env,
      stdio: 'inherit',
    },
  );
  ownedWebServer.once('error', (error) => {
    console.error(`[web] ${error.stack ?? error}`);
  });

  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (ownedWebServer.exitCode !== null || ownedWebServer.signalCode !== null) {
      throw new Error('secure-send-web exited before becoming ready');
    }
    if (await isReachable(WEB_URL)) {
      return;
    }
    await sleep(250);
  }
  throw new Error(`secure-send-web did not become ready at ${WEB_URL.origin}`);
}

async function loadChromium() {
  const playwrightEntry = join(
    CACHE_ROOT,
    'node_modules',
    'playwright-core',
    'index.mjs',
  );
  try {
    await access(playwrightEntry, fsConstants.R_OK);
  } catch {
    await mkdir(CACHE_ROOT, { recursive: true });
    await runCommand(
      'npm',
      [
        'install',
        '--prefix',
        CACHE_ROOT,
        '--no-save',
        '--no-package-lock',
        `playwright-core@${PLAYWRIGHT_VERSION}`,
      ],
    );
  }
  const playwright = await import(pathToFileURL(playwrightEntry).href);
  return playwright.chromium;
}

async function findBrowser() {
  const candidates = [
    process.env.CHROME_PATH,
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      await access(candidate, fsConstants.X_OK);
      return candidate;
    } catch {
      // Try the next known browser path.
    }
  }
  throw new Error('No Chrome-family browser found; set CHROME_PATH');
}

function runCli(args, label) {
  const child = spawn(CLI, args, {
    cwd: CLI_ROOT,
    env: { ...process.env, RUST_LOG: 'error,webrtc_ice=error' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  activeClis.add(child);

  const captured = { stdout: '', stderr: '' };
  child.stdout.on('data', (chunk) => {
    captured.stdout += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    captured.stderr += chunk.toString();
  });
  const exit = new Promise((resolvePromise, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      activeClis.delete(child);
      resolvePromise({ code, signal });
    });
  });
  return { child, captured, exit, label };
}

function outputTail(text, maximum = 4_000) {
  return text.length > maximum ? `…${text.slice(-maximum)}` : text;
}

function cliFailure(processHandle, detail) {
  return new Error(
    `${processHandle.label}: ${detail}\n`
    + `stdout:\n${outputTail(processHandle.captured.stdout)}\n`
    + `stderr:\n${outputTail(processHandle.captured.stderr)}`,
  );
}

async function waitForStdoutLine(
  processHandle,
  predicate,
  description,
  timeoutMs = 120_000,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const lines = processHandle.captured.stdout
      .split(/\r?\n/)
      .map((line) => line.trim());
    const match = lines.find(predicate);
    if (match !== undefined) {
      return match;
    }
    if (
      processHandle.child.exitCode !== null
      || processHandle.child.signalCode !== null
    ) {
      throw cliFailure(processHandle, `exited before producing ${description}`);
    }
    await sleep(100);
  }
  throw cliFailure(processHandle, `timed out waiting for ${description}`);
}

async function waitForCliSuccess(
  processHandle,
  description,
  timeoutMs = 150_000,
) {
  const result = await withTimeout(processHandle.exit, timeoutMs, description);
  if (result.code !== 0) {
    throw cliFailure(
      processHandle,
      `exited with code ${result.code ?? 'null'}, signal ${result.signal ?? 'none'}`,
    );
  }
}

function instrumentPage(page, label) {
  const pageErrors = [];
  page.on('pageerror', (error) => {
    pageErrors.push(error);
    console.error(`[${label}:pageerror] ${error.stack ?? error}`);
  });
  return () => {
    if (pageErrors.length > 0) {
      throw new Error(`${label}: browser page raised ${pageErrors.length} error(s)`);
    }
  };
}

async function readWebConfirmationCode(page) {
  await page.waitForFunction(
    () => /Confirmation code\s+[0-9A-Z]{4}-[0-9A-Z]{4}/.test(document.body.innerText),
    null,
    { timeout: 120_000 },
  );
  const text = await page.locator('body').innerText();
  const match = text.match(/Confirmation code\s+([0-9A-Z]{4})-([0-9A-Z]{4})/);
  if (!match) {
    throw new Error('Web receiver confirmation code was not found');
  }
  return `${match[1]}${match[2]}`;
}

async function assertSameBytes(expectedPath, actualPath, label) {
  const [expected, actual] = await Promise.all([
    readFile(expectedPath),
    readFile(actualPath),
  ]);
  if (!expected.equals(actual)) {
    throw new Error(
      `${label}: byte mismatch (${expected.length} expected, ${actual.length} actual)`,
    );
  }
  const digest = createHash('sha256').update(actual).digest('hex');
  console.log(`[PASS] ${label}: ${actual.length} bytes, sha256 ${digest}`);
}

async function cliToCli() {
  console.log('\n=== CLI sender -> CLI receiver ===');
  const source = join(CLI_ROOT, 'README.md');
  const outputDir = await mkdtemp(join(ARTIFACTS, 'cli-to-cli-'));
  const sender = runCli(['test', 'send', source], 'CLI sender');
  const pin = await waitForStdoutLine(
    sender,
    (line) => line.length === 12,
    'sender PIN',
  );
  console.log(`[e2e] sender PIN: ${pin}`);

  const receiver = runCli(
    ['test', 'receive', pin, '--output', outputDir],
    'CLI receiver',
  );
  const confirmationCode = await waitForStdoutLine(
    receiver,
    (line) => CONFIRMATION_CODE.test(line),
    'receiver confirmation code',
  );
  console.log(`[e2e] receiver confirmation code: ${confirmationCode}`);
  sender.child.stdin.write(`${confirmationCode}\n`);

  await Promise.all([
    waitForCliSuccess(sender, 'CLI sender'),
    waitForCliSuccess(receiver, 'CLI receiver'),
  ]);
  await assertSameBytes(
    source,
    join(outputDir, 'README.md'),
    'CLI -> CLI transferred file',
  );
}

async function cliToWeb() {
  console.log('\n=== CLI sender -> web receiver ===');
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  const assertNoPageErrors = instrumentPage(page, 'CLI -> web');
  try {
    const source = join(CLI_ROOT, 'README.md');
    const sender = runCli(['test', 'send', source], 'CLI sender');
    const pin = await waitForStdoutLine(
      sender,
      (line) => line.length === 12,
      'sender PIN',
    );
    console.log(`[e2e] CLI sender PIN: ${pin}`);

    await page.goto(new URL('/receive', WEB_URL).href, {
      waitUntil: 'domcontentloaded',
    });
    await page.getByRole('textbox', { name: 'PIN', exact: true }).fill(pin);
    await page.getByRole('button', { name: 'Receive', exact: true }).click();

    const confirmationCode = await readWebConfirmationCode(page);
    console.log(`[e2e] web receiver confirmation code: ${confirmationCode}`);
    sender.child.stdin.write(`${confirmationCode}\n`);

    const downloadButton = page.getByRole('button', { name: 'Download File' });
    await downloadButton.waitFor({ state: 'visible', timeout: 150_000 });
    await waitForCliSuccess(sender, 'CLI sender');

    const downloadPromise = page.waitForEvent('download', { timeout: 30_000 });
    await downloadButton.click();
    const download = await downloadPromise;
    const downloaded = join(ARTIFACTS, 'cli-to-web-README.md');
    await download.saveAs(downloaded);
    await assertSameBytes(source, downloaded, 'CLI -> web downloaded file');
    assertNoPageErrors();
  } finally {
    await context.close();
  }
}

async function webToCli() {
  console.log('\n=== Web sender -> CLI receiver ===');
  const context = await browser.newContext();
  const page = await context.newPage();
  const assertNoPageErrors = instrumentPage(page, 'web -> CLI');
  try {
    const source = join(CLI_ROOT, 'docs', 'USE_CASES.md');
    const outputDir = await mkdtemp(join(ARTIFACTS, 'web-to-cli-'));

    await page.goto(new URL('/send', WEB_URL).href, {
      waitUntil: 'domcontentloaded',
    });
    await page.locator('input[type="file"]').first().setInputFiles(source);
    await page.getByRole('button', { name: 'Start Auto Exchange' }).click();

    const pinInput = page.getByRole('textbox', { name: 'PIN', exact: true });
    await pinInput.waitFor({ state: 'visible', timeout: 120_000 });
    const pin = await pinInput.inputValue();
    if (pin.length !== 12) {
      throw new Error(`Unexpected web sender PIN: ${pin}`);
    }
    console.log(`[e2e] web sender PIN: ${pin}`);

    const receiver = runCli(
      ['test', 'receive', pin, '--output', outputDir],
      'CLI receiver',
    );
    const confirmationCode = await waitForStdoutLine(
      receiver,
      (line) => CONFIRMATION_CODE.test(line),
      'receiver confirmation code',
    );
    console.log(`[e2e] CLI receiver confirmation code: ${confirmationCode}`);

    const confirmationInput = page.getByRole('textbox', {
      name: 'Confirmation code',
    });
    await confirmationInput.waitFor({ state: 'visible', timeout: 60_000 });
    await confirmationInput.fill(confirmationCode);
    await page.getByRole('button', { name: 'Start transfer' }).click();

    await waitForCliSuccess(receiver, 'CLI receiver');
    await page.getByText('Transfer Complete!', { exact: true }).waitFor({
      state: 'visible',
      timeout: 60_000,
    });
    await assertSameBytes(
      source,
      join(outputDir, 'USE_CASES.md'),
      'web -> CLI saved file',
    );
    assertNoPageErrors();
  } finally {
    await context.close();
  }
}

async function terminate(child, processGroup = false) {
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  const signal = (name) => {
    try {
      if (processGroup && child.pid !== undefined) {
        process.kill(-child.pid, name);
      } else {
        child.kill(name);
      }
    } catch (error) {
      if (error.code !== 'ESRCH') {
        throw error;
      }
    }
  };
  signal('SIGTERM');
  const exited = new Promise((resolvePromise) => child.once('exit', resolvePromise));
  try {
    await withTimeout(exited, 5_000, 'child process shutdown');
  } catch {
    signal('SIGKILL');
  }
}

async function cleanup() {
  if (cleanupStarted) {
    return;
  }
  cleanupStarted = true;
  await Promise.allSettled([...activeClis].map((child) => terminate(child)));
  if (browser) {
    await browser.close().catch(() => {});
  }
  await terminate(ownedWebServer, true).catch(() => {});
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    cleanup().finally(() => process.exit(signal === 'SIGINT' ? 130 : 143));
  });
}

try {
  await assertProtocolVersionMatches();
  await runCommand('cargo', ['build', '--all-features'], { cwd: CLI_ROOT });
  const chromium = await loadChromium();
  const executablePath = await findBrowser();
  await ensureWebServer();
  browser = await chromium.launch({
    executablePath,
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });

  await cliToCli();
  await cliToWeb();
  await webToCli();
  console.log(`\nALL LIVE INTEROPERABILITY TESTS PASSED\nArtifacts: ${ARTIFACTS}`);
} catch (error) {
  console.error(`\nLIVE INTEROPERABILITY TEST FAILED\n${error.stack ?? error}`);
  console.error(`Artifacts: ${ARTIFACTS}`);
  process.exitCode = 1;
} finally {
  await cleanup();
}
