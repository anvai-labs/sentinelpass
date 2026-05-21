import { copyFile, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

const emittedFiles = [
  'browser-extension/chrome/background.js',
  'browser-extension/chrome/content.js',
  'browser-extension/chrome/popup.js',
  'browser-extension/firefox/background.js',
  'browser-extension/firefox/content.js',
  'browser-extension/firefox/popup.js',
  'sentinelpass-ui/app.js',
  'sentinelpass-ui/credential-types.js',
  'sentinelpass-ui/state.js',
  'sentinelpass-ui/utils.js',
  'sentinelpass-ui/totp.js',
  'sentinelpass-ui/entries.js'
];

for (const relativePath of emittedFiles) {
  const absolutePath = path.join(repoRoot, relativePath);
  const content = await readFile(absolutePath, 'utf8');
  const sanitized = content.replace(/\nexport \{\};\s*$/m, '\n');
  if (sanitized !== content) {
    await writeFile(absolutePath, sanitized, 'utf8');
  }
}

const uiFilesToSync = [
  ['sentinelpass-ui/app.js', 'sentinelpass-ui/dist/app.js'],
  ['sentinelpass-ui/credential-types.js', 'sentinelpass-ui/dist/credential-types.js'],
  ['sentinelpass-ui/url-utils.js', 'sentinelpass-ui/dist/url-utils.js'],
  ['sentinelpass-ui/state.js', 'sentinelpass-ui/dist/state.js'],
  ['sentinelpass-ui/utils.js', 'sentinelpass-ui/dist/utils.js'],
  ['sentinelpass-ui/totp.js', 'sentinelpass-ui/dist/totp.js'],
  ['sentinelpass-ui/entries.js', 'sentinelpass-ui/dist/entries.js'],
  ['sentinelpass-ui/index.html', 'sentinelpass-ui/dist/index.html'],
  ['sentinelpass-ui/styles.css', 'sentinelpass-ui/dist/styles.css']
];

for (const [source, target] of uiFilesToSync) {
  await copyFile(path.join(repoRoot, source), path.join(repoRoot, target));
}

console.log('[web:build] Post-processed emitted JS and synced sentinelpass-ui/dist assets');
