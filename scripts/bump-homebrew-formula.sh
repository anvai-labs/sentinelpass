#!/usr/bin/env bash
# Bump the sentinelpass formula in anvai-labs/homebrew-tap for a release.
#
# Usage: scripts/bump-homebrew-formula.sh <version>   (e.g. 0.8.0)
# Env:   GH_TOKEN (or TAP_TOKEN) — token with Contents:write on the tap.
#
# The formula pins prebuilt release archives (sentinelpass-<version>-macos.tar.gz
# and -linux.tar.gz), so bumping means: new version line + two sha256 values.
set -euo pipefail

VERSION="${1:-${VERSION:-}}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>   (e.g. 0.8.0)" >&2
    exit 1
fi

TAP_REPO="${TAP_REPO:-anvai-labs/homebrew-tap}"
FORMULA="${FORMULA:-Formula/sentinelpass.rb}"

command -v gh >/dev/null || { echo "gh CLI required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

TMP_TAP="$(mktemp -d)"
trap 'rm -rf "$TMP_TAP"' EXIT

echo "Cloning ${TAP_REPO}..."
gh repo clone "$TAP_REPO" "$TMP_TAP/tap" -- --depth 1

sha256_of() {
    local url="$1"
    if command -v sha256sum >/dev/null; then
        curl -fsSL "$url" | sha256sum | awk '{print $1}'
    else
        curl -fsSL "$url" | shasum -a 256 | awk '{print $1}'
    fi
}

BASE="https://github.com/anvai-labs/sentinelpass/releases/download/v${VERSION}"
MACOS_SHA="$(sha256_of "${BASE}/sentinelpass-${VERSION}-macos.tar.gz")"
LINUX_SHA="$(sha256_of "${BASE}/sentinelpass-${VERSION}-linux.tar.gz")"
echo "macos sha256: ${MACOS_SHA}"
echo "linux sha256: ${LINUX_SHA}"

python3 - "$TMP_TAP/tap/$FORMULA" "$VERSION" "$MACOS_SHA" "$LINUX_SHA" <<'PYEOF'
import re
import sys

path, version, macos_sha, linux_sha = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(path) as f:
    content = f.read()

# The formula may pin the version via a `version "X"` line or via the version
# embedded in the archive URLs. Handle both shapes.
content, n_ver = re.subn(r'(  version ")[^"]+(")', rf"\g<1>{version}\g<2>", content)

url_versions = set(re.findall(r"download/v(\d+(?:\.\d+)+)/", content))
if url_versions:
    if len(url_versions) != 1:
        sys.exit(f"Formula URLs disagree on version: {sorted(url_versions)}")
    old = url_versions.pop()
    if old != version:
        content = re.sub(rf'(url "[^"]*?v){old}(/)', rf"\g<1>{version}\g<2>", content)
        content = re.sub(rf"(url \"[^\"]*?sentinelpass-){old}(-)", rf"\g<1>{version}\g<2>", content)

# Replace the two archive sha256 values in order of appearance
shas = iter([macos_sha, linux_sha])
content, n_sha = re.subn(r'(  sha256 ")[0-9a-f]+(")', lambda m: m.group(1) + next(shas) + m.group(2), content)

if n_sha != 2:
    sys.exit(f"Unexpected formula shape (version-line replacements: {n_ver}, sha replacements: {n_sha})")

with open(path, "w") as f:
    f.write(content)
print(f"Formula bumped to {version}")
PYEOF

cd "$TMP_TAP/tap"
git config user.name "sentinelpass-release-bot"
git config user.email "noreply@anvai-labs.dev"
git add "$FORMULA"
git commit -m "sentinelpass v${VERSION}"
git push origin HEAD
echo "Pushed formula bump for v${VERSION} to ${TAP_REPO}"
