#!/bin/bash
# Package Firefox Extension for AMO (addons.mozilla.org)
#
# The zip is built from the OUTPUT of the canonical extension pipeline
# (`npm run ext:build`), never from a hand-maintained file list: a stale
# hand list is what shipped background scripts that throw on missing
# imports (WBS-911 F2). The runtime set zipped here is exactly the set
# installation/install.sh deploys for Chrome; firefox/ shares the same
# byte-identical build outputs.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIREFOX_DIR="${SCRIPT_DIR}/firefox"
DIST_DIR="${SCRIPT_DIR}/dist"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION="${1:-latest}"

echo "📦 Packaging Firefox Extension for AMO"
echo "Version: ${VERSION}"
echo ""

# Rebuild through the canonical pipeline first. firefox/ carries only build
# outputs (byte-parity with chrome/ is gated by
# tests/web/extension-pipeline.test.ts); rebuilding here guarantees the zip
# can never package a stale artifact.
echo "Building extension via canonical pipeline (npm run ext:build)..."
(cd "$REPO_ROOT" && npm run ext:build)
echo ""

# Create dist directory
mkdir -p "${DIST_DIR}"

# Remove old package
rm -f "${DIST_DIR}/sentinelpass-firefox.zip"

# Runtime file set: manifest + every built .js + static assets, derived from
# the build output directory rather than enumerated by hand.
cd "${FIREFOX_DIR}"

shopt -s nullglob
JS_FILES=(*.js)
ICON_FILES=(icon*.png)
shopt -u nullglob

if [[ ${#JS_FILES[@]} -eq 0 ]]; then
  echo "ERROR: no built .js files found in firefox/ — the pipeline produced no artifacts." >&2
  exit 1
fi
if [[ ! -f manifest.json || ! -f popup.html || ! -f styles.css ]]; then
  echo "ERROR: core runtime files (manifest.json/popup.html/styles.css) missing." >&2
  exit 1
fi
if [[ ${#ICON_FILES[@]} -eq 0 ]]; then
  echo "ERROR: no icon*.png assets found in firefox/." >&2
  exit 1
fi

# Create clean package with only runtime files (never .ts sources, docs,
# or packaging metadata — those are development-tree files).
echo "Creating package..."
PACKAGE_FILES=(manifest.json popup.html styles.css "${ICON_FILES[@]}" "${JS_FILES[@]}")

zip -r "${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip" \
  "${PACKAGE_FILES[@]}" \
  > /dev/null

# Verify package
echo "Verifying package..."
PACKAGE_PATH="${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip"
PACKAGE_SIZE=$(stat -f%z "$PACKAGE_PATH" 2>/dev/null || stat -c%s "$PACKAGE_PATH" 2>/dev/null)
TS_COUNT=$(unzip -l "$PACKAGE_PATH" | grep -c '\.ts$' || echo 0)
NODE_MODULES_COUNT=$(unzip -l "$PACKAGE_PATH" | grep -c 'node_modules' || echo 0)

# WBS-911 F2: every built .js must be in the zip — a module-type background
# script missing one of its imports throws on startup.
for js in "${JS_FILES[@]}"; do
  if ! unzip -l "$PACKAGE_PATH" | grep -q "[[:space:]]${js}\$"; then
    echo "ERROR: built artifact ${js} is missing from the package." >&2
    exit 1
  fi
done

echo "✓ Package created: ${PACKAGE_PATH}"
echo "  Size: $(numfmt --to=iec-i --suffix=B $PACKAGE_SIZE 2>/dev/null || echo ${PACKAGE_SIZE} bytes)"
echo "  JavaScript files: ${#JS_FILES[@]}"
echo "  TypeScript files: ${TS_COUNT}"
echo "  node_modules: ${NODE_MODULES_COUNT}"
echo ""

# List package contents
echo "Package contents:"
unzip -l "$PACKAGE_PATH"
echo ""

# Create latest symlink
cd "${DIST_DIR}"
rm -f sentinelpass-firefox.zip
ln -s "sentinelpass-firefox-${VERSION}.zip" sentinelpass-firefox.zip

echo "✓ Ready for AMO submission!"
echo "  Upload: ${PACKAGE_PATH}"
echo ""
echo "Next steps:"
echo "  1. Go to Firefox Add-ons Developer Dashboard"
echo "  2. Upload the package"
echo "  3. Fill in store listing details"
echo "  4. Submit for review"
