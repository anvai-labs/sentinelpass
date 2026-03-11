#!/bin/bash
# Package Chrome Extension for Chrome Web Store

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHROME_DIR="${SCRIPT_DIR}/chrome"
DIST_DIR="${SCRIPT_DIR}/dist"
VERSION="${1:-latest}"

echo "📦 Packaging Chrome Extension for Chrome Web Store"
echo "Version: ${VERSION}"
echo ""

# Create dist directory
mkdir -p "${DIST_DIR}"

# Remove old package
rm -f "${DIST_DIR}/sentinelpass-chrome.zip"

# Create clean package with only necessary files
echo "Creating package..."
cd "${CHROME_DIR}"

zip -r "${DIST_DIR}/sentinelpass-chrome-${VERSION}.zip" \
  manifest.json \
  background.js \
  content.js \
  popup.js \
  popup.html \
  styles.css \
  logger.js \
  save-heuristics.js \
  icon16.png \
  icon48.png \
  icon128.png \
  > /dev/null

# Verify package
echo "Verifying package..."
PACKAGE_SIZE=$(stat -f%z "${DIST_DIR}/sentinelpass-chrome-${VERSION}.zip" 2>/dev/null || stat -c%s "${DIST_DIR}/sentinelpass-chrome-${VERSION}.zip" 2>/dev/null)
TS_COUNT=$(unzip -l "${DIST_DIR}/sentinelpass-chrome-${VERSION}.zip" | grep -c '\.ts$' || echo 0)
NODE_MODULES_COUNT=$(unzip -l "${DIST_DIR}/sentinelpass-chrome-${VERSION}.zip" | grep -c 'node_modules' || echo 0)

echo "✓ Package created: ${DIST_DIR}/sentinelpass-chrome-${VERSION}.zip"
echo "  Size: $(numfmt --to=iec-i --suffix=B $PACKAGE_SIZE 2>/dev/null || echo ${PACKAGE_SIZE} bytes)"
echo "  TypeScript files: ${TS_COUNT}"
echo "  node_modules: ${NODE_MODULES_COUNT}"
echo ""

# List package contents
echo "Package contents:"
unzip -l "${DIST_DIR}/sentinelpass-chrome-${VERSION}.zip" | tail -12
echo ""

# Create latest symlink
cd "${DIST_DIR}"
rm -f sentinelpass-chrome.zip
ln -s "sentinelpass-chrome-${VERSION}.zip" sentinelpass-chrome.zip

echo "✓ Ready for Chrome Web Store submission!"
echo "  Upload: ${DIST_DIR}/sentinelpass-chrome-${VERSION}.zip"
echo ""
echo "Next steps:"
echo "  1. Go to Chrome Web Store Developer Dashboard"
echo "  2. Upload the package"
echo "  3. Fill in store listing details"
echo "  4. Submit for review"
