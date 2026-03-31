#!/bin/bash
# Package Firefox Extension for AMO (addons.mozilla.org)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIREFOX_DIR="${SCRIPT_DIR}/firefox"
DIST_DIR="${SCRIPT_DIR}/dist"
VERSION="${1:-latest}"

echo "📦 Packaging Firefox Extension for AMO"
echo "Version: ${VERSION}"
echo ""

# Create dist directory
mkdir -p "${DIST_DIR}"

# Remove old package
rm -f "${DIST_DIR}/sentinelpass-firefox.zip"

# Create clean package with only necessary files
echo "Creating package..."
cd "${FIREFOX_DIR}"

zip -r "${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip" \
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
PACKAGE_SIZE=$(stat -f%z "${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip" 2>/dev/null || stat -c%s "${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip" 2>/dev/null)
TS_COUNT=$(unzip -l "${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip" | grep -c '\.ts$' || echo 0)
NODE_MODULES_COUNT=$(unzip -l "${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip" | grep -c 'node_modules' || echo 0)

echo "✓ Package created: ${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip"
echo "  Size: $(numfmt --to=iec-i --suffix=B $PACKAGE_SIZE 2>/dev/null || echo ${PACKAGE_SIZE} bytes)"
echo "  TypeScript files: ${TS_COUNT}"
echo "  node_modules: ${NODE_MODULES_COUNT}"
echo ""

# List package contents
echo "Package contents:"
unzip -l "${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip" | tail -12
echo ""

# Create latest symlink
cd "${DIST_DIR}"
rm -f sentinelpass-firefox.zip
ln -s "sentinelpass-firefox-${VERSION}.zip" sentinelpass-firefox.zip

echo "✓ Ready for AMO submission!"
echo "  Upload: ${DIST_DIR}/sentinelpass-firefox-${VERSION}.zip"
echo ""
echo "Next steps:"
echo "  1. Go to Firefox Add-ons Developer Dashboard"
echo "  2. Upload the package"
echo "  3. Fill in store listing details"
echo "  4. Submit for review"
