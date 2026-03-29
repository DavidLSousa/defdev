#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "========================================="
echo "  DevSecOps Agent Demo"
echo "  Scanning: test-fixtures/vulnerable-app"
echo "========================================="
echo ""

cd "$REPO_ROOT"

# Build if needed
if [ ! -f "packages/cli/dist/bin/security-mvp.js" ]; then
  echo "[INFO] Building packages..."
  npm install && npm run build
fi

echo "[1/2] Running in TEXT format..."
echo ""
node packages/cli/dist/bin/security-mvp.js scan ./test-fixtures/vulnerable-app \
  --no-sca \
  --format text || true

echo ""
echo "[2/2] Saving JSON report to demo/devsecops-report.json..."
node packages/cli/dist/bin/security-mvp.js scan ./test-fixtures/vulnerable-app \
  --no-sca \
  --format json \
  --output demo/devsecops-report.json || true

echo ""
echo "Report saved to: demo/devsecops-report.json"
echo "Demo complete!"
