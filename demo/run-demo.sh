#!/usr/bin/env bash
# End-to-end BuildBreaker demo against the local Docker / BuildKit builder.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/buildbreaker ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -e ".[test]"
fi
BB=.venv/bin/buildbreaker

echo "=== BuildBreaker version ==="
$BB --version

echo "=== Probe catalog ==="
$BB list

EXAMPLES="$ROOT/examples"
mkdir -p "$EXAMPLES/default" "$EXAMPLES/hardened" "$EXAMPLES/logs"

echo "=== Profile: full (default networking) ==="
$BB run --profile full --out /tmp/bb-demo-default \
  --active --i-understand --yes --cleanup \
  --emit-dir "$EXAMPLES/default" \
  --format text -o "$EXAMPLES/default-run.txt" \
  --no-color || true
rm -rf "$EXAMPLES/logs/default"
cp -r /tmp/bb-demo-default/_logs "$EXAMPLES/logs/default"

echo "=== Profile: hardened (--network=none on every probe) ==="
$BB run --profile hardened --out /tmp/bb-demo-hardened \
  --active --i-understand --yes --cleanup \
  --emit-dir "$EXAMPLES/hardened" \
  --format text -o "$EXAMPLES/hardened-run.txt" \
  --no-color || true
rm -rf "$EXAMPLES/logs/hardened"
cp -r /tmp/bb-demo-hardened/_logs "$EXAMPLES/logs/hardened"

echo "=== Unit tests ==="
.venv/bin/pytest -q

echo "=== Demo complete ==="
ls -la "$EXAMPLES"
