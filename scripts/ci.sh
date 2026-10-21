#!/usr/bin/env bash
# ci.sh — single quality gate: optional harness init → regenerate → fail on drift
# → xlsx integrity → marker validation. Works both inside the Obsidian vault
# (global harness present) and in the standalone public repo (no harness).
set -u
DOM="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$DOM/../.." && pwd)"
fail=0

echo "== [1/5] harness init (optional) =="
INIT=""
if [ -f "$ROOT/scripts/init.sh" ] && [ -f "$ROOT/_Agents/HARNESS.md" ]; then
  INIT="$ROOT/scripts/init.sh"
fi
if [ -n "$INIT" ]; then
  bash "$INIT" >/dev/null 2>&1 && echo "ok: init exit 0" || { echo "FAIL: $INIT"; exit 1; }
else
  echo "skip: no harness init (standalone repo)"
fi

echo "== [2/5] regenerate (deterministic) =="
tmp="$(mktemp -d)"
cp "$DOM/research/utility-report.md" "$tmp/u.md" 2>/dev/null || true
cp "$DOM/checklist/agentic-skills-offensive-checklist.md" "$tmp/c.md" 2>/dev/null || true
cp "$DOM/checklist/items.json" "$tmp/i.json" 2>/dev/null || true
ruby "$DOM/scripts/consolidate.rb" >/dev/null 2>&1 || { echo "FAIL: consolidate.rb"; exit 1; }
ruby "$DOM/scripts/build-checklist.rb" >/dev/null 2>&1 || { echo "FAIL: build-checklist.rb"; exit 1; }
echo "ok: artifacts regenerated"

echo "== [3/5] drift check =="
for pair in "u.md:research/utility-report.md" \
            "c.md:checklist/agentic-skills-offensive-checklist.md" \
            "i.json:checklist/items.json"; do
  n="${pair%%:*}"; f="${pair#*:}"
  if diff -q "$tmp/$n" "$DOM/$f" >/dev/null 2>&1; then
    echo "ok: $f stable"
  else
    echo "DRIFT: $f differs from source — commit the regenerated file"; fail=1
    echo "----- diff (regenerated vs committed) -----"
    diff -u "$tmp/$n" "$DOM/$f" | head -40
    echo "------------------------------------------"
  fi
done

echo "== [4/5] xlsx integrity =="
if python3 -c "import openpyxl" >/dev/null 2>&1; then
  # verify the committed workbook (do not rebuild: openpyxl metadata is not byte-stable)
  python3 "$DOM/scripts/check-xlsx.py" || fail=1
else
  echo "skip: openpyxl not installed (pip install openpyxl)"
fi

echo "== [5/5] validate markers =="
if bash "$DOM/scripts/validate.sh" >/dev/null 2>&1; then
  echo "ok: markers valid"
else
  echo "FAIL: validate.sh"; fail=1
fi

rm -rf "$tmp"
if [ "$fail" -ne 0 ]; then echo "CI: FAIL"; exit 1; fi
echo "CI: PASS"
