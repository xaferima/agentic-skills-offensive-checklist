#!/usr/bin/env bash
# Local verify (HARNESS §11.3/§7): expected markers exist + YAML parses.
# exit 0 = all markers present & valid.
set -u
BASE="$(cd "$(dirname "$0")/.." && pwd)"
RES="$BASE/research"
expected=(
  ast01-items.yaml ast02-items.yaml ast03-items.yaml ast04-items.yaml ast05-items.yaml
  ast06-items.yaml ast07-items.yaml ast08-items.yaml ast09-items.yaml ast10-items.yaml
  ast11-platform-items.yaml dedup-matrix.md tooling-map.md utility-report.md
)
fail=0
for f in "${expected[@]}"; do
  if [[ -f "$RES/$f" ]]; then echo "ok       $f"; else echo "MISSING  $f"; fail=1; fi
done
for y in "$RES"/ast*-items.yaml; do
  [[ -e "$y" ]] || continue
  if command -v ruby >/dev/null 2>&1; then
    ruby -ryaml -e 'YAML.load_file(ARGV[0]); print "yaml ok  #{ARGV[0]}\n"' "$y" \
      || { echo "BAD YAML $y"; fail=1; }
  elif command -v python3 >/dev/null 2>&1 && python3 -c "import yaml" >/dev/null 2>&1; then
    python3 -c "import sys,yaml; yaml.safe_load(open(sys.argv[1])); print('yaml ok  '+sys.argv[1])" "$y" || { echo "BAD YAML $y"; fail=1; }
  else
    echo "skip-parse $y (no yaml parser: ruby absent / python3 without PyYAML)"
  fi
done

# Phase 2 markers (checklist + docs)
for f in README.md README-es.md checklist/agentic-skills-offensive-checklist.md checklist/REVIEW.md; do
  if [[ -f "$BASE/$f" ]]; then echo "ok       $f"; else echo "MISSING  $f"; fail=1; fi
done
if [[ -f "$BASE/checklist/REVIEW.md" ]] && grep -q '^verdict: PASS' "$BASE/checklist/REVIEW.md"; then
  echo "ok       REVIEW verdict=PASS"
else
  echo "MISSING  checklist/REVIEW.md verdict=PASS"; fail=1
fi

# Phase 3 markers (ES mirror + tracking xlsx + local CI)
for f in checklist/agentic-skills-offensive-checklist-es.md checklist/agentic-skills-offensive-checklist.xlsx \
         checklist/items.json scripts/assemble-es.rb scripts/build-xlsx.py scripts/check-xlsx.py scripts/ci.sh \
         citation.cff; do
  if [[ -f "$BASE/$f" ]]; then echo "ok       $f"; else echo "MISSING  $f"; fail=1; fi
done
if [[ -x "$BASE/scripts/ci.sh" ]]; then echo "ok       ci.sh executable"; else echo "MISSING  ci.sh +x"; fail=1; fi

# EN/ES parity: same item count and same section count
if [[ -f "$BASE/checklist/agentic-skills-offensive-checklist.md" && -f "$BASE/checklist/agentic-skills-offensive-checklist-es.md" ]]; then
  en_n=$(grep -c '^- \[ \] \*\*' "$BASE/checklist/agentic-skills-offensive-checklist.md")
  es_n=$(grep -c '^- \[ \] \*\*' "$BASE/checklist/agentic-skills-offensive-checklist-es.md")
  if [[ "$en_n" -eq "$es_n" && "$en_n" -eq 65 ]]; then
    echo "ok       EN/ES parity items=$en_n"
  else
    echo "MISMATCH EN=$en_n ES=$es_n (expected 65/65)"; fail=1
  fi
fi
echo "---- validate exit=$fail"
exit $fail
