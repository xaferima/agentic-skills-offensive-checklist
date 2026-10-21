# Contributing

Thanks for helping keep this checklist sharp.

## Ground rules

- **Lab-only.** Every test must run in researcher-owned Docker/local environments. Changes that
  target third-party systems or users are rejected.
- **Offensive, not defensive.** Each item states an attacker action and an observable evidence
  artifact. Mitigation-only items are out of scope (they belong to OWASP AST10 itself).
- **Cite evidence.** A new item needs at least one public source (CVE, advisory, research post,
  incident write-up) in its `refs`.

## Adding or editing an item

1. Edit the matching `research/astNN-items.yaml` and keep the full schema:
   `id, title, objective, target_env, procedure, tools, evidence, impact, severity_hint, refs,
   verdict, utility_scores{A,B,C,D,E}, rationale, collateral`.
2. Score it A–E. The gate is:

   ```
   INCLUDE   if B >= 4 AND avg(A,D,E) >= 3.5 AND C >= 3
   REFERENCE if D <= 2
   DISCARD   otherwise
   ```
3. Regenerate and verify (needs `ruby` and `python3` + `openpyxl`):

   ```bash
   ruby scripts/consolidate.rb
   ruby scripts/build-checklist.rb
   python3 scripts/build-xlsx.py
   bash scripts/ci.sh
   ```

4. The **English checklist is the source of truth**. If you change item wording, update
   `checklist/agentic-skills-offensive-checklist-es.md` too (its assembly script needs the
   translation parts and is only used for a full re-translation).

## Definition of done

`bash scripts/ci.sh` must print `CI: PASS`:

- regenerated artifacts match the committed ones (no drift),
- the `.xlsx` opens with 65 rows and the status dropdown,
- markers validate and the EN/ES item counts stay at parity (65/65).
