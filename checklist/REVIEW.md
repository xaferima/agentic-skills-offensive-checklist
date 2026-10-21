# Domain Review — Agentic Skills Offensive Checklist

Verifier: domain reviewer (mechanical check against on-disk YAML + utility-report.md).
Source of truth: `research/ast*-items.yaml` (11 files) and `research/utility-report.md`.
Artifact under review: `checklist/agentic-skills-offensive-checklist.md`.

## 1. counts — PASS

Per-section body counts match utility-report INCLUDE counts; 12 checklist sections = 11 YAML sections because `ast11-platform-items` (INCLUDE 8) is split into checklist §11 (host/IDE, 5) + §12 (MCP, 3) = 8.

| section | body items | utility INCLUDE | match |
|---|---|---|---|
| 1 (AST01) | 1.1–1.8 = 8 | ast01 8 | PASS |
| 2 (AST02) | 2.1–2.7 = 7 | ast02 7 | PASS |
| 3 (AST03) | 3.1–3.6 = 6 | ast03 6 | PASS |
| 4 (AST04) | 4.1–4.6 = 6 | ast04 6 | PASS |
| 5 (AST05) | 5.1–5.5 = 5 | ast05 5 | PASS |
| 6 (AST06) | 6.1–6.5 = 5 | ast06 5 | PASS |
| 7 (AST07) | 7.1–7.5 = 5 | ast07 5 | PASS |
| 8 (AST08) | 8.1–8.6 = 6 | ast08 6 | PASS |
| 9 (AST09) | 9.1–9.4 = 4 | ast09 4 | PASS |
| 10 (AST10) | 10.1–10.5 = 5 | ast10 5 | PASS |
| 11+12 (AST11) | 11.1–11.5 + 12.1–12.3 = 8 | ast11-platform 8 | PASS |
| **TOTAL** | **65** | **65** | **PASS** |

Evidence: body numbering is contiguous; grand total 65 = utility-report "INCLUDE 65".

## 2. mapping — PASS

Every numbered item's trailing `Source item: <ID>` resolves to an existing YAML item whose title/impact/severity match. All 65 verified; representative sample (≥1 per section):

- 1.1 → `AS01T01` "Exfiltrate SSH keys with three-line prose payload" / exfil-creds / critical ✓
- 2.3 → `AS02T03` "Redirect API traffic to steal key" / exfil-creds / critical ✓
- 3.4 → `AS03T04` "Chain lethal trifecta via untrusted skill fetch" / takeover / critical ✓
- 4.5 → `AS04T05` "Inject undeclared manifest keys past schema" / RCE / high ✓
- 5.2 → `AS05T02` "Rug-pull fetched document after install" / persistencia / critical ✓
- 6.3 → `AS06T03` "Escape host-mode skill execution to host filesystem" / RCE / high ✓
- 7.3 → `AS07T03` "Serve unsigned malicious auto-update" / RCE / critical ✓
- 8.4 → `AS08T04` "Prompt-inject scanner's LLM judge" / RCE / high ✓
- 9.3 → `AS09T04` "Persist through unmanaged SOUL and MEMORY artifacts" / persistencia / High ✓ (9.1–9.2 map to T01/T02; 9.4→T05)
- 10.4 → `AS10T04` "Land skill on weakest-enforcement platform" / takeover / critical ✓
- 11.5 → `AS11T06` "Exfiltrate secrets via agent-rendered markdown image" / exfil-creds / high ✓
- 12.1 → `AS11T05` "Spawn STDIO reverse shell from untrusted repo MCP config" / RCE / critical ✓

Note (not an issue): AST11 items are cross-section reordered (11.5=AS11T06, 12.1=AS11T05); IDs remain unique and each maps to the correct title.

## 3. no_ref_in_body — PASS

- Body Source-item IDs are exclusively `AS##T##` INCLUDE ids; no `AS01R0x`, `AS02T08/09`, `AS04T07/08`, `AS06T06`, `AS07T06/07`, `AS09T03/06` (REFERENCE) and no `AS01X01` (DISCARD) appear numbered.
- Appendix A lists exactly the 11 REFERENCE ids (AS01R01, AS01R02, AS02T08, AS02T09, AS04T07, AS04T08, AS06T06, AS07T06, AS07T07, AS09T03, AS09T06) = utility-report REFERENCE count 11.
- Appendix B lists exactly 1 row (`AS01X01`) = utility-report DISCARD count 1.

## 4. completeness — PASS

All 65 numbered items carry Objective, Procedure, Tools, Evidence, Collateral, Refs, Source item. Procedure step counts all fall within 3–6 (observed 5–6 across every item; no item has 0–2 or ≥7). No missing field found on any item.

## 5. refs — PASS

Every checklist ref traces to a URL/CVE/source present in that item's YAML `refs` (or its module `source_urls`). All 65 items checked, including:

- §1–§2 short/prose refs reproduce the YAML `refs` entries verbatim (e.g., 1.1 = the 4 AS01T01 refs).
- §2 URL refs map to YAML: `research.checkpoint.com/2026/rce-and-api-token-exfiltration...`, `github.com/advisories/GHSA-ph6w-f82w-28w6`, `GHSA-4fgq-fpq9-mr3g`/CVE-2025-59536, `CVE-2026-21852`, `m10x.de/.../pwning-ai-agents-part-2`, `air.security/blog-posts/skilljacking`, `trailofbits` blog all present in the respective YAML.
- §11/§12 host refs (`mistral-vibe` blob pin d33db9f, `github.com/m10x/malim`, m10x part-3/part-4) all appear in the YAML `refs`.
- No orphan ref introduced by the checklist.

## 6. structure — PASS

Sections `## 1.` … `## 12.` present and consecutively numbered; `## Appendix A — Linked, not duplicated (REFERENCE)` and `## Appendix B — Discarded (traceability)` both present; every section has ≥1 numbered item (no empty/broken section).

## 7. phase3 (ES mirror + xlsx + CI) — PASS

- **ES parity:** `checklist/agentic-skills-offensive-checklist-es.md` has 65 `- [ ] **` items and 12 `## N.` sections, identical numbering to the EN checklist; ES appendices A/B present.
- **XLSX:** `checklist/agentic-skills-offensive-checklist.xlsx` has 2 sheets; `Checklist` = 1 header + 65 data rows (Nº/Sección/Source ID/Título/Impacto/Severidad/Target/Estado/Notas); status dropdown (`list`) on `H2:H66`; `Dashboard` carries COUNTIF/COUNTIFS for 5 statuses + 12 sections.
- **Single source of numbering:** `checklist/items.json` (65 records) is emitted by `build-checklist.rb` and consumed by `build-xlsx.py` — no duplicated numbering logic.
- **CI gate:** `bash scripts/ci.sh` → init exit 0 → regenerate → no drift in `utility-report.md`/checklist → `validate.sh` exit 0 (markers + EN/ES parity 65/65).

---

```yaml
verdict: PASS
checked: [counts, mapping, no_ref_in_body, completeness, refs, structure, phase3]
issues: []
```
