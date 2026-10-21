# Agentic Skills — Offensive Pentesting Checklist

[![validate-checklist](https://github.com/xaferima/agentic-skills-offensive-checklist/actions/workflows/ci.yml/badge.svg)](https://github.com/xaferima/agentic-skills-offensive-checklist/actions/workflows/ci.yml)
[![license: CC BY-SA 4.0](https://img.shields.io/badge/license-CC%20BY--SA%204.0-lightgrey.svg)](LICENSE)

> Attacker-centric test checklist for AI coding agents and their **skills** — covering
> OpenClaw (`SKILL.md` / `SOUL.md` / `MEMORY.md`), Claude Code (`skill.json`, `.claude/settings.json`, hooks),
> Cursor / Codex (`manifest.json`) and VS Code (`package.json`, `extension.ts`), plus MCP servers and hosts.
> Offensive counterpart to the [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) (AST10).

**65 attack tests · 12 sections · lab-only.**

---

## Why this exists

Agentic **skills** are the behaviour layer that gives an agent real-world effect: they orchestrate file access,
network egress, shell, memory and cross-session state. OWASP's AST10 documents the risks and their **mitigations**.
This project is the **offensive mirror**: for every defensive check it asks —

> *What does the attacker **do**, with **what tool**, and **what evidence** confirms the finding?*

The dangerous baseline is Simon Willison's **lethal trifecta**: private data access + untrusted content + external
egress — which most production agent deployments satisfy simultaneously.

## Scope & ethics (non-negotiable)

- Every test runs **only** in researcher-owned **Docker / local** labs.
- PoCs use [`snyk-labs/toxicskills-goof`](https://github.com/snyk-labs/toxicskills-goof) or the researcher's **own lab skills** —
  **never** real registry skills to attack third-party systems or users.
- Each item declares its **collateral damage risk** (e.g., memory wipe, host RCE).
- Discovery/control-plane tests target **your own lab instance only**.

## Methodology

1. **Primary sources.** OWASP AST10 `ast01`–`ast10`, `checklist.md`, `universal-skill-format.md`,
   `threat-intelligence.md`, `case-studies.md` — plus public research: the m10x *"Pwning AI Agents"* series,
   Snyk ToxicSkills, Check Point (`CVE-2025-59536`), Oasis ClawJacked (`CVE-2026-28363`),
   Air Security *"The Story of Skills"*, Trail of Bits scanner-bypass, and `arXiv:2602.06547`.
2. **Inversion rule.** Each defensive check is rewritten as its attack mirror (attacker verb + observable success).
   Items that merely restate a mitigation are rejected.
3. **Utility gate.** Each candidate is scored A–E and admitted only if
   `B ≥ 4 AND avg(A,D,E) ≥ 3.5 AND C ≥ 3`:

   | | criterion |
   |---|---|
   | A | agent-specificity (unique to autonomous agents vs generic) |
   | B | testability (controlled lab + concrete tool + objective result) |
   | C | public evidence (real CVE / research / incident) |
   | D | non-duplication |
   | E | offensive impact (RCE / creds / persistence / takeover) |

   `REFERENCE` if `D ≤ 2` (covered elsewhere → link only); `DISCARD` otherwise.
4. **Deduplication.** Overlap with OWASP API Top 10 / LLM Top 10 / Agentic-AI Top 10 and existing
   checklists is mapped in [`research/dedup-matrix.md`](research/dedup-matrix.md) — overlapping tests are
   marked `REFERENCE` and linked, never duplicated.

## Contents

| # | Section | Source | Items |
|---|---|---|---|
| 1 | Malicious Skill Delivery & Impersonation | AST01 | 8 |
| 2 | Skill Supply-Chain & Dependency Hijack | AST02 | 7 |
| 3 | Over-Privilege & Credential Exfiltration | AST03 | 6 |
| 4 | Metadata & Deserialization Injection | AST04 | 6 |
| 5 | Untrusted External Instruction Sources | AST05 | 5 |
| 6 | Isolation, Sandbox & Control-Plane Exposure | AST06 | 5 |
| 7 | Update Drift, Hot-Reload & Patch-Lag | AST07 | 5 |
| 8 | Scanner Evasion & Detection Bypass | AST08 | 6 |
| 9 | Governance, Agent Identity (NHI) & Shadow Skills | AST09 | 4 |
| 10 | Cross-Platform Porting & Metadata Loss | AST10 | 5 |
| 11 | Agent Host Exploitation (Config-as-Code RCE) | AST11 host/IDE | 5 |
| 12 | MCP Server & Tool Trust Boundary | AST11 MCP | 3 |
| | **Total** | | **65** |

## How to use

1. Stand up an isolated lab (Docker containers, localhost listeners, reverse-shell sinkholes).
2. Open [`checklist/agentic-skills-offensive-checklist.md`](checklist/agentic-skills-offensive-checklist.md) and work the sections.
3. A finding is **confirmed only** when the stated **evidence** artifact is observed (log line, connection, file content, successful prompt).
4. Mark `[x]` on confirmation; annotate outcomes inline.
5. `REFERENCE` items are cross-links to other checklists (Appendix A of the checklist).
6. Track progress in [`checklist/agentic-skills-offensive-checklist.xlsx`](checklist/agentic-skills-offensive-checklist.xlsx)
   (one row per item, status dropdown, live dashboard). Spanish mirror:
   [`checklist/agentic-skills-offensive-checklist-es.md`](checklist/agentic-skills-offensive-checklist-es.md).

## Repository layout

```
README.md                                   # this file (EN)
README-es.md                                # Spanish mirror
checklist/
  agentic-skills-offensive-checklist.md     # the 65-item checklist (generated, EN — source of truth)
  agentic-skills-offensive-checklist-es.md  # Spanish mirror (generated)
  agentic-skills-offensive-checklist.xlsx   # tracking sheet: status dropdown + dashboard
  items.json                                # machine-readable item export (feeds the .xlsx)
  REVIEW.md                                 # reviewer verdict (domain harness)
research/
  ast01-items.yaml … ast10-items.yaml       # candidate items + scores + verdicts
  ast11-platform-items.yaml                 # platform / MCP-host vectors
  dedup-matrix.md                           # overlap rules vs other checklists
  tooling-map.md                            # tool → test → evidence
  utility-report.md                         # full scores/verdicts table + counts
scripts/
  validate.sh                               # marker + YAML integrity + EN/ES parity check
  consolidate.rb                            # merge YAMLs → utility-report.md
  build-checklist.rb                        # deterministic checklist + items.json assembly
  assemble-es.rb                            # stitch ES translation parts → ES checklist
  build-xlsx.py                             # build the tracking .xlsx from items.json
  check-xlsx.py                             # workbook integrity (65 rows + status dropdown)
  ci.sh                                     # the gate: regenerate → drift → xlsx → validate
.github/workflows/ci.yml                    # GitHub Actions running scripts/ci.sh
LICENSE                                     # CC-BY-SA-4.0
citation.cff                                # machine-readable citation (CFF 1.2)
SECURITY.md                                 # how to report a problem
CONTRIBUTING.md                             # how to add and score an item
```

## Tooling (summary)

| Tool | What it validates |
|---|---|
| [`NVIDIA/SkillSpector`](https://github.com/NVIDIA/SkillSpector) | broadest static+semantic skill scan (AST01–04, 08–10) |
| [Snyk](https://snyk.io/) | agent-scan / ToxicSkills-style behavioural scan |
| Gitleaks · TruffleHog | credential/secret detection in skill files |
| [`alice-dot-io/caterpillar`](https://github.com/alice-dot-io/caterpillar) | dynamic behavioural SAST for AI agents |
| [`luckyPipewrench/pipelock`](https://github.com/luckyPipewrench/pipelock) | runtime network proxy — DLP, injection, tool poisoning |
| Burp Suite · mitmproxy | interception / exfil capture |
| Frida | runtime instrumentation (agent extensions) |
| jq · yq · docker | manifest inspection, lab isolation |

Full matrix and gaps in [`research/tooling-map.md`](research/tooling-map.md).

## Continuous integration

[`scripts/ci.sh`](scripts/ci.sh) is the single gate. It:

1. runs the harness `init.sh` when present (skipped in the public repo),
2. regenerates `research/utility-report.md`, the EN checklist and `items.json`,
3. **fails on drift** if the committed artifacts differ from the source YAMLs,
4. checks the `.xlsx` opens with 65 rows and the status dropdown,
5. validates markers and EN/ES parity (65/65).

GitHub Actions runs the same script on every push to `main` and on pull requests
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Locally:

```bash
pip install openpyxl
bash scripts/ci.sh      # → CI: PASS
```

## Release history & roadmap

- **v1.0.0 — initial release:** **65** attack tests across 12 sections (EN + ES mirrors),
  tracking `.xlsx` (status dropdown + dashboard), and the full research corpus
  (**77** candidates scored: **65** included / **11** referenced / **1** discarded).
  A CI gate regenerates every artifact from the source YAMLs and fails on drift.
- **Planned:** per-engagement scoring rubric on top of the 65 items; platform-specific
  lab quick-starts.

## License

Derivative of the OWASP Agentic Skills Top 10 (CC-BY-SA-4.0); distributed under the same terms.
