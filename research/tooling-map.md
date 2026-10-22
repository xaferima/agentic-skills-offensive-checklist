---
title: "Offensive Tooling Map — OWASP Agentic Skills Top 10 (AST10)"
created: 2026-10-14
status: complete
domain: agentic-skills-offensive-checklist
sources_verified: 2026-10-14
---

# Offensive Tooling Map — Attacker-Centric Validation of Agentic Skills

> **Provenance.** Every tool below was verified by fetching its repository or product page on 2026-10-14. Capability statements are quoted from the verified source; nothing is inferred. Where a capability could not be verified, it is marked **unverified**.
>
> **Scope.** This is an *offensive* map: each entry is an attack-side test that produces an evidence artifact usable in a report, mapped to the AST section it falsifies. It is the companion to the OWASP [Agentic Skills Top 10 checklist](https://raw.githubusercontent.com/OWASP/www-project-agentic-skills-top-10/main/checklist.md).

---

## 1. Tool Map

| # | TOOL | What OFFENSIVE test(s) it validates | Evidence artifact it produces | AST section(s) it covers | lab-or-remote | link |
|---|------|--------------------------------------|-------------------------------|--------------------------|----------------|------|
| 1 | **NVIDIA SkillSpector** | Static + optional LLM-semantic scan of a skill bundle (SKILL.md, scripts, deps) against **71 patterns in 17 categories**: prompt injection (P1–P9), anti-refusal (AR1–AR3), data exfiltration (E1–E4), privilege escalation (PE1–PE3), supply chain (SC1–SC10: unpinned deps, `curl \| bash`, obfuscated base64/hex, **live OSV.dev CVE lookup**, abandoned deps, typosquatting, shipped `.pyc`, concealed executables, dependency source redirection), excessive agency (EA1–EA5), memory poisoning (MP1–MP3), rogue agent (RA1–RA2), behavioral AST (exec/eval/`__import__`/subprocess/`os.system`/`getattr` chains), taint tracking (TT1–TT5 incl. credential→network sink), YARA (YR1–YR4), MCP least privilege (LP1–LP4), MCP tool poisoning (TP1–TP4). Also **MCP Registry snapshot diffing** (added/removed servers, changed normalized fields, `unmodeled_changes`). | Terminal report + `--format json\|markdown\|sarif` with **0–100 risk score**, severity, recommendation (`SAFE`/`CAUTION`/`DO NOT INSTALL`), per-finding confidence %, line numbers; `skillspector baseline` fingerprint/glob `.skillspector-baseline.yaml`; Docker image (`make docker-build`); `skillspector mcp` for install-gating. | AST01, AST02, AST03, AST04, AST08, AST09, AST10 (+ AST07/AST10 via `--mcp-registry-compare`) | **lab** (local `scan`, zip/URL/git ingest, Docker) and **remote** (`skillspector mcp --transport http` bound to loopback only) | [github.com/NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) |
| 2 | **Snyk — Agent Scan** (`snyk-agent-scan`, formerly Invariant Labs mcp-scan) | Auto-discovers installed agents, agent skills and MCP configs (Claude Code/Desktop, Cursor, Windsurf, Gemini CLI, Amp, Amazon Q…) and scans them for **prompt injection, tool poisoning, tool shadowing, toxic flows, sensitive-data handling, and malware payloads hidden in natural language**. Companion Snyk CLI covers dependency/supply chain (`snyk test`) and Open Source + Code + Secrets in one pass (`snyk agent test --experimental`). Underlying research: **ToxicSkills** (3,984 skills; 36.82% flawed, 13.4% critical, 76+ confirmed malicious payloads) and **280+ Leaky Skills**. | Risk-based scored report with named indicators; `--json` output; per-skill/MCP findings; fleet upload to Snyk Evo (background/MDM mode); signed binary release with SBOM + checksums. | AST01, AST02, AST03, AST08, AST09 (inventory), AST10 (cross-registry: ClawHub + skills.sh) | **remote** (analysis API / Snyk cloud); local component discovery. Uses `SNYK_TOKEN`. | [github.com/snyk/agent-scan](https://github.com/snyk/agent-scan) |
| 3 | **Gitleaks** | Secret/credential detection in a skill directory (`dir`), a skill repo's **full git history** (`git`), or `stdin` — with recursive **decoding of percent/hex/base64 (≥32/≥16 chars)** via `--max-decode-depth` and **nested-archive traversal** via `--max-archive-depth`. Tests whether the skill carries live keys, and whether encoded payloads hide a second-stage credential. | JSON / CSV / JUnit / SARIF report with `Secret`, `RuleID`, `Entropy`, `File`, `Line`, `Commit`, `Fingerprint`; `.gitleaksignore` fingerprints; `--baseline-path` delta report. | AST03 (3.8 credential stores, `.env`, `**/credentials*`), AST08 (8.3) | **lab** (local dir/git scan); Docker image `zricethezav/gitleaks` or `ghcr.io/gitleaks/gitleaks` | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| 4 | **TruffleHog** | Same detection surface as Gitleaks but **verifies** each finding against the live provider API — proving the leaked secret is actually **`verified`** (active/usable), which is what turns an AST03 finding into a demonstrable blast radius. Also scans Docker images, S3/GCS, GitHub orgs, HF datasets (an AI supply-chain vector). | Console finding + `--json` / `--sarif` with `DetectorType`, `DetectorName`, `Verified`, `ExtraData` (account/ARN/user_id); `--fail` exit code 183 for CI gating; `--results=verified,unknown`. | AST03, AST08, AST02 (dependency/image surface) | **remote** by design (verification calls provider APIs); local filesystem/git source | [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| 5 | **Alice Caterpillar** | Pre-install behavioral/dangerous-pattern scoring of a skill file, in three modes: `alice` (cloud API, most thorough), `openai` (own key, full code in-repo), `offline` (built-in pattern matching, **no network calls**). Detects credential theft (SSH/AWS/API tokens), data exfiltration (curl/wget to external servers), persistence (crontab, startup scripts), crypto wallet theft, network attacks, code obfuscation (base64, hex), **overly broad permissions**, and supply-chain attacks (postinstall hooks, remote script execution). Library API: `runPatternScan`, `ALL_RULES`, `scanSingleSkill`, `collectSkill`. | JSON (`--json`) or CSV (`-o csv`) scan output; per-skill **grade A–F and score 0–100**; `--verbose` findings; **grade F exits code 1** for CI gating. | AST01, AST03, AST08 | **lab** (`--mode offline`) and **remote** (`--mode alice`) | [github.com/alice-dot-io/caterpillar](https://github.com/alice-dot-io/caterpillar) |
| 6 | **Pipelock** | Runtime/egress offensive validation of what a skill actually *does* when the agent acts: ordered URL scanner pipeline (length, scheme, CRLF, path traversal, allow/blocklist, literal-IP SSRF floor, DLP, entropy, nested-URL, **DNS SSRF + rebinding**, rate limits, data budgets); **65 DLP patterns** (API keys, tokens, crypto keys, env secrets, financial IDs, BIP-39 seed phrases); **34 prompt-injection/state-poisoning patterns + 6-pass normalization** (zero-width, homoglyphs, leetspeak, optional whitespace, vowel folding, base64, hex); **MCP bidirectional proxy** (input + response scan, tools/list poisoning / mid-session rug-pull, 30 tool-policy rules, 10 tool-call-chain patterns); **WebSocket frame scanning**; **canary tokens** (honeytoken in egress proves env-var exfil); **skill-scan** (source→sink combos, e.g. credential→network-sink, with line evidence); process sandbox (Landlock + netns, seccomp on linux/amd64) and `pipelock contain` (3-UID operator/proxy/agent, no route off-host); `pipelock assess` runs attack simulation into a signed evidence bundle. | **Mediator-signed action receipts** (`pipelock demo --receipts-dir ./out`, `pipelock verify-receipt --key ./out/signer.pub`); hash-chained JSONL **flight recorder**; `pipelock evidence view --out report.html` offline report; `skill-scan` line evidence; signed `assess` bundle (`pipelock assess verify`). | AST01, AST03, AST04, AST06, AST07, AST08 | **lab** (loopback proxy / sandbox / contain). Strict mode blocks all non-allowlisted egress — the DLP-vs-exfil oracle. | [github.com/luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock) |
| 7 | **Semgrep** | Custom static rules for skill scripts and manifests: dangerous sinks (`exec`, `eval`, `subprocess` with `shell=True`, `os.system`), unsafe deserialization (`yaml.load` instead of `yaml.safe_load`, `pickle.loads`), hardcoded credentials, network egress to non-allowlisted domains, wildcard permission manifests. 30+ languages incl. YAML, JSON, Bash, Python, JS/TS. | Findings text/JSON/**SARIF** with rule ID, path, line, metadata; `--config` local rule file (no registry metrics upload with `--metrics=off`); pre-commit hook. | AST01, AST04, AST02 | **lab** (scans locally; code never uploaded by default) | [github.com/semgrep/semgrep](https://github.com/semgrep/semgrep) |
| 8 | **Bandit** | Python-specific AST analysis of skill scripts: subprocess `shell=True`, `eval`/`exec`, `os.system`/exec-family, `__import__`, hardcoded passwords, `pickle`, `yaml.load`, `urllib` URL open — i.e. the executable tail of a SKILL.md's instructions. | JSON / text / HTML / SARIF report with issue ID (Bxxx), severity, **confidence**, line number, code snippet. | AST01, AST04 | **lab** (local; container `ghcr.io/pycqa/bandit/bandit`) | [github.com/PyCQA/bandit](https://github.com/PyCQA/bandit) |
| 9 | **Burp Suite** | The network-facing half of a skill: replay and mutate **MCP/HTTP control-plane endpoints** exposed by the agent host (localhost vs `0.0.0.0`), WebSocket control channels (log-poisoning / CVE-2026-28363-style hijack conditions), and any tool-callback URL the skill instructs the agent to fetch. Repeater + Intruder for unauthenticated `tools/call`, unauthorized device registration, and missing rate limiting. | Saved Burp project + site map / proxy history; Repeater & Intruder results; scan report (HTML/SARIF); WebSocket frame transcripts. | AST06 (6.3 localhost+auth, 6.6 WS rate-limit/auth), AST05 (follow external references) | **lab** and **remote** (own scope only). Community/Pro/DAST editions. | [portswigger.net/burp](https://portswigger.net/burp) |
| 10 | **mitmproxy** | Scriptable, headless capture of **the egress the agent actually takes under a skill** — TLS interception of MCP HTTP + Streamable HTTP/SSE flows and WebSocket frames, so the exfil target proves itself in the flow log rather than in a regex. | `mitmdump` flow dump (`--save-stream-file`), addon-generated JSON, console flow log with full request/response bodies. | AST01, AST05, AST06 | **lab** (local proxy, own agent + own sink) | [github.com/mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) |
| 11 | **Frida** | Extension / host **interposition (IC)**: instrument the agent host or browser extension process to observe **and tamper with** what a skill can reach — hook `open`/`connect`/`execve` to prove over-privilege (AST03), observe writes to identity files `SOUL.md` / `MEMORY.md` / `AGENTS.md` (AST01/3.6), and defeat certificate pinning / TLS interception resistance in an agent extension. `frida-trace`, `frida-discover`, `frida-ps`, `frida-ls-devices` from `frida-tools`. | Frida `send()`/console trace logs, `frida-trace` handler output, memory/module dumps. **Note:** there is no off-the-shelf Frida script for agent-extension IC — hook logic is built per assessment (**unverified as a ready-made tool**). | AST01 (1.6), AST03 (3.3, 3.8), AST06 | **lab only** (own host/extension process) | [github.com/frida/frida](https://github.com/frida/frida) |
| 12 | **jq** | Triage / diff layer over every JSON-emitting tool above: extract and prove which AST section a finding maps to, count severities across scanners, and **diff two scans over time to detect update drift**. | Filtered finding sets; cross-scanner severity counts; JSON/SARIF delta between two snapshots. | AST07, AST08, AST09 | **lab** | [github.com/jqlang/jq](https://github.com/jqlang/jq) |
| 13 | **yq** | Safe manifest parsing (a `yq`/`yq -p yaml` read is *not* `yaml.load`): enumerate declared `permissions.files.read/write/deny_write`, `permissions.network.allow`, `shell`, `tools`, `requires.binaries`, `risk_tier`, `signature`, `content_hash`; surface unexpected/undeclared keys and unsafe YAML tags. Supports `--security-disable-file-ops` and `--security-disable-env-ops` for hostile input. | Extracted permission table; key inventory / unexpected-key diff; format conversion YAML↔JSON for downstream tooling. | AST03, AST04 (4.7 unsafe YAML tags, 4.9 key allowlist), AST10 | **lab** | [github.com/mikefarah/yq](https://github.com/mikefarah/yq) |
| 14 | **docker** | Isolation validation: run the skill's agent **without** `--network host`, as a non-root user, read-only rootfs, with dropped capabilities, and with a pinned image digest — turning AST06's "will it run in a container, not host-mode" into an observable test. Also a reproducible canary image and a way to run scanners (SkillSpector, Bandit, Gitleaks, yq) without touching the host. | `docker inspect` output (network mode, caps, user, rootfs), run log showing denial of egress, image digest as the content-hash pin. | AST02 (2.3 pins), AST06 (6.1) | **lab** | [docs.docker.com](https://docs.docker.com/) |
| 15 | **snyk-labs/toxicskills-goof** | **Test corpus** — known-malicious skills to measure scanner true-positive rate: a fake **Vercel** skill that exfiltrates `uname -a` to pastebin.com (effective across Gemini CLI **and** OpenClaw), a fake **testing-guidelines** skill hiding instructions via **ASCII smuggling**, plus ClawHub `NET_NiNjA` Google skill samples. Repo ships `.agents/skills`, `.gemini/skills`, `.cursor` layouts for cross-platform coverage. | Per-scanner detection matrix (e.g. `uvx mcp-scan@latest --skills .agents/skills`), true-positive rate table, per-platform equivalence note. | AST01, AST04, AST08, AST10 | **lab only** — repo explicitly states skills are malicious and must not be used | [github.com/snyk-labs/toxicskills-goof](https://github.com/snyk-labs/toxicskills-goof) |
| 16 | **websocat** + **`nc` (netcat)** | AST06 **control-plane** probe: is the agent's local WebSocket/TCP control interface reachable, unauthenticated, and not rate-limited (the ClawJacked / 135,000-exposed-instances precondition)? `nc` doubles as the local callback/exfil sink listener that proves a skill sends out data. | Connection refused vs. accepted handshake; WebSocket frame transcript; `nc` listener log containing the received payload; timestamped connection counts (rate-limit evidence). | AST06 (6.3, 6.6), AST01 | **lab** and **own-scope remote**. websocat is MIT; `nc` ships with macOS/Linux. | [github.com/vi/websocat](https://github.com/vi/websocat) |
| 17 | **base64** + **xxd** | AST04/AST08 **steganography and encoding**: hidden payloads in `SKILL.md` natural language — ASCII smuggling (zero-width U+200B–U+200D, U+2060), base64- and hex-encoded directives, homoglyphs and RTL overrides. `base64 -d`/`-D` reveals the payload; `xxd` shows the invisible codepoints that pattern-matching scanners miss. | Decoded payload strings; hexdump of invisible/non-ASCII codepoints; the recovered instruction text as a finding exhibit. | AST04 (4.2), AST08 (8.1, 8.2), AST01 | **lab** | `base64` (GNU coreutils / BSD) · `xxd` (vim) |
| 18 | **MegaLinter** (OX Security) | Independent **pattern-layer baseline** for the AS08T05-style A/B test: its `security` flavor runs a battery of pattern linters (Python/Bash AST, YAML/JSON schema, secrets, spellcheck of natural-language docs) over a skill package, recording what pure pattern matching catches before the LLM-semantic pass — a third independent pattern layer alongside SkillSpector `--no-llm` and Caterpillar offline. Ships **native coding-agent integrations** (Claude Code, Cursor, Codex, OpenCode, Copilot CLI…), so the same baseline can run inside the agent's own PR loop. | Per-linter console/SARIF reports, non-zero exit on findings (CI gating); per-flavor lint matrix across the package's scripts and manifests. | AST08 (8.1–8.2 baseline), AST04 (manifest lint) | **lab** (local runner) and **CI** | [megalinter.io](https://megalinter.io/) · [github.com/oxsecurity/megalinter](https://github.com/oxsecurity/megalinter) |

**Coverage note.** No single tool covers all ten AST risks; the checklist itself states this and recommends a multi-tool pipeline (static + credential detection + behavioral/dynamic) under AST08 §8.6 — and warns that scanner results are **advisory only**, never the sole gate, especially not when the scanner is itself a skill.

---

## 2. Pipeline — Which Tool For Which Phase

Recommended multi-tool sequence. Each phase feeds evidence into the next; a failure at any phase blocks promotion.

```
① SOURCING ───▶ ② STATIC ──▶ ③ METADATA ──▶ ④ DYNAMIC CANARY ──▶ ⑤ CONTROL-PLANE ──▶ ⑥ EXFIL CAPTURE
   (1)          (1)(7)(8)     (13)(12)(1)       (6)(10)(15)           (16)(9)(11)          (6)(10)(4)(3)
```

| Phase | Question it answers | Tools | Gate to pass | Notes |
|-------|---------------------|-------|--------------|-------|
| **① Skill sourcing** | Is this source, publisher and version trustworthy? | toxicskills-goof (15) to calibrate the pipeline; `docker` (14) to build the canary image with a pinned digest | Publisher identity resolved out-of-band; content hash recorded | No automated provenance tool exists in the skill ecosystem — this phase is largely manual (see Gaps). |
| **② Static** | Does the code do what the description says? | SkillSpector (1), Semgrep (7), Bandit (8) | Zero critical/high static findings, or each triaged and accepted | SkillSpector first (broadest pattern coverage + OSV.dev CVE lookup), then Semgrep/Bandit for language-specific sinks the skill's own scripts hide. |
| **③ Metadata** | Is the manifest honest and safely parsed? | `yq` (13) to extract the permission block; `jq` (12) to diff manifests; SkillSpector (1) for LP1–LP4/TP1–TP4; `base64`/`xxd` (17) to reveal smuggled text | `risk_tier` consistent with `shell`/`network.allow`/`deny_write`; no unexpected keys; no invisible codepoints | Parse with `yq`, never `yaml.load`. Re-run `yq` after any update to catch silent property loss. |
| **④ Dynamic canary** | Does observed behaviour match declared behaviour? | Caterpillar (5) offline mode, Pipelock `sandbox`/`skill-scan` (6), mitmproxy (10) | Observed syscalls/egress ⊆ declared permissions | The `docker`-hosted canary is where a fake Vercel-style skill fires; compare against toxicskills-goof ground truth. |
| **⑤ Control-plane** | Is the agent's own control interface exposed? | `websocat`/`nc` (16), Burp (9), Frida (11) | Control endpoints require auth and are rate-limited; identity-file writes blocked | Covers the ClawJacked precondition and the log-poisoning-via-WebSocket class. |
| **⑥ Exfil capture** | If the skill wanted to steal, could it — and did the control stop it? | Pipelock (6) strict mode + canary tokens + `verify-receipt`, mitmproxy (10) for the flow log, TruffleHog (4) to prove any leaked secret is live, Gitleaks (3) for the packaged-secret baseline | Signed receipts verify; canary honeytoken never observed in egress | Pipelock's capability separation (agent has secrets, no network; proxy has network, no secrets) is the oracle that makes this phase conclusive. |
| **⑦ (post-install) drift watch** | Did the skill or its upstream change under us? | `jq` (12) to diff two SARIF/JSON scans; SkillSpector `--mcp-registry-compare` (1); Gitleaks `--baseline-path` (3) | No new findings across scans; hash of installed skill unchanged | Directly tests AST07; hot-reload must be disabled in non-dev environments (7.5). |

**Minimum viable chain** for a time-boxed review: **toxicskills-goof → SkillSpector (static) → `yq` manifest → Pipelock strict-mode canary with a honeytoken → `verify-receipt`.** That is five commands and it covers AST01, AST03, AST04, AST06 and AST08 with signed evidence.

---

## 3. Gaps — AST Risks With No Adequate Automated Offensive Tool

| AST | Risk | Gap | Manual step that fills it |
|-----|------|-----|---------------------------|
| **AST01 §1.3 / AST02 §2.1** | Cryptographic signature verification | No agent-skill registry publishes a verifiable ed25519 signature or a `content_hash` an operator can check independently — SkillSpector and Caterpillar both detect *behaviour*, neither validates a publisher signature. | Resolve `did:web` / GitHub verified-org identity out-of-band, compute the skill package hash yourself, and record it in the inventory. |
| **AST02 §2.7** | Pre-mutation installer receipt | No installer in the ecosystem emits a reviewable plan with `writes_started=false` before mutating agent settings, hooks, MCP config, commands, or instruction files. | Snapshot `~/.claude`, `.claude/settings.json`, hooks and MCP configs before install (checksum tree), diff after, then approve. |
| **AST05** (all) | Untrusted external instructions | This is the largest gap: **no tool enumerates and follows the transitive reference graph of external URLs a skill documents, nor pins and re-verifies referenced content hashes at load.** Air Security found 17,822 of 142,836 live skills (12.4%, 6.7M installs) resting on at least one untrusted external instruction source, and a single PoC skill with an attacker-controlled documentation URL reached 26,000+ agents with every scanner clearing it. | Build the source inventory by hand (every URL in `SKILL.md` and bundled files), pin each to a content hash at review time, inline what can be inlined, and re-verify on load. Add a filesystem/egress tripwire so a load-time fetch that is not on the allowlist fails the review. |
| **AST06 §6.4** | seccomp / AppArmor profiles | Pipelock can *attach* Landlock/seccomp to a process it launches, and Docker can drop capabilities, but no tool audits whether the **agent host runtime itself** runs under a seccomp/AppArmor profile. | `docker inspect` for caps + network mode, `aa-status` / `/proc/<pid>/status` `Seccomp:` field, and a syscall-deny diff between a host-mode and container-mode run. |
| **AST07 §7.5** | Hot-reload / SkillsWatcher drift | No tool watches a live agent host for module/skill reload and reports the diff; a compromised upstream becomes active instantly. | Disable hot-reload in non-dev environments (documented config change, not a test), monitor skill paths with inode/mtime change detection, and use Frida to hook the loader if you need runtime proof of a reload. |
| **AST09** (all) | Governance | Inherently untestable by offensive tooling — inventory entries, L0–L3 risk tiers, approval records, audit log completeness, review cadence and revocation/deprovisioning are process artifacts, not code. | Reconcile the live filesystem against the central inventory; verify each entry carries hash + install date + installer identity + last scan status; sample audit logs for the four required fields; confirm revocation is wired to offboarding. |
| **AST10** | Cross-platform reuse | Only toxicskills-goof exercises two platforms (Gemini CLI and OpenClaw) with one payload; there is no generic per-platform metamorphic-equivalence tester that proves permissions, `risk_tier` and signature survive a port. | Port the manifest per platform by hand, then run the project's metadata-loss comparison plus a `yq`-based key/permission diff on each variant, and re-run the static scan per platform rather than assuming equivalence. |
| **AST08 §8.1–8.2** | Natural-language-only malice | 13.4% of critical-severity skills are missed by pattern matching; Trail of Bits (Jun 2026) showed every public skill scanner tested — including ClawHub's VirusTotal + LLM guard model and Cisco's `skill-scanner` — bypassed **in under an hour** via payload padding that forces truncation, logic hidden in binary/archive formats, and prompt-injecting the scanner's own LLM judge. SkillSpector's LLM mode and Caterpillar's `alice` mode raise the bar but are not immune. | Run **two independent LLM-semantic reviews with different providers/models** (SkillSpector `--llm` + Caterpillar `--mode openai`), require agreement before approval, and always pair with a dynamic canary. Treat any single scanner's green result as advisory. |
| **§11 (Frida)** | Agent-extension IC | No ready-made instrumentation scripts exist for agent extension/host interposition; the hook logic (which module, which offset, which identity-file write) is bespoke per assessment. | Write the hook against the specific extension build using `frida-discover` + `frida-trace`, and validate the hook on a control run before trusting negative results. |

---

## 4. One Command Per Tool (lab-ready)

```bash
# 1. NVIDIA SkillSpector — static + LLM semantic scan, SARIF out
uv tool install git+https://github.com/NVIDIA/skillspector.git && skillspector scan ./my-skill/ --format sarif --output report.sarif

# 2. Snyk Agent Scan — discover + scan installed skills on the machine
export SNYK_TOKEN=your-api-token-here && uvx snyk-agent-scan@latest --skills ~/path/to/my/SKILL.md

# 3. Gitleaks — scan a skill dir, decode base64/hex/percent, recurse into archives
gitleaks dir ./my-skill/ --max-decode-depth 3 --max-archive-depth 2 --report-format sarif --report-path gitleaks.sarif

# 4. TruffleHog — verify only live secrets in a skill package
trufflehog filesystem ./my-skill/ --results=verified --json

# 5. Caterpillar — offline (no network) pre-install scan, grade A–F, fail CI on F
npm install -g @alice-io/caterpillar && caterpillar ask ./my-skill/ --mode offline --json

# 6. Pipelock — strict-mode firewall + honeytoken canary + self-verifying receipts
pipelock init --output ./pipelock.yaml && pipelock demo --receipts-dir ./out \
  && pipelock verify-receipt "$(ls ./out/*.json | head -1)" --key ./out/signer.pub

# 7. Semgrep — custom rule over skill scripts (dangerous sinks)
semgrep --config ./skill-rules.yaml --metrics=off --sarif --output semgrep.sarif ./my-skill/

# 8. Bandit — Python AST scan of skill scripts
bandit -r ./my-skill/scripts/ -f json -o bandit.json -ll -ii

# 9. Burp Suite — intercept agent control-plane traffic through the proxy
java -jar -Xmx2g burpsuite_community.jar --project-file=ast.lab.burp

# 10. mitmproxy — scriptable TLS capture of the agent's MCP/HTTPS egress
mitmdump -w ast-exfil.flow --set flow_detail=3 --mode regular --listen-port 8080

# 11. Frida — hook open()/connect()/execve() in the agent host process (lab only)
frida-trace -f /path/to/agent-binary -i 'open*' -i 'connect*' -i 'execve*' -o /tmp/ast-trace

# 12. jq — pull CRITICAL/HIGH findings out of a SkillSpector JSON report
jq '[.findings[] | select(.severity=="CRITICAL" or .severity=="HIGH") | {id,file,line,severity}]' report.json

# 13. yq — read the SKILL.md permission manifest safely (never yaml.load)
yq --front-matter=process '.permissions' my-skill/SKILL.md

# 14. Docker — run the skill's agent with no network, read-only, non-root
docker run --rm --read-only --network none --user 1000:1000 --cap-drop all ast-canary:sha256-<digest>

# 15. toxicskills-goof — measure scanner TP rate on known-malicious skills
uvx mcp-scan@latest --skills toxicskills-goof/.agents/skills/google/SKILL.md

# 16. websocat / nc — probe the agent's local WebSocket control plane; catch the callback
websocat -t - ws://127.0.0.1:9222/devtools/page/<id>; nc -lvp 4444

# 17. base64 / xxd — reveal smuggled and encoded payloads in SKILL.md
grep -oP '[\x{200B}-\x{200D}\x{2060}]' my-skill/SKILL.md | wc -l; xxd my-skill/SKILL.md | grep -A1 -B1 'e2 80'
base64 -d <<< "$(grep -oP '[A-Za-z0-9+/]{40,}={0,2}' my-skill/scripts/stage1.sh | head -1)"

# 18. MegaLinter — independent pattern-layer baseline over the skill package (security flavor)
npx mega-linter-runner --flavor security -e "'ENABLE=BASH,PYTHON,YAML,JSON'"
```

> **Ethics boundary.** Everything above is scoped to assets you own or are authorised to test: a lab container, a canary image, your own agent host, and loopback control endpoints. Burp, mitmproxy, Frida, `nc` and `websocat` are dual-use; running them against a third-party agent registry, control plane or host is out of scope for this document.
