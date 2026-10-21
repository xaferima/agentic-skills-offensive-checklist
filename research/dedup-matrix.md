# Dedup / Overlap Matrix — Attacker-Centric Agentic Skills Checklist

**Domain:** `agentic-skills-offensive-checklist` · **Phase:** 1-research · **Task:** A13
**Purpose:** decide which candidate tests are **UNIQUELY agentic** → `INCLUDE` (written as new items) vs **already covered elsewhere** → `REFERENCE` (link only, never duplicated).
**Date:** 2026-10-14

---

## 0. Sources Compared (never fabricated — all read)

| Ref ID | Source | What was read |
|---|---|---|
| **AST10-I** | OWASP Agentic Skills Top 10 — `index.md` | Summary table AST01–AST10, Universal Skill Format, incident timeline, MAESTRO mapping |
| **AST10-C** | OWASP Agentic Skills Top 10 — `checklist.md` | Full numbered checks `1.1`–`10.6` (83 rows) + B1–B4 trust-boundary block |
| **LLM10** | OWASP Top 10 for LLM Applications **2025** | LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Supply Chain · LLM04 Data & Model Poisoning · LLM05 Improper Output Handling · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector & Embedding Weaknesses · LLM09 Misinformation · LLM10 Unbounded Consumption |
| **ASI10** | OWASP Top 10 for **Agentic Applications** (Black Hat EU 2025 / 2026 ed.) | ASI01 Agent Goal Hijack · ASI02 Tool Misuse & Exploitation · ASI03 Identity & Privilege Abuse · ASI04 Agentic Supply Chain · ASI05 Unexpected Code Execution · ASI06 Memory & Context Poisoning · ASI07 Insecure Inter-Agent Communication · ASI08 Cascading Failures · ASI09 Human-Agent Trust Exploitation · ASI10 Rogue Agents |
| **API10** | OWASP API Security Top 10 **2023** | API1 BOLA · API2 Broken Authentication · API3 BOPLA · API4 Unrestricted Resource Consumption · API5 BFLA · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8 Security Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs |
| **LOC-API** | `Pentesting/Checklist/API_Pentesting_Checklist.md` | Enumeration / Authentication+JWT / Access / Authorization-OAuth / Input / Processing / Output / Monitoring / Wordlists |
| **LOC-KYC** | `Pentesting/Checklist/MOBILE_KYC_PenTest_Checklist.md` | 23 sections; §5 KYC API, §6 JWT, §7–8 Mobile RE, §9 SDK, §10 Network, §11 File Upload, §12–13 Session/Access, §14 Data Exposure, §15 Injection, §17 Rate Limit, §18 Logging, §20 Vendor Risk, §21 WebView |

**Mental model used as the boundary test (AST10-I):** *MCP = how the model talks to tools; AST10 = what those tools actually do.* A candidate item is `INCLUDE` only when its **attack surface exists because a skill is a packaged, distributable behavior bundle** (SKILL.md / skill.json / manifest.json / package.json + bundled scripts + declared permissions + registry identity). If the test would still make sense against a plain REST API, a plain mobile app, or a plain LLM prompt, it is `REFERENCE`.

---

## 1. Per-Section Overlap Table (AST01–AST10 + PLATFORM)

Legend — **INCLUDE** = uniquely agentic, write new items. **REF** = already covered, link only. **INT** = internal AST-to-AST duplicate (see §3 rules).

### AST01 — Malicious Skills `Critical`

| Aspect | Verdict | Already covered by |
|---|---|---|
| Behavioral canary of a skill in isolation, comparing **observed** vs **declared** behavior | **INCLUDE** | — |
| Static review of the **natural-language instruction layer** (`SKILL.md` prose) for encoded payloads | **INCLUDE** | — (LLM10 is model-side, not skill-file side) |
| ed25519 signature + `content_hash` verification of a skill package | **INCLUDE** | — |
| Registry publisher-identity / typosquat / brand-impersonation of a **skill name** | **INCLUDE** | — |
| Write access to agent identity files `SOUL.md` / `MEMORY.md` / `AGENTS.md` | **INCLUDE** | owner AST01 (persistence); cross-ref AST03 §3.6 |
| Generic code-malware static scan (regex/pattern) of bundled scripts | **REF** | **LOC-KYC §21.6 Tools** ("jadx + grep"), **LOC-API §Processing**; generic SAST = Semgrep/Bandit per **AST10-C** Recommended Tools |
| Malicious dependency hiding inside a skill package | **REF** | **LLM10 LLM03:2025**, **ASI10 ASI04:2026**, **LOC-KYC §20 "SDK Dependency Analysis"** |

### AST02 — Supply Chain Compromise `Critical`

| Aspect | Verdict | Already covered by |
|---|---|---|
| Skill publisher code-signing key ↔ verified identity (`did:web:` / verified org) | **INCLUDE** | — |
| **Repository-controlled config as executable code** — `.claude/settings.json`, hooks, env overrides executing at `clone`/`open` before any trust dialog (CVE-2025-59536) | **INCLUDE** | — (defeats every "review before merge" control) |
| Installer **pre-mutation receipt** before writing agent settings, hooks, MCP config, commands, instruction files | **INCLUDE** | — |
| Skill pinned to immutable `sha256:` content hash (skill package) | **INCLUDE** | owner AST02 §2.2 |
| Mutable version tags / version ranges (`^`, `~`) for nested deps | **REF** | **LLM10 LLM03**, **ASI10 ASI04**, **LOC-KYC §20 "Supply Chain Integrity"** |
| SBOM (CycloneDX/SPDX) for skill dependency tree | **REF** | **LLM10 LLM03**, **LOC-KYC §20 "SDK Dependency Analysis"** |
| Transitive/recursive dependency scan depth | **REF** | **ASI10 ASI04**, **LOC-KYC §9 "SDK Version Review"** |

### AST03 — Over-Privileged Skills `High`

| Aspect | Verdict | Already covered by |
|---|---|---|
| Skill **permission manifest** with explicit scoped `files.read/write/deny_write`, `network.allow`, `shell`, `tools` | **INCLUDE** | — |
| `network: true` boolean over-permission → missing **domain allowlist** | **INCLUDE** | — |
| `**/*` wildcard file scopes / broad globs in a skill manifest | **INCLUDE** | — |
| Declared-vs-actual credential access: `~/.ssh/`, `~/.aws/`, `.env`, `**/credentials*`, `*.wallet`, browser data dirs — the **Lethal Trifecta** (private data + untrusted content + egress) | **INCLUDE** | — |
| **Per-skill scoped credentials** vs shared agent-level API keys | **INCLUDE** | — |
| Unrestricted `shell: true` in a skill manifest | **INCLUDE** | — |
| `risk_tier` stated as `L0`/`L1` while manifest grants shell/network/identity-write | **INCLUDE** | — (metadata/privilege mismatch; also AST04 §4.5) |
| "Least privilege / don't over-grant permissions" as a generic principle | **REF** | **LLM10 LLM06:2025**, **ASI10 ASI03:2026**, **LOC-KYC §9 "SDK Permission Audit"** |

### AST04 — Insecure Metadata `High`

| Aspect | Verdict | Already covered by |
|---|---|---|
| **ASCII smuggling / zero-width Unicode / base64 steganography inside natural-language skill instructions** | **INCLUDE** | — (prose-layer steganography; no other checklist covers it) |
| Unsafe YAML loaders on **skill manifest** files (`yaml.load`, `!!python/object`, `!!python/apply`) | **INCLUDE** | — when the deserialized object grants permissions/tools |
| Missing key allowlist / JSON-Schema validation on skill manifests | **INCLUDE** | — |
| `requirements.txt` / `package.json` / `pyproject.toml` inside a skill package treated as untrusted code | **INCLUDE** | borderline → also **LLM10 LLM03** |
| Description does not match observed functionality (hidden capability) | **INCLUDE** | — |
| Skill name impersonates a known brand without affiliation | **INCLUDE** | — |
| Default-permissive metadata defaults (dangerous capabilities on by default) | **INCLUDE** | — |
| Generic unsafe deserialization / XXE / entity expansion / Billion-Laughs in *any* parser | **REF** | **LOC-API §Processing** ("If you are parsing XML, YAML or any other language with anchors and refs… entity expansion is not enabled to avoid `Billion Laughs/XML bomb`"), **LOC-KYC §15 "XML/SOAP Injection"** |
| Generic JSON prototype-pollution / parser-confusion fuzzing | **REF** | **LOC-KYC §15 "JSON Injection / Prototype Pollution"** |

### AST05 — Untrusted External Instructions `High`

| Aspect | Verdict | Already covered by |
|---|---|---|
| Skill references external docs / URLs / remote files **at runtime** | **INCLUDE** | — |
| External instruction source pinned to a content hash, re-verified on load | **INCLUDE** | — |
| Runtime fetch of attacker-mutable instructions = **"the payload is the documentation URL"** | **INCLUDE** | — (Air Security PoC bypassed every scanner) |
| **Transitive** reference-graph of external instruction sources | **INCLUDE** | — |
| Inlining remote instructions into the signed package vs runtime fetch | **INCLUDE** | — |
| Fleet-wide visibility of which skills fetch from which external sources | **INCLUDE** | — |
| Vetted-domain **egress allowlist** as a pure network control | **REF** | **API10 API7:2023 (SSRF)**, **API10 API8:2023**, **LOC-API §Access** |

**Verdict:** AST05 is the most **agentic-exclusive** section — 5 of 6 checks have no analogue in LLM10, ASI10, API10 or either local checklist. Treat as the checklist's primary novel contribution.

### AST06 — Weak Isolation `High`

| Aspect | Verdict | Already covered by |
|---|---|---|
| **Localhost control-plane hijack of the agent** — WebSocket / admin API on `127.0.0.1` brute-forced by a malicious web page (ClawJacked, CVE-2026-28363) | **INCLUDE** | — (the single clearest keep-INCLUDE boundary) |
| Agent control interfaces reachable without authentication / bound to `0.0.0.0` (135K exposed instances) | **INCLUDE** | — |
| **Per-skill namespacing / process isolation between skills** (no shared FS or memory) | **INCLUDE** | — |
| Workspace-skill override / **hot-reload precedence** in production | **INCLUDE** | owner AST06 §6.7 (see **INT-3**) |
| Agent-action **audit logging** for file access, shell, network, memory writes | **INCLUDE** | owner AST09 §9.4 |
| Host-mode execution as default vs explicit opt-in | **INCLUDE** | — |
| Generic containerization / Docker sandboxing as an infra control | **REF** | general hardening; **ASI10 ASI05** for the sandbox-escape angle |
| seccomp / AppArmor syscall profiles | **REF** | generic OS hardening (not agentic-specific) |
| SSRF from a skill to **cloud metadata** `169.254.169.254` | **REF** | **API10 API7:2023**, **LOC-API §Processing**; BlueRock MarkItDown MCP PoC |
| TLS on generic non-agent channels | **REF** | **LOC-API §Access** ("Use HTTPS on server side with TLS 1.2+…"), **LOC-KYC §10** |

### AST07 — Update Drift `Medium`

| Aspect | Verdict | Already covered by |
|---|---|---|
| **Hot-reload / SkillsWatcher disabled outside dev** (compromised upstream becomes instantly active) | **INCLUDE** | owner AST06 §6.7 — **INT-3**, do not re-list |
| Auto-update gated behind human re-approval in production | **INCLUDE** | — |
| Skill-specific **security advisory / CVE subscription** for installed skills | **INCLUDE** | — |
| Skill pinned to immutable `sha256:` | **INT** | duplicate of **AST02 §2.2** → single owner AST02, cross-ref here |
| Updates re-triggering a security rescan | **REF** | **LLM10 LLM03**, **ASI10 ASI04**, **LOC-KYC §20 "Supply Chain Integrity"** |
| Update signature verification (generic) | **REF** | **LLM10 LLM03**, **ASI10 ASI04** |

**Verdict:** weakest section. Most of its value is captured once under AST02 (pinning) and AST06 (hot-reload). Keep ~3 net-new items.

### AST08 — Poor Scanning `Medium`

| Aspect | Verdict | Already covered by |
|---|---|---|
| **Code layer AND natural-language instruction layer scanned independently** | **INCLUDE** | — (the core AST08 novelty) |
| Behavioral/semantic scanning (intent-aware) rather than regex signatures | **INCLUDE** | — |
| Scan environment the skill **cannot detect or influence** (anti-sandbox-detection) | **INCLUDE** | — |
| Scanner is **advisory only, never a sole gate** — especially scanners that are themselves skills | **INCLUDE** | — (ClawHub "Skill Defender" abused as false-trust signal) |
| Payload **padding → scanner truncation** bypass | **INCLUDE** | — (Trail of Bits, 2026-06) |
| Logic hidden in binary/archive formats to evade skill scanners | **INCLUDE** | — |
| Prompt-injecting the **scanner's own LLM judge** | **INCLUDE** | — |
| Dynamic behavioral testing vs declared scope | **INT** | duplicate of **AST01 §1.5** canary → single owner AST01 |
| Credential detection scanning (Gitleaks / TruffleHog) in skill files | **REF** | **LOC-KYC §21.6 Tools** row "truffleHog / gitleaks — Secret scanning in decompiled source"; generic secret scanning |
| Pre-install risk score threshold (SkillSpector et al.) | **INCLUDE** | agent-skill-aware scanner gate — unique gating semantics |

### AST09 — No Governance `Medium`

| Aspect | Verdict | Already covered by |
|---|---|---|
| Centralized **skill inventory** (name, version, hash, install date, installer identity, last scan status) | **INCLUDE** | principle = **API10 API9:2023**; but *no other local checklist inventories agent skills* → keep |
| **Risk-tier classification L0–L3** per skill | **INCLUDE** | — (unique to the Universal Skill Format) |
| **Agent identities as non-human identities (NHI)** with scoped, rotated credentials | **INCLUDE** | — (IAM-for-agents; nothing local covers it) |
| Skill-invocation logging: skill ID, user context, tools called, files accessed, network connections, outputs | **INCLUDE** | — (agent action audit trail) |
| Revocation / deprovisioning tied to offboarding **and skill-specific IR scenarios** | **INCLUDE** | — |
| Approval workflow for skill installation (approver identity + date) | **INCLUDE** | — (change-approval applied to skills) |
| Periodic reassessment cadence by risk tier | **REF** | generic review cadence |
| Centralized logs / SIEM forwarding / "don't log sensitive data" | **REF** | **LOC-API §Monitoring**, **LOC-KYC §18** ("Audit Trail for KYC Events", "Biometric Data in Logs", "SIEM Integration") |
| Alert channels (Slack/SMS/Email/Kibana/CloudWatch) | **REF** | **LOC-API §Monitoring** ("Use alerts for SMS, Slack, Email, Telegram, Kibana, Cloudwatch…") |

### AST10 — Cross-Platform Reuse `Medium`

| Aspect | Verdict | Already covered by |
|---|---|---|
| **Security-metadata loss on port** (`SKILL.md` YAML ↔ `skill.json` ↔ `manifest.json` ↔ `package.json`) — permission/`risk_tier`/signature silently dropped | **INCLUDE** | — (no other list has a portable-artifact-diff test) |
| Adoption of the **Universal Skill Format** / platform-agnostic manifest with all security fields | **INCLUDE** | — |
| Per-platform gap analysis: sandbox model, permission enforcement, default config per host | **INCLUDE** | — |
| Credential handling consistency across platforms | **INCLUDE** | — |
| **Cross-registry threat-intel sharing** for a skill published on multiple registries | **INCLUDE** | — |
| "Test each target environment independently, don't assume equivalence" | **REF** | generic QA/release principle |

### PLATFORM — Platform-Specific Vectors (task A11, `ast11-platform-items.yaml`)

Not an AST category; consolidates per-host attack surface read from **AST10-I** (Skill Formats by Platform table + incident timeline).

| Aspect | Verdict | Already covered by |
|---|---|---|
| **OpenClaw** local WebSocket control plane hijack from a browser tab (ClawJacked, CVE-2026-28363, CVSS 9.9) | **INCLUDE** | — |
| **Claude Code** repo-config-as-code RCE at project open, before trust dialog (CVE-2025-59536 CVSS 8.7 / CVE-2026-21852) | **INCLUDE** | — |
| **OpenClaw** identity-file poisoning `openclaw.json`, `device.json`, `soul.md`, `memory.md` for session-persistent backdooring (Vidar variants) | **INCLUDE** | — |
| **OpenClaw** log poisoning → agent re-reads its own logs → indirect injection (2026.2.13) | **INCLUDE** | — |
| **OpenClaw** 135K+ internet-exposed instances, insecure defaults, no firewall/auth | **INCLUDE** | — |
| **ClawHub** registry poisoning at scale (ClawHavoc, 1,184 skills, single C2 IP) | **INCLUDE** | — |
| **skills.sh** SkillJacking via deleted GitHub account / expired domain / freed cloud slot re-registration | **INCLUDE** | — |
| **Cursor/Codex** `manifest.json` + handler-script trust model | **INCLUDE** | — |
| **VS Code** `package.json` + `extension.ts` extension surface | **INCLUDE** | generic IDE-extension supply chain = **LLM10 LLM03 / ASI10 ASI04** → keep only the skill-bearing parts |
| **skills.sh / ClawHub install-time scan bypass** (social-media-delivered skill reaching 26K agents) | **INCLUDE** | — |
| Localhost CSRF / DNS-rebinding against a **generic** local service | **REF** | **API10 API8:2023 (Security Misconfiguration)**, **LOC-API §Access** ("For private APIs, allow access only from safelisted IPs/hosts") |
| Mobile-app SDK_RE/Frida/pinning-bypass techniques reused for an agent runtime | **REF** | **LOC-KYC §7–8** |

---

## 2. DEDUP RULES (applied per candidate item)

> Each rule is a decision procedure the consolidator runs mechanically. **Owner** = the section that writes the full item; everything else cross-references it.

**R1 — Identity-file writes.** Write access to `SOUL.md` / `MEMORY.md` / `AGENTS.md` / `soul.md` / `memory.md` / `device.json` / `openclaw.json` → **INCLUDE**, owner **AST01**. AST03 §3.6 and AST06 may cross-reference but must not re-write the test. *(Rationale: persistence + behavior-shaping is one test with two consequences.)*

**R2 — Skill content-hash pinning.** Pinning a skill to `sha256:` → **INT**: owner **AST02 §2.2**; AST07 §7.1 becomes a one-line cross-reference. If an item pins a *nested dependency* rather than the skill itself → **REFERENCE** (LLM03 / ASI04 / LOC-KYC §20).

**R3 — Hot-reload / workspace precedence.** "Hot-reload disabled in production" → **INCLUDE**, owner **AST06 §6.7**; AST07 §7.5 = cross-ref. *(Isolation failure and drift failure are the same symptom.)*

**R4 — Canary / behavioral sandbox test.** A dynamic "observed vs declared behavior" test → **INCLUDE**, owner **AST01 §1.5**. AST08's "dynamic behavioral testing in a sandboxed runtime" (§8.5) = cross-ref. A *generic* "run in a container" hardening statement → **REFERENCE** (infra checklist).

**R5 — SSRF target decides.** `SSRF → 169.254.169.254` / cloud metadata / internal REST API → **REFERENCE** (**API10 API7:2023**; LOC-API §Processing; BlueRock MarkItDown MCP PoC). `SSRF → 127.0.0.1:<agent-port>` control-plane, WebSocket, or admin API → **INCLUDE** under **AST06**. The attacker's *target*, not the technique, is the discriminator.

**R6 — Secret scanning.** Scanning `.env` / `~/.ssh` / `*.wallet` / browser data for **any** credentials → **REFERENCE** (**LOC-KYC §21.6 Tools** "truffleHog / gitleaks"; LOC-KYC §14). **INCLUDE** only the *agentic delta*: a credential store the skill never declared (AST03 §3.8), or credentials pre-staged in a skill's own runtime (`requires`).

**R7 — Prompt injection basics.** "Ignore previous instructions", goal hijack, jailbreak → **REFERENCE** (**LLM10 LLM01:2025**, **ASI10 ASI01:2026**). **INCLUDE** only the skill-specific carriers: zero-width/base64 smuggling in `SKILL.md` prose (AST04 §4.2), runtime-fetched external instructions (AST05), and injection aimed at the scanner's own LLM judge (AST08).

**R8 — Deserialization depends on the payload.** YAML/JSON unsafe-load → **REFERENCE** (`!!python/object` generally; **LOC-API §Processing** XXE/Billion-Laughs; LOC-KYC §15). **INCLUDE** only when the deserialized object is a **skill manifest whose fields grant permissions/tools/files/network** (AST04 §4.7, §4.11).

**R9 — TLS / pinning / weak ciphers.** Generic TLS 1.2+/cipher/HSTS/pinning checks → **REFERENCE** (**LOC-API §Access**; **LOC-KYC §10 "Certificate Pinning Enforcement", "Weak Cipher Suites"**). **INCLUDE** only TLS/auth on the **agent control channel**, including localhost WebSocket (AST06 §6.3, §6.6).

**R10 — SBOM / dependency tree / CVE alerts.** SBOM generation, transitive-depth scan, version-range pinning, advisory subscription for *libraries* → **REFERENCE** (**LLM10 LLM03**, **ASI10 ASI04**, LOC-KYC §9/§20). **INCLUDE** only the skill-package-scoped variant: skill + its `requires` binaries + its **instruction-source** dependency graph.

**R11 — Rate limiting / resource consumption.** Endpoint throttling, DoS limits, quota → **REFERENCE** (**API10 API4:2023**; **LOC-API §Access** "Limit requests (Throttling)"; **LOC-KYC §17**). **INCLUDE** only rate limits on **agent control/auth channels** (AST06 §6.6) and per-skill invocation cost.

**R12 — IDOR / mass assignment / BOLA.** Any object-ID substitution or overposting test → **REFERENCE**, full stop (**API10 API1:2023 & API3:2023**; **LOC-KYC §5 "IDOR on KYC Sessions", §13 "Horizontal Privilege Escalation"**; **LOC-API §Input** "IDOR in body/header is more vulnerable than ID in URL"). Exception: the object is a **skill record / skill grant / agent identity** → then it is a new agentic test.

**R13 — JWT.** Algorithm confusion, `alg:none`, secret brute-force, claim tampering, expiry → **REFERENCE** (**LOC-API §JWT**; **LOC-KYC §6**, all nine items). **INCLUDE** only agent-issued tokens and NHI scoped/rotated credentials (AST09 §9.7).

**R14 — Inventory.** Generic asset/deprecation management → **REFERENCE** (**API10 API9:2023**). **INCLUDE** the *skill* inventory because neither local checklist inventories agent skills (AST09 §9.1) — the instance is new even though the principle is not.

**R15 — Impersonation venue decides.** Skill-store typosquat / fake-brand skill / fake publisher → **INCLUDE** (AST01 §1.1, AST04 §4.6). Domain/homograph/email typosquatting → **REFERENCE** (OSINT recon, **LOC-KYC §19**).

**R16 — Biometrics never re-tested.** Liveness, deepfake, 3D mask, GAN face, video-selfie, Rekognition/S3/WebView-KYC tests → **REFERENCE** (**LOC-KYC §1–§4, §21**, verbatim). Link only if a **skill** is the consumer of a KYC vendor, and then test only the skill→vendor trust boundary, not the biometrics.

**R17 — Callback forgery venue decides.** Vendor **webhook** forgery / callback tampering → **REFERENCE** (**LOC-KYC §13 "Vendor Webhook Spoofing"**, **§20 "Vendor Webhook Authentication"**). **Agent-to-agent / MCP server callback** forgery → **INCLUDE** (adjacent to **ASI10 ASI07**).

**R18 — Log hygiene.** "Don't log tokens/PII/credit cards" → **REFERENCE** (**LOC-API §Monitoring**; **LOC-KYC §18** "JWT Tokens in Logs"). **INCLUDE** the agentic delta: logs must capture *tools called, files accessed, network connections, and outputs of the skill* (AST09 §9.4).

**R19 — File upload / polyglot.** MIME bypass, polyglot, oversized payload, ImageMagick, EXIF injection → **REFERENCE** (**LOC-API §Input** "Test file uploads request"; **LOC-KYC §11** all eight items). **INCLUDE** only if the uploaded artifact is a **skill package / skill archive** whose parser differs from a web upload.

**R20 — Error handling & fingerprinting.** Verbose errors, debug-mode detection, banner/header fingerprinting, status-code semantics → **REFERENCE** (**LOC-API §Output**; **LOC-KYC §16** "Verbose Error Messages", "Debug Mode Detection").

**R21 — Injection in non-instruction contexts.** SQLi / NoSQL / command / XML injection in KYC or API fields → **REFERENCE** (**LOC-API §Input**; **LOC-KYC §15**). **INCLUDE** only injection into an **instruction channel** (skill manifest field, memory file, log file re-read by the agent).

**R22 — Internal dedup precedence.** When two AST sections describe the same test, the **earlier-numbered section owns it** unless that section is REFERENCE-heavy; the later section writes a cross-reference. Ordering: AST01 > AST02 > AST03 > AST04 > AST05 > AST06 > AST07 > AST08 > AST09 > AST10 > PLATFORM.

---

## 3. DO-NOT-DUPLICATE but MUST-LINK

Generic items that belong to other checklists. The README must cross-link to the exact target line.

| Generic item | Target checklist to link | Exact target line |
|---|---|---|
| Credential / secret scanning (Gitleaks, TruffleHog) in code & binaries | **LOC-KYC** | §21.6 Tools — *"truffleHog / gitleaks — Secret scanning in decompiled source"* |
| Sensitive-data exposure / clipboard / screenshot / at-rest encryption | **LOC-KYC** | §14 Sensitive Data Exposure (all items, L235–246) |
| SSRF (cloud metadata, internal APIs) | **API10** | API7:2023 Server Side Request Forgery — `owasp.org/API-Security/editions/2023/en/0xa7...` |
| Egress allowlisting / private-network restriction | **LOC-API** | §Access — *"For private APIs, allow access only from safelisted IPs/hosts"* |
| TLS 1.2+, secure ciphers, HSTS, SSL-strip | **LOC-API** | §Access — *"Use HTTPS on server side with TLS 1.2+ and secure ciphers to avoid MITM"* / *"Use HSTS header…"* |
| Certificate pinning enforcement, weak cipher scan, HTTP downgrade, DNS spoofing, WebSocket auth | **LOC-KYC** | §10 Network Traffic Analysis — *"Certificate Pinning Enforcement"*, *"Weak Cipher Suites"*, *"WebSocket Security"* |
| Prompt injection / jailbreak fundamentals | **LLM10 + ASI10** | LLM01:2025 Prompt Injection; ASI01:2026 Agent Goal Hijack |
| Excessive agency / over-permissioned tool use | **LLM10 + ASI10** | LLM06:2025 Excessive Agency; ASI02:2026 Tool Misuse and Exploitation; ASI03:2026 Identity and Privilege Abuse |
| Agent identity & privilege escalation (RBAC/BFLA/BOLA framing) | **ASI10** | ASI03:2026 Identity and Privilege Abuse |
| Supply chain, malicious plugins, poisoned prompt templates | **LLM10 + ASI10** | LLM03:2025 Supply Chain; ASI04:2026 Agentic Supply Chain Vulnerabilities |
| Third-party SDK dependency analysis, SBOM, checksum/signature verification of vendor binaries | **LOC-KYC** | §20 Third-Party Vendor Risk — *"SDK Dependency Analysis"*, *"Supply Chain Integrity"* |
| Unsafe deserialization, XXE, entity expansion / Billion-Laughs | **LOC-API** | §Processing — *"If you are parsing XML data, make sure entity parsing is not enabled to avoid XXE"* / *"…anchors and refs… Billion Laughs/XML bomb"* |
| Prototype pollution / JSON parser confusion | **LOC-KYC** | §15 — *"JSON Injection / Prototype Pollution"* |
| IDOR / horizontal & vertical privilege escalation | **API10 + LOC-KYC** | API1:2023 BOLA; API3:2023 BOPLA; LOC-KYC §5 *"IDOR on KYC Sessions"*, §13 *"Horizontal/Vertical Privilege Escalation"* |
| Mass assignment / overposting | **API10 + LOC-KYC** | API3:2023 BOPLA; LOC-KYC §5 *"Mass Assignment / Overposting"* |
| JWT testing (alg confusion, brute-force, claim tampering, expiry, scope) | **LOC-API + LOC-KYC** | LOC-API §JWT (all items); LOC-KYC §6 JWT Authentication Testing (all nine items) |
| OAuth `redirect_uri` / `state` / `response_type` / scope | **LOC-API** | §Authorization — OAuth block |
| Rate limiting, throttling, DoS limits, quota | **API10 + LOC-KYC** | API4:2023 Unrestricted Resource Consumption; LOC-API §Access *"Limit requests (Throttling)…"*; LOC-KYC §17 Rate Limiting & Abuse Prevention |
| CSRF on cookie-authenticated APIs | **LOC-API** | §Input — *"Cross-site Request Forgery (CSRF)…"* |
| Generic file upload: MIME bypass, polyglot, oversized, malformed, ImageMagick, path traversal in filename | **LOC-API + LOC-KYC** | LOC-API §Input *"Test file uploads request"*; LOC-KYC §11 File Upload Testing (all items) |
| SQL / NoSQL / command / XML injection in application fields | **LOC-API + LOC-KYC** | LOC-API §Input *"Validate user input to avoid common vulnerabilities…"*; LOC-KYC §15 Input Validation & Injection |
| Verbose errors, debug mode, banner/header fingerprinting | **LOC-API + LOC-KYC** | LOC-API §Output *"Remove fingerprinting headers…"*; LOC-KYC §16 Error Handling & Information Disclosure |
| Liveness bypass, deepfake, 3D mask, video-selfie manipulation, WebView-KYC, Rekognition/S3 | **LOC-KYC** | §1–§4 and §21 (WebView-Based KYC Flow) in their entirety |
| Mobile reverse engineering (JADX, Apktool, Frida, SSL Kill Switch, jailbreak/root bypass) | **LOC-KYC** | §7 and §8 |
| Mobile intent / deep-link / URL-scheme hijack | **LOC-KYC** | §21.1 *"Universal Links / Deep Link Hijacking"*, §21.5 *"URL Scheme Interception"*, *"Intent Redirection (Android)"* |
| Centralized logging, alert channels, IDS/IPS, SIEM forwarding, "don't log sensitive data" | **LOC-API + LOC-KYC** | LOC-API §Monitoring (all items); LOC-KYC §18 Logging, Auditing & Monitoring |
| OSINT / facial recon / Shodan / subdomain enumeration | **LOC-KYC** | §19 OSINT — Target Reconnaissance |
| Endpoint enumeration & wordlists | **LOC-API** | §Enumeration + §Wordlists |

---

## 4. Expected REFERENCE vs INCLUDE Tally

Estimated from **AST10-C**'s 83 numbered checks plus the ~12 PLATFORM vectors (A11), projected through the rules in §2.

### Per section

| Section | Candidate items | INCLUDE | REFERENCE (incl. internal) |
|---|---:|---:|---:|
| AST01 Malicious Skills | 6 | 5 | 1 |
| AST02 Supply Chain | 7 | 4 | 3 |
| AST03 Over-Privileged | 8 | 6 | 2 |
| AST04 Insecure Metadata | 12 | 8 | 4 |
| AST05 Untrusted External Instructions | 6 | 5 | 1 |
| AST06 Weak Isolation | 7 | 5 | 2 |
| AST07 Update Drift | 6 | 2 | 4 |
| AST08 Poor Scanning | 7 | 5 | 2 |
| AST09 No Governance | 7 | 5 | 2 |
| AST10 Cross-Platform Reuse | 6 | 5 | 1 |
| PLATFORM (A11) | 12 | 9 | 3 |
| **Total** | **84** | **59** | **25** |

### By category verdict

| Verdict | Count |
|---|---|
| `INCLUDE`-dominant sections | **9** (AST01, 03, 04, 05, 06, 08, 09, 10, PLATFORM) |
| Mixed sections | **2** (AST02, AST07) |
| `REFERENCE`-dominant sections | **0** |

### Directional ratios

- **Overall item split: ≈ 70% INCLUDE / 30% REFERENCE** (59/84 vs 25/84).
- **REFERENCE destination split:** ~45% → OWASP API Top 10 2023 + `LOC-API`; ~35% → `LOC-KYC` (§9–§21); ~15% → LLM Top 10 2025; ~5% → Agentic AI Top 10.
- **Most deduped section:** AST07 Update Drift (≈67% REFERENCE) — its substance collapses into AST02 (pinning) + AST06 (hot-reload).
- **Least deduped section:** AST05 Untrusted External Instructions (≈17% REFERENCE) and PLATFORM (≈25% REFERENCE) — these carry the checklist's unique value.

---

## 5. The Single Most Important Keep-INCLUDE Boundary

> **SSRF to a cloud metadata endpoint = REFERENCE (API Top 10 API7, already covered). Localhost control-plane hijack of an *agent* = INCLUDE (agentic-specific).**

A test is uniquely agentic when the **victim is the agent's own behavior or control surface** — its instruction files (`SKILL.md`, `SOUL.md`, `MEMORY.md`), its permission manifest, its per-skill credential scope, its localhost control plane, or its update/hot-reload path. Everything that still works when you replace the victim with a plain REST endpoint or a plain mobile app is somebody else's checklist. Concretely: the ClawJacked boundary (a web page brute-forcing `127.0.0.1` WebSocket to hijack a running agent, CVE-2026-28363 CVSS 9.9) is the canonical INCLUDE case, and plain `169.254.169.254` SSRF is the canonical REFERENCE case.

---

*Part of Phase 1 research for `agentic-skills-offensive-checklist`. Sources: OWASP Agentic Skills Top 10 (`index.md`, `checklist.md`), OWASP LLM Top 10 2025, OWASP Top 10 for Agentic Applications (ASI01–ASI10), OWASP API Security Top 10 2023, plus the two local checklists under `Pentesting/Checklist/`.*
