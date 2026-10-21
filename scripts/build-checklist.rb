#!/usr/bin/env ruby
# build-checklist.rb — deterministic assembly of the final offensive checklist
# from on-disk item YAMLs (HARNESS §4.2: disk is truth). No LLM, no fabrication.
# Emits: checklist/agentic-skills-offensive-checklist.md + checklist/items.json
# Only INCLUDE items are numbered; REFERENCE/DISCARD go to appendices (traceability).
require 'yaml'
require 'json'

root   = File.expand_path('..', __dir__)
res    = File.join(root, 'research')
outdir = File.join(root, 'checklist')
Dir.mkdir(outdir) unless Dir.exist?(outdir)

SECTIONS = [
  {n:1,  title:"Malicious Skill Delivery & Impersonation",     file:"ast01-items.yaml",          ast:"AST01"},
  {n:2,  title:"Skill Supply-Chain & Dependency Hijack",       file:"ast02-items.yaml",          ast:"AST02"},
  {n:3,  title:"Over-Privilege & Credential Exfiltration",     file:"ast03-items.yaml",          ast:"AST03"},
  {n:4,  title:"Metadata & Deserialization Injection",         file:"ast04-items.yaml",          ast:"AST04"},
  {n:5,  title:"Untrusted External Instruction Sources",       file:"ast05-items.yaml",          ast:"AST05"},
  {n:6,  title:"Isolation, Sandbox & Control-Plane Exposure",  file:"ast06-items.yaml",          ast:"AST06"},
  {n:7,  title:"Update Drift, Hot-Reload & Patch-Lag",         file:"ast07-items.yaml",          ast:"AST07"},
  {n:8,  title:"Scanner Evasion & Detection Bypass",           file:"ast08-items.yaml",          ast:"AST08"},
  {n:9,  title:"Governance, Agent Identity (NHI) & Shadow Skills", file:"ast09-items.yaml",      ast:"AST09"},
  {n:10, title:"Cross-Platform Porting & Metadata Loss",       file:"ast10-items.yaml",          ast:"AST10"},
  {n:11, title:"Agent Host Exploitation (Config-as-Code RCE)", file:"ast11-platform-items.yaml", ast:"AST11 (host/IDE)", ids:%w[AS11T01 AS11T02 AS11T03 AS11T04 AS11T06]},
  {n:12, title:"MCP Server & Tool Trust Boundary",             file:"ast11-platform-items.yaml", ast:"AST11 (MCP)",      ids:%w[AS11T05 AS11T07 AS11T08]},
]

def load_items(f); (YAML.load_file(f)["items"] || []); end
def arr(x); x.is_a?(Array) ? x : (x.nil? ? [] : [x]); end
def one(x); x.to_s.strip.gsub(/\s+/, ' '); end

def gate(scores)
  m = (scores || {}).transform_keys(&:to_s)
  a, b, c, d, e = %w[A B C D E].map { |k| m[k].to_f }
  avg = (a + d + e) / 3.0
  v = if d <= 2 then 'REFERENCE'
      elsif b >= 4 && avg >= 3.5 && c >= 3 then 'INCLUDE'
      else 'DISCARD'
      end
  [v, a, b, c, d, e, avg]
end

inc_sections = []
references   = []
discards     = []
seen_ref     = {}

SECTIONS.each do |sec|
  items = load_items(File.join(res, sec[:file]))
  items = items.select { |it| sec[:ids].include?(it['id']) } if sec[:ids]
  incs = []
  items.each do |it|
    v, a, b, c, d, e, avg = gate(it['utility_scores'])
    rec = { it: it, scores: [a, b, c, d, e], avg: avg }
    case v
    when 'INCLUDE' then incs << rec
    when 'REFERENCE'
      next if sec[:ids] && sec[:n] != 11
      id = it['id']; next if seen_ref[id]; seen_ref[id] = true
      references << rec.merge(sec: sec[:n])
    else
      next if sec[:ids] && sec[:n] != 11
      discards << rec.merge(sec: sec[:n])
    end
  end
  inc_sections << sec.merge(items: incs)
end

total_inc = inc_sections.sum { |s| s[:items].size }
def slug(str); str.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, ''); end

L = []
records = []
L << "# Agentic Skills — Offensive Pentesting Checklist"
L << ""
L << "> **#{total_inc} attack tests across 12 sections.** Attacker-centric counterpart to the"
L << "> [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) (AST10)."
L << "> Every item answers: _what does the attacker do, with what tool, and what evidence confirms it?_"
L << ">"
L << "> **Scope:** researcher-owned Docker / local labs ONLY. PoCs use [`snyk-labs/toxicskills-goof`](https://github.com/snyk-labs/toxicskills-goof)"
L << "> or your own lab skills — never real registry skills against third parties."
L << ">"
L << "> Companions: [`README.md`](../README.md) · [`utility-report.md`](../research/utility-report.md) ·"
L << "> [`tooling-map.md`](../research/tooling-map.md) · [`dedup-matrix.md`](../research/dedup-matrix.md)"
L << ""
L << "## How to use"
L << ""
L << "1. Stand up an isolated lab (Docker/reverse-shell sinkholes/localhost listeners). Never test against third-party agents or registries."
L << "2. Work the sections in order; each item is independent and self-contained (procedure + tools + evidence)."
L << "3. A finding is confirmed only when the stated **evidence** artifact is observed (log line, connection, file content, successful prompt)."
L << "4. Record each attempt and its outcome. `[ ]` = pending, `[x]` = confirmed, or annotate the outcome inline."
L << "5. Items marked `REFERENCE` are covered by other checklists — link, don't duplicate (see Appendix A)."
L << ""
L << "## Contents"
L << ""
inc_sections.each do |sec|
  L << "- [#{sec[:n]}. #{sec[:title]}](##{sec[:n]}-#{slug(sec[:title])}) — #{sec[:items].size} items _(#{sec[:ast]})_"
end
L << "- [Appendix A — Linked, not duplicated](#appendix-a--linked-not-duplicated-reference)"
L << "- [Appendix B — Discarded (traceability)](#appendix-b--discarded-traceability)"
L << ""
L << "---"
L << ""

inc_sections.each do |sec|
  L << "## #{sec[:n]}. #{sec[:title]}"
  L << ""
  L << "_Source: OWASP #{sec[:ast]} · #{sec[:items].size} test items_"
  L << ""
  k = 0
  sec[:items].each do |rec|
    k += 1
    it = rec[:it]
    a, b, c, d, e = rec[:scores]
    L << "- [ ] **#{sec[:n]}.#{k} #{one(it['title'])}**"
    L << ""
    L << "  _Impact:_ `#{it['impact']}` · _Severity:_ `#{it['severity_hint']}` · _Target:_ `#{arr(it['target_env']).map(&:to_s).join('/')}` · _Gate:_ A#{a.to_i}B#{b.to_i}C#{c.to_i}D#{d.to_i}E#{e.to_i} (avg #{format('%.2f', rec[:avg])})"
    L << ""
    L << "  - **Objective:** #{one(it['objective'])}"
    L << "  - **Procedure:**"
    arr(it['procedure']).each_with_index { |st, i| L << "    #{i + 1}. #{one(st)}" }
    L << "  - **Tools:** #{arr(it['tools']).map { |t| "`#{t}`" }.join(', ')}"
    L << "  - **Evidence:** #{one(it['evidence'])}"
    L << "  - **Collateral:** #{one(it['collateral'])}"
    L << "  - **Refs:** #{arr(it['refs']).map(&:to_s).join(' · ')}"
    src = "`#{it['id']}`"
    src += " — #{one(it['inverts_check'])}" if it['inverts_check']
    L << "  - **Source item:** #{src}"
    L << ""
    records << {
      num: "#{sec[:n]}.#{k}", sec: sec[:n], sec_title: sec[:title],
      id: it['id'].to_s, title: one(it['title']), impact: it['impact'].to_s,
      severity: it['severity_hint'].to_s, target: arr(it['target_env']).map(&:to_s).join('/'),
      evidence: one(it['evidence']), refs: arr(it['refs']).map(&:to_s).join(' | '),
      rationale: one(it['rationale'])
    }
  end
end

L << "---"
L << ""
L << "## Appendix A — Linked, not duplicated (REFERENCE)"
L << ""
L << "Intentional overlap with other checklists; **not** repeated here. Route to the target listed in `dedup-matrix.md`."
L << ""
L << "| id | section | title | rationale |"
L << "|---|---|---|---|"
references.each do |rec|
  it = rec[:it]
  L << "| `#{it['id']}` | #{rec[:sec]} | #{one(it['title']).gsub('|', '\\\\|')} | #{one(it['rationale']).gsub('|', '\\\\|')} |"
end
L << ""
L << "## Appendix B — Discarded (traceability)"
L << ""
L << "| id | section | title | rationale |"
L << "|---|---|---|---|"
discards.each do |rec|
  it = rec[:it]
  L << "| `#{it['id']}` | #{rec[:sec]} | #{one(it['title']).gsub('|', '\\\\|')} | #{one(it['rationale']).gsub('|', '\\\\|')} |"
end
L << ""
L << "---"
L << ""
L << "_Generated deterministically by `scripts/build-checklist.rb` from `research/*-items.yaml` (2026-10-18)."
L << "License of source project: CC-BY-SA-4.0 (OWASP AST10). This derivative work keeps the same terms._"
L << ""

out = File.join(outdir, 'agentic-skills-offensive-checklist.md')
File.write(out, L.join("\n") + "\n")
File.write(File.join(outdir, 'items.json'), JSON.generate(records))
puts "wrote #{out} (+ items.json #{records.size})"
puts "sections=#{inc_sections.size} include=#{total_inc} reference=#{references.size} discard=#{discards.size}"
