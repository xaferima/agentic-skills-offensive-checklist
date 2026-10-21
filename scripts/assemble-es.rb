#!/usr/bin/env ruby
# assemble-es.rb — stitch translated ES parts (.es-part1..3.md) with a Spanish
# header + auto-generated contents (parsed from the parts). Deterministic.
root = File.expand_path('..', __dir__)
dir  = File.join(root, 'checklist')

PARTS = %w[.es-part1.md .es-part2.md .es-part3.md]
missing = PARTS.reject { |f| File.exist?(File.join(dir, f)) }
unless missing.empty?
  abort <<~MSG
    assemble-es.rb: translation parts not found (#{missing.join(', ')}).
    The Spanish mirror is committed as checklist/agentic-skills-offensive-checklist-es.md;
    the .es-part*.md sources are intentionally not published. Rebuilding the mirror
    requires a full re-translation (see CONTRIBUTING.md).
  MSG
end

parts = PARTS.map { |f| File.read(File.join(dir, f)) }
body = parts.join("\n")

sections = []
current  = nil
body.each_line do |ln|
  if ln =~ /^##\s+(\d+)\.\s+(.+?)\s*$/
    current = { n: $1.to_i, title: $2.strip, count: 0 }
    sections << current
  elsif ln =~ /^- \[ \] \*\*/ && current
    current[:count] += 1
  end
end

total = sections.sum { |s| s[:count] }
contents = sections.map { |s| "- #{s[:n]}. #{s[:title]} — #{s[:count]} ítems" }.join("\n")

header = <<~MD
# Agentic Skills — Checklist Ofensivo de Pentesting

> **#{total} pruebas de ataque en 12 secciones.** Contraparte centrada en el atacante del
> [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) (AST10).
> Cada ítem responde: _¿qué hace el atacante, con qué herramienta, y qué evidencia confirma el hallazgo?_
>
> **Alcance:** SOLO laboratorios Docker/local propiedad del investigador. Los PoCs usan [`snyk-labs/toxicskills-goof`](https://github.com/snyk-labs/toxicskills-goof)
> o skills propias de laboratorio — nunca skills reales de registros públicos contra terceros.
>
> Mirror en español de [agentic-skills-offensive-checklist.md](./agentic-skills-offensive-checklist.md) — la versión EN es la fuente de verdad.
>
> _Traducción mantenida como artefacto: no se regenera automáticamente (ver `CONTRIBUTING.md`)._
> Acompañantes: [`README.md`](../README.md) · [`README-es.md`](../README-es.md) · [`utility-report.md`](../research/utility-report.md)

## Cómo usar

1. Levanta un laboratorio aislado (Docker, sinkholes de reverse-shell, listeners en localhost). Nunca pruebes contra agentes o registros de terceros.
2. Recorre las secciones en orden; cada ítem es independiente y autocontenido.
3. Un hallazgo se confirma solo cuando se observa el artefacto de **evidencia** indicado (línea de log, conexión, contenido de archivo, prompt exitoso).
4. Registra cada intento: `[ ]` = pendiente, `[x]` = confirmado, o anota el resultado.
5. Los ítems `REFERENCE` están cubiertos por otras checklists — se enlazan, no se duplican (ver Apéndice A).

## Contenido

#{contents}

---
MD

out = File.join(dir, 'agentic-skills-offensive-checklist-es.md')
File.write(out, header + "\n" + body + "\n")
puts "wrote #{out}"
puts "sections=#{sections.size} items=#{total}"
