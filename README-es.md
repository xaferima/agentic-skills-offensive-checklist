> Mirror en español de [README.md](./README.md) — la versión en inglés es la fuente de verdad.

# Agentic Skills — Checklist Ofensivo de Pentesting

[![validate-checklist](https://github.com/xaferima/agentic-skills-offensive-checklist/actions/workflows/ci.yml/badge.svg)](https://github.com/xaferima/agentic-skills-offensive-checklist/actions/workflows/ci.yml)
[![license: CC BY-SA 4.0](https://img.shields.io/badge/license-CC%20BY--SA%204.0-lightgrey.svg)](LICENSE)

> Checklist de pruebas centrado en el atacante para agentes de codificación de IA y sus **skills** — abarca
> OpenClaw (`SKILL.md` / `SOUL.md` / `MEMORY.md`), Claude Code (`skill.json`, `.claude/settings.json`, hooks),
> Cursor / Codex (`manifest.json`) y VS Code (`package.json`, `extension.ts`), además de servidores y hosts MCP.
> Contraparte ofensiva del [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) (AST10).

**65 pruebas de ataque · 12 secciones · solo laboratorio.**

---

## Por qué existe esto

Las **skills** de agentes son la capa de comportamiento que le da efecto en el mundo real a un agente: orquestan
acceso a archivos, salida a red, shell, memoria y estado entre sesiones. El AST10 de OWASP documenta los riesgos y sus
**mitigaciones**. Este proyecto es el **espejo ofensivo**: por cada control defensivo se pregunta —

> *¿Qué hace el atacante, con **qué herramienta**, y **qué evidencia** confirma el hallazgo?*

La línea base peligrosa es la **trifecta letal** de Simon Willison: acceso a datos privados + contenido no confiable +
salida externa — combinación que la mayoría de los despliegues de agentes en producción cumple de forma simultánea.

## Alcance y ética (no negociable)

- Cada prueba se ejecuta **únicamente** en laboratorios **Docker / locales** propiedad del investigador.
- Los PoC usan [`snyk-labs/toxicskills-goof`](https://github.com/snyk-labs/toxicskills-goof) o las **skills de laboratorio propias**
  del investigador — **nunca** skills reales del registro para atacar sistemas o usuarios de terceros.
- Cada ítem declara su **riesgo de daño colateral** (p. ej., borrado de memoria, RCE en el host).
- Las pruebas de descubrimiento/plano de control apuntan **solo a tu propia instancia de laboratorio**.

## Metodología

1. **Fuentes primarias.** OWASP AST10 `ast01`–`ast10`, `checklist.md`, `universal-skill-format.md`,
   `threat-intelligence.md`, `case-studies.md` — además de investigación pública: la serie *"Pwning AI Agents"* de m10x,
   Snyk ToxicSkills, Check Point (`CVE-2025-59536`), Oasis ClawJacked (`CVE-2026-28363`),
   Air Security *"The Story of Skills"*, el bypass de escáner de Trail of Bits, y `arXiv:2602.06547`.
2. **Regla de inversión.** Cada control defensivo se reescribe como su espejo de ataque (verbo del atacante + éxito observable).
   Los ítems que solo reformulan una mitigación se rechazan.
3. **Filtro de utilidad.** Cada candidato se puntúa de A–E y se admite solo si
   `B ≥ 4 AND avg(A,D,E) ≥ 3.5 AND C ≥ 3`:

   | | criterio |
   |---|---|
   | A | especificidad del agente (exclusivo de agentes autónomos frente a genérico) |
   | B | testeabilidad (laboratorio controlado + herramienta concreta + resultado objetivo) |
   | C | evidencia pública (CVE / investigación / incidente real) |
   | D | no duplicación |
   | E | impacto ofensivo (RCE / credenciales / persistencia / toma de control) |

   `REFERENCE` si `D ≤ 2` (ya cubierto en otro lado → solo enlace); `DISCARD` en caso contrario.
4. **Deduplicación.** El solapamiento con OWASP API Top 10 / LLM Top 10 / Agentic-AI Top 10 y con checklists
   existentes se mapea en [`research/dedup-matrix.md`](research/dedup-matrix.md) — las pruebas que se solapan se
   marcan como `REFERENCE` y se enlazan, nunca se duplican.

## Contenido

| # | Sección | Fuente | Ítems |
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

## Cómo usarlo

1. Levanta un laboratorio aislado (contenedores Docker, listeners en localhost, sumideros de reverse shell).
2. Abre [`checklist/agentic-skills-offensive-checklist.md`](checklist/agentic-skills-offensive-checklist.md) y recorre las secciones.
3. Un hallazgo se **confirma solo** cuando se observa el artefacto de **evidencia** declarado (línea de log, conexión, contenido de archivo, prompt exitoso).
4. Marca `[x]` al confirmar; anota los resultados en línea.
5. Los ítems `REFERENCE` son enlaces cruzados a otros checklists (Apéndice A del checklist).
6. Da seguimiento en [`checklist/agentic-skills-offensive-checklist.xlsx`](checklist/agentic-skills-offensive-checklist.xlsx)
   (una fila por ítem, desplegable de estado, dashboard en vivo). Versión en español:
   [`checklist/agentic-skills-offensive-checklist-es.md`](checklist/agentic-skills-offensive-checklist-es.md).

## Estructura del repositorio

```
README.md                                   # fuente de verdad (EN)
README-es.md                                # este archivo (espejo ES)
checklist/
  agentic-skills-offensive-checklist.md     # checklist de 65 ítems (generado, EN — fuente de verdad)
  agentic-skills-offensive-checklist-es.md  # espejo en español (generado)
  agentic-skills-offensive-checklist.xlsx   # hoja de seguimiento: desplegable de estado + dashboard
  items.json                                # export legible por máquina (alimenta el .xlsx)
  REVIEW.md                                 # veredicto del reviewer (arnés del dominio)
research/
  ast01-items.yaml … ast10-items.yaml       # ítems candidatos + puntajes + veredictos
  ast11-platform-items.yaml                 # vectores de plataforma / host MCP
  dedup-matrix.md                           # reglas de solapamiento vs otros checklists
  tooling-map.md                            # herramienta → prueba → evidencia
  utility-report.md                         # tabla completa de puntajes/veredictos + conteos
scripts/
  validate.sh                               # marcadores + integridad YAML + paridad EN/ES
  consolidate.rb                            # YAMLs → utility-report.md
  build-checklist.rb                        # ensamblado determinista del checklist + items.json
  assemble-es.rb                            # une las partes traducidas → checklist ES
  build-xlsx.py                             # construye el .xlsx de seguimiento desde items.json
  check-xlsx.py                             # integridad del libro (65 filas + desplegable)
  ci.sh                                     # gate: regenerar → drift → xlsx → validar
.github/workflows/ci.yml                    # GitHub Actions que ejecuta scripts/ci.sh
LICENSE                                     # CC-BY-SA-4.0
citation.cff                                # cita legible por máquina (CFF 1.2)
SECURITY.md                                 # cómo reportar un problema
CONTRIBUTING.md                             # cómo agregar y puntuar un ítem
```

## Herramientas (resumen)

| Herramienta | Qué valida |
|---|---|
| [`NVIDIA/SkillSpector`](https://github.com/NVIDIA/SkillSpector) | el escaneo estático+semántico de skills más amplio (AST01–04, 08–10) |
| [Snyk](https://snyk.io/) | escaneo de comportamiento estilo agent-scan / ToxicSkills |
| Gitleaks · TruffleHog | detección de credenciales/secretos en archivos de skills |
| [`alice-dot-io/caterpillar`](https://github.com/alice-dot-io/caterpillar) | SAST de comportamiento dinámico para agentes de IA |
| [`luckyPipewrench/pipelock`](https://github.com/luckyPipewrench/pipelock) | proxy de red en tiempo de ejecución — DLP, inyección, envenenamiento de herramientas |
| Burp Suite · mitmproxy | interceptación / captura de exfiltración |
| Frida | instrumentación en tiempo de ejecución (extensiones de agentes) |
| jq · yq · docker | inspección de manifiestos, aislamiento del laboratorio |

Matriz completa y brechas en [`research/tooling-map.md`](research/tooling-map.md).

## Integración continua

[`scripts/ci.sh`](scripts/ci.sh) es el único gate. Hace:

1. corre el `init.sh` del arnés si existe (se omite en el repo público),
2. regenera `research/utility-report.md`, el checklist EN y `items.json`,
3. **falla ante drift** si los artefactos commiteados difieren de los YAML fuente,
4. verifica que el `.xlsx` abra con 65 filas y el desplegable de estado,
5. valida marcadores y paridad EN/ES (65/65).

GitHub Actions ejecuta el mismo script en cada push a `main` y en cada pull request
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). En local:

```bash
pip install openpyxl
bash scripts/ci.sh      # → CI: PASS
```

## Historial de versiones y hoja de ruta

- **v1.0.0 — versión inicial:** **65** pruebas de ataque en 12 secciones (espejos EN + ES),
  `.xlsx` de seguimiento (desplegable de estado + dashboard) y el corpus de investigación completo
  (**77** candidatos puntuados: **65** incluidos / **11** referenciados / **1** descartado).
  Un gate de CI regenera cada artefacto desde los YAML fuente y falla ante drift.
- **Planificado:** rubric de puntaje por engagement sobre los 65 ítems; guías rápidas
  de laboratorio por plataforma.

## Licencia

Derivado del OWASP Agentic Skills Top 10 (CC-BY-SA-4.0); distribuido bajo los mismos términos.
