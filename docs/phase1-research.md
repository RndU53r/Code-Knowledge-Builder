# Phase 1: Reference project research

Both repos were cloned read-only (`git -c core.hooksPath=/dev/null clone --depth 1`) into a scratch directory. Nothing was installed or executed. Citations are `repo/path:line` at the commits below.

| Short name | Repo | Commit inspected |
| --- | --- | --- |
| `othman` | https://github.com/OthmanAdi/codebase-knowledge-builder | `b01f40c5` (2026-08-30) |
| `arden` | https://github.com/ardennguyen/Codebase-Knowledge-Builder | `f1030acf` (2026-09-28) |

## 1. OthmanAdi/codebase-knowledge-builder

**What it is:** a single Agent Skill, also packaged as a skills-only Claude Code plugin (`othman/.claude-plugin/plugin.json:19`, `"skills": "./skills/"`). There is no code, no agents, no hooks, and no commands. It is 4 markdown files: `SKILL.md`, two references, and one template.

**Pipeline** (`othman/skills/codebase-knowledge-builder/SKILL.md:12`): four phases.
1. Reconnaissance: scope, provenance, revision, and an inventory of tracked files (`SKILL.md:23-32`, `references/recon-checklist.md`).
2. Deep-dive: one question per evidence trail, happy, error, and edge paths (`SKILL.md:34-44`, `references/deep-dive-methodology.md`).
3. Artifact authoring: fill in the template (`SKILL.md:46-54`).
4. Validation and delivery: re-check citations, compare the worktree, recheck the output path (`SKILL.md:56-64`).

**Output format:** one markdown "knowledge artifact" per question (`templates/knowledge_artifact.md`). It has sections for Provenance, Executive Summary, Architecture table, Behavior Trace, Interfaces/Config, Decisions, Visual Model (optional Mermaid), Unresolved Questions, and Evidence Index. Every claim carries a label (`observed` / `inferred` / `unknown` / `not applicable`) with a `relative/path:line` citation (`references/deep-dive-methodology.md:54-59`).

**Strong points:**
- An explicit trust contract: repo content is untrusted evidence, the target stays read-only, no symlink following, secrets excluded, and output goes outside the target by default (`SKILL.md:14-21`).
- Mermaid hygiene: synthetic node IDs and escaped labels, and repo text never goes into diagram syntax (`SKILL.md:54`, `deep-dive-methodology.md:75`).
- Its own CI pins actions by SHA and runs `npm pack --ignore-scripts` (`.github/workflows/quality.yml`). That's a good model for our supply-chain checks.

**License:** MIT, © 2025 Ahmad Othman Ammar Adi (`othman/LICENSE:1-3`). We can reuse, adapt, and redistribute it, including commercially, as long as the copyright and permission notice are kept.

## 2. ardennguyen/Codebase-Knowledge-Builder

**What it is:** a standalone Python CLI (`python main.py --repo|--dir ...`, `arden/README.md:55-65`) built on the PocketFlow framework. It sends repo files to an external LLM (Gemini, OpenRouter, Anthropic, or Ollama) and writes tutorial or API-reference markdown, optionally as an MkDocs site. It is **not** a Claude Code plugin.

**Pipeline** (`arden/flow.py:19-51`): FetchRepo → ContextRouter, which takes one of three routes:
- `direct`: IdentifyAbstractions → AnalyzeRelationships
- `batch`: MapAbstractions → ReduceAbstractions (map-reduce for large repos) → AnalyzeRelationships
- `deterministic`: DeterministicFileMapper → ExtractFacts

All routes end with OrderChapters → WriteChapters → CombineTutorial. Prompts are per mode in `arden/prompts/{tutorial,advanced,api-reference,sdk}/` plus common ones (`extract_facts`, `extract_manifest`, `group_modules`).

**Output format:** one chapter per abstraction (or per file in `api-reference` mode), plus `index.md`, `full_content.md`, and optional MkDocs nav (`arden/README.md:97`). In `api-reference` mode it also writes `facts.json` and `chapter_check.json` (`arden/README.md:88`).

**Strong points:**
- **Quote-verified facts.** The LLM must quote source lines exactly, and code discards any fact whose quote isn't in the file (`arden/prompts/common/extract_facts.md:5`, `arden/utils/facts.py:251` `verify_file_claims`). The result is a `facts.json` of symbols, dependencies, config keys, and errors with line numbers.
- **Deterministic doc checks** with no LLM: broken links, Mermaid that won't render, signature drift against the source, invented type names (`arden/utils/chapter_check.py:209,219,767,797`).
- **Cross-file import resolution** from manifests (package.json, tsconfig, go.mod, Cargo.toml) (`arden/README.md:88`).
- **Incremental MD5 caching** to skip unchanged modules (`arden/README.md:90`).
- Secret files are never sent to the LLM (`arden/docs/design.md:465`).

**License:** CC BY-NC-SA 4.0, © 2026 Arden Nguyen Duc Huy (`arden/LICENSE:5-7`, `arden/NOTICE:25-46`).
- **NonCommercial:** no use in a commercial product, a paid service, or company operations (`arden/NOTICE:36-39`).
- **ShareAlike:** if you share an adaptation, it must also be CC BY-NC-SA (`arden/NOTICE:44-46`).
- Portions from the original PocketFlow Tutorial-Codebase-Knowledge stay MIT (`arden/NOTICE:82-89`). [unknown] Which files, and whether the facts and chapter-check code existed in the MIT-era versions, wasn't checked.

**What this means for us:** don't copy its code or prompt text into our plugin. Doing so would force our plugin under NC-SA and block company use. Ideas and techniques aren't covered by copyright, so we can **use it only as inspiration** and write our own implementation from scratch. We'll still credit it in the README.

## 3. Gaps against our requirements (Phase 3 A–E)

| Requirement | othman | arden |
| --- | --- | --- |
| A. Inventory (languages, entry points, deps) | Partial: recon checklist, single repo | Partial: manifest-based imports and symbols |
| A. Call/data flow across repos, async, shared state | No: one subsystem per artifact | No: single repo, import-level only |
| A. Polyglot edges (FFI, subprocess, generated clients) | No | Partial: imports across languages, no runtime edges |
| A. System HLD + per-repo HLD/LLD, sequence diagrams | No: one free-form artifact | Partial: "advanced" chapters, not HLD/LLD |
| B. Outputs and conditions table | No (has error/edge paths) | No (extracts config keys and errors) |
| C. Threat model (STRIDE, DFD, CWE/OWASP) | No | No |
| D. `context.md` for scanners | No | No (`facts.json` is the nearest thing) |
| E. Supply-chain and injection audit | No (safety is about the agent, not findings) | No |
| Multi-repo / microservices | No | No |
| Untrusted-input safety | **Strong**, but prose only, not enforced | Weak: no untrusted-data framing found in prompts (grep for "untrusted", "injection", "treat as data" returned nothing) |
| Enforced guards (hooks), parallel agents, verifier | No | Has a deterministic verifier in Python, no hooks |
| Incremental refresh | No | Yes (MD5 cache) |
| Runs inside Claude Code | Yes | No: separate CLI with its own API keys |

## 4. Prompt-injection check on the references

- A phrase scan ("ignore previous instructions", "you are now", "run this script", and similar) found **no matches** in either repo. A scan for hidden or bidirectional Unicode also found **none**.
- `arden` ships agent instruction files (`CLAUDE.md`, `.agents/rules/AGENTS.md`, `.clinerules/`, `.cursor/rules/`, `.windsurf/rules/`). They're ordinary contributor guides for agents working *on that repo*, not hostile. I treated them as data and didn't follow them. Finding: informational, low confidence that it matters.

## 5. Comparison and recommendation

| | othman | arden |
| --- | --- | --- |
| Form | Agent Skill / CC plugin (markdown only) | Python CLI + external LLM API |
| Scope | One question, one repo | Whole repo as a tutorial or API docs |
| Evidence model | Labels + `path:line` citations | Quote-verified facts + line numbers |
| Verification | Manual checklist | Deterministic code checks |
| Safety | Excellent written contract | Secret-file exclusion only |
| License | MIT: reuse with attribution | CC BY-NC-SA: inspiration only |

**From othman (adapt, with MIT notice in `NOTICE`):**
1. The trust contract: untrusted input, read-only, no symlinks, secret redaction. This becomes our shared `references/safety-contract.md`, now enforced by hooks.
2. The evidence labels `observed / inferred / unknown / not applicable`, mapped to the `[inferred]` / `[unknown]` markers and high/medium/low confidence the prompt requires.
3. The provenance block (repo, revision, timestamp, scope, exclusions) at the top of every output file.
4. The Mermaid rules (synthetic IDs, escaped labels) and the recon checklist structure.

**From arden (ideas only, written fresh):**
1. A **citation verifier** script: every `path:line` must exist, and quoted snippets must match the source. This powers the verifier agent and the PostToolUse hook.
2. **Deterministic output checks**: Mermaid syntax, broken internal links, and empty-citation sections.
3. **Content-hash incremental refresh** to drive `/ckb:update`.
4. **Manifest-based import resolution** for cross-repo and polyglot edges.
5. **Map-reduce for large repos**, which maps naturally onto parallel per-repo analyzer agents.

**Entirely new (in neither repo):** multi-repo flow tracing, outputs-and-conditions, the threat model, `context.md`, the supply-chain audit, hooks, and the agent set.
