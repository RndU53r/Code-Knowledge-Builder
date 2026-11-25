---
ckb_context: 1
scope: {{repo_or_system}}
revision: {{sha_or_local}}
generated: {{iso8601}}
languages: []
repo_kind: ""        # from the facts block: application | service | library | iac | cicd-pipeline | gitops-config | mixed | ...
entry_points: 0      # counts below come from the generated facts block (evidence/context-facts-<repo>.json)
sources: 0
sinks: 0
core_files: 0
test_files: 0
focus_areas: []
---
# Security context: {{repo_or_system}}

> **ckb provenance**
> - Sources: {{sources_with_revisions}}
> - Generated: {{iso8601}} by ckb {{version}}, stage `{{stage}}`
> - Scope: {{scope}} · Excluded: {{exclusions}}
> - Method: static analysis only; no target code executed
> - Verification: {{verification_status}}

## Facts (generated)
<!-- Embed repos/<repo>/context-facts.md here verbatim, markers included (written by scripts/context_facts.py; check_outputs.py verifies it).
     It holds the code map and, depending on the repo kind: entry points, taint sources, sinks and known-safe patterns (application/service/library),
     provisioned resources and exposure (iac, gitops-config), or pipelines with triggers, runners, secrets, third-party code and deploy gates (cicd-pipeline).
     Do not edit it. Add your judgement in the numbered sections below, next to these tables, never over them. System-level file: omit this section and link each repo's context.md. -->

## 1. Purpose and tech stack
## 2. Entry points and trust boundaries
<!-- Judgement on top of the generated entry-point table: boundary crossed, real exposure (internet/internal/admin/CI), auth you verified. For iac repos this section is
     "provisioned resources and exposure"; for cicd-pipeline repos it is "triggers and blast radius" (who can start each pipeline, with which token, on which runner). -->
| Entry point | Exposure | Boundary | Source |
| --- | --- | --- | --- |
## 3. Authn/authz model
## 4. Sensitive data and where it flows
| Data | Source | Sinks | Protection | Source |
| --- | --- | --- | --- | --- |
## 5. Dangerous sinks and sanitizers already in place
<!-- Start from the generated sink table (and its known-safe patterns); add the sanitizer or guard you confirmed by reading and a final verdict per sink.
     For iac repos this section is "privileged operations" (wildcard IAM, public ingress, disabled encryption); for cicd-pipeline repos "privileged steps and secrets". -->
| Sink | Kind | Sanitizer or guard | Verdict | Source |
| --- | --- | --- | --- | --- |
## 6. Known-safe patterns and known-risky areas
## 7. Inter-service contracts
| Contract | Producer | Consumer | Auth | Source |
| --- | --- | --- | --- | --- |
## 8. Config and env conditions that change behavior
| Condition | Effect | Default | Source |
| --- | --- | --- | --- |
## 9. Threat-model summary and scanner focus
| Priority | Focus area | Paths | Why | Threat IDs |
| --- | --- | --- | --- | --- |
