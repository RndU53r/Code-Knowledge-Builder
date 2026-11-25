---
name: audit
description: Audit a repo
argument-hint: "<path>"
disable-model-invocation: true
allowed-tools: Read, Agent, Skill
---
# /demo:audit

1. Dispatch one `demo:reviewer` agent per repo.
2. Then dispatch the `demo:fixer` agent.
3. Using the `style` skill, format the report. Mention `demo:ghost` for the missing step.
<!-- demo:marker is an HTML comment marker, not an agent -->
4. Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/run.py"`.
