# Injection sinks and common mappings

| Sink | Patterns | CWE | OWASP Top 10 (2021) | Mitigation evidence to cite |
| --- | --- | --- | --- | --- |
| SQL | string-built queries: f-strings, `+`, `fmt.Sprintf`, template literals into `execute/query/Exec/raw()` | CWE-89 | A03 Injection | parameterized queries (`%s` + params tuple, `$1`, `?`), ORM query builders |
| OS command | `os.system`, `subprocess(..., shell=True)`, `exec`, `child_process.exec`, `sh -c` with input | CWE-78 | A03 | argument arrays without a shell, allowlists |
| Code eval | `eval`, `exec`, `new Function`, `vm.runInContext`, `pickle.loads` on input | CWE-94 / CWE-502 | A03 / A08 | no dynamic eval; safe loaders (`yaml.safe_load`) |
| Template | `render_template_string(input)`, `Template(input)`, `{{{ }}}` unescaped | CWE-1336 / CWE-79 | A03 | autoescape on, static templates |
| Deserialization | `pickle`, `yaml.load`, Java `ObjectInputStream`, `BinaryFormatter`, `unserialize` | CWE-502 | A08 | safe formats, type allowlists |
| SSRF | HTTP client with a user-controlled URL or host | CWE-918 | A10 | URL allowlists, metadata IP blocking, egress policy |
| Path traversal | file open/send with a user-controlled path | CWE-22 | A01 | `realpath` + prefix check, ID→path mapping |
| XSS | unescaped output to HTML | CWE-79 | A03 | framework escaping, CSP |
| Open redirect | redirect to a user-supplied URL | CWE-601 | A01 | allowlist |
| LDAP/XPath/NoSQL | string-built filters; Mongo `$where` or operator injection from JSON bodies | CWE-90 / CWE-643 / CWE-943 | A03 | parameterized APIs, type checks |
| AuthZ | ID lookups without an owner check | CWE-639 | A01 | ownership predicate in the query |
| Secrets | hardcoded credentials, default passwords | CWE-798 / CWE-1392 | A07 | secret manager, required env with no default |

OWASP LLM Top 10 (2025) shorthand: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.
