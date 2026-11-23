# Context formats ckb ingests

| Category | Formats | Extracted |
| --- | --- | --- |
| Diagrams | draw.io / diagrams.net (`.drawio`, `.drawio.xml`, `.dio`, including compressed pages) | per page: shapes (label, container such as a swimlane, group, or VPC, style hints for AWS/Azure/GCP icons), connectors (source → target : label) |
| | Visio `.vsdx` | per page: shape text; connectors from Connect begin and end cells |
| | SVG | text labels only |
| | PNG/JPG/GIF/WebP whiteboards and exports | `needs_reading`: Claude views the image with the Read tool and writes `<file>.notes.md` |
| Documents | Word `.docx` | headings (as markdown levels), paragraphs, tables |
| | PowerPoint `.pptx` | per-slide text |
| | PDF | text per page via `pdftotext` (poppler) when installed; otherwise `needs_reading` (the Read tool reads PDFs) |
| | Markdown, text, reStructuredText, AsciiDoc, HTML | text (HTML with tags and scripts removed) |
| IaC | Terraform (`.tf`, `.tf.json`, `.tfvars`, terragrunt), AWS CloudFormation, SAM, CDK (`cdk.json`), Azure ARM and Bicep, GCP Deployment Manager (`.jinja`, YAML), Kubernetes, Helm, Pulumi | copied verbatim; `inventory.py` lists cloud resources and `scan_supply_chain.py` runs IaC misconfiguration checks (SC-D05 to SC-D09, SC-S08) |
| CSPM and IaC scanners | AWS Security Hub ASFF, Prowler JSON / OCSF / CSV, ScoutSuite results, Microsoft Defender for Cloud assessments, GCP Security Command Center findings, Checkov JSON, SARIF (Checkov, tfsec, KICS, Trivy, Snyk IaC), generic CSV with severity, resource, and title columns (Wiz, Prisma Cloud, Orca exports) | a normalized table, one finding per line: provider, check ID, severity, status, resource, title; plus severity counts and the number not passing |
| Not supported | `.doc`, `.vsd`, `.ppt`, `.xls` (legacy binary) | ask for an export to an open format |

Limits: 50 MB per file; archive members 25 MB; 100 MB uncompressed per archive; compression ratio above 200:1 refused; XML with DOCTYPE or ENTITY refused. Secret-looking values are redacted in every converted file.
