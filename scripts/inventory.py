#!/usr/bin/env python3
"""Static inventory of one repo: languages, manifests, frameworks, entry-point and
edge candidates, contracts, infra artifacts, config reads. Reads files only.

Usage:
  inventory.py --root REPO_ROOT --key REPO_KEY [--json-out F] [--exclude GLOB ...]

Everything here is a CANDIDATE produced by regex. Agents must open the cited line
and confirm before stating it as fact. Each candidate carries a ckb citation.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ckb_common import is_binary, is_secret_file, now_iso, read_text, redact_text, walk_files, walk_symlinks  # noqa: E402

LANG = {".py": "python", ".go": "go", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript", ".java": "java", ".kt": "kotlin",
        ".rs": "rust", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".c": "c", ".h": "c", ".cc": "cpp",
        ".cpp": "cpp", ".hpp": "cpp", ".swift": "swift", ".scala": "scala", ".sh": "shell", ".bash": "shell",
        ".ps1": "powershell", ".sql": "sql", ".tf": "terraform", ".proto": "protobuf", ".graphql": "graphql",
        ".gql": "graphql", ".lua": "lua", ".ex": "elixir", ".exs": "elixir", ".dart": "dart", ".cxx": "cpp", ".hh": "cpp", ".hxx": "cpp",
        ".pl": "perl", ".pm": "perl", ".t": "perl", ".psgi": "perl", ".cgi": "perl", ".abap": "abap"}
MANIFESTS = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pyproject.toml",
             "poetry.lock", "uv.lock", "Pipfile", "setup.py", "setup.cfg", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
             "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "Gemfile", "Gemfile.lock", "composer.json",
             "mix.exs", "pubspec.yaml", "Makefile", "CMakeLists.txt", "BUILD", "BUILD.bazel", "WORKSPACE", "nx.json",
             "turbo.json", "lerna.json", "pnpm-workspace.yaml", "tsconfig.json", "deno.json", "*.csproj", "*.sln"}
INFRA = [
    ("dockerfile", re.compile(r"(^|/)(Dockerfile[^/]*|[^/]+\.Dockerfile|Containerfile)$")),
    ("compose", re.compile(r"(^|/)(docker-)?compose[^/]*\.ya?ml$")),
    ("kubernetes", re.compile(r"(^|/)(k8s|kube|kubernetes|manifests|deploy)/.+\.ya?ml$")),
    ("helm", re.compile(r"(^|/)(Chart\.yaml|values[^/]*\.yaml|templates/.+\.yaml)$")),
    ("kustomize", re.compile(r"(^|/)kustomization\.ya?ml$")),
    ("terraform", re.compile(r"\.tf$|\.tfvars$|\.tf\.json$|(^|/)terragrunt\.hcl$")),
    ("azure-bicep", re.compile(r"\.bicep$")),
    ("azure-arm", re.compile(r"(?i)(^|/)(azuredeploy|mainTemplate|arm[^/]*)\.(parameters\.)?json$")),
    ("aws-cdk", re.compile(r"(^|/)cdk\.json$")),
    ("pulumi", re.compile(r"(^|/)Pulumi(\.[^/]+)?\.ya?ml$")),
    ("gcp-deployment-manager", re.compile(r"(?i)\.(jinja|jinja2)$|(^|/)deployment[^/]*\.ya?ml$")),
    ("cloudformation", re.compile(r"(^|/)(template|cloudformation|stack)[^/]*\.(ya?ml|json)$")),
    ("serverless", re.compile(r"(^|/)(serverless\.ya?ml|template\.ya?ml|sam\.ya?ml)$")),
    ("github-actions", re.compile(r"^\.github/workflows/.+\.ya?ml$")),
    ("gitlab-ci", re.compile(r"(^|/)\.gitlab-ci\.ya?ml$")),
    ("jenkins", re.compile(r"(^|/)Jenkinsfile$")),
    ("circleci", re.compile(r"^\.circleci/config\.ya?ml$")),
    ("azure-pipelines", re.compile(r"(^|/)azure-pipelines\.ya?ml$")),
    ("gateway", re.compile(r"(?i)(^|/)(nginx[^/]*\.conf|envoy[^/]*\.ya?ml|kong[^/]*\.ya?ml|traefik[^/]*\.ya?ml|ingress[^/]*\.ya?ml|apigateway[^/]*|openresty[^/]*)$")),
]
CONTRACTS = [
    ("openapi", re.compile(r"(?i)(openapi|swagger)[^/]*\.(ya?ml|json)$")),
    ("protobuf", re.compile(r"\.proto$")),
    ("graphql", re.compile(r"\.(graphql|gql)$")),
    ("asyncapi", re.compile(r"(?i)asyncapi[^/]*\.(ya?ml|json)$")),
    ("avro", re.compile(r"\.(avsc|avdl)$")),
    ("json-schema", re.compile(r"(?i)\.schema\.json$|(^|/)schemas?/.+\.json$")),
]
FRAMEWORK_HINTS = {
    "express": "Express", "fastify": "Fastify", "koa": "Koa", "@nestjs/core": "NestJS", "next": "Next.js",
    "fastapi": "FastAPI", "flask": "Flask", "django": "Django", "aiohttp": "aiohttp", "starlette": "Starlette",
    "celery": "Celery", "gin-gonic/gin": "Gin", "labstack/echo": "Echo", "gofiber/fiber": "Fiber",
    "go-chi/chi": "chi", "gorilla/mux": "gorilla/mux", "grpc": "gRPC", "spring-boot": "Spring Boot",
    "actix-web": "Actix", "axum": "Axum", "rails": "Rails", "laravel": "Laravel", "kafkajs": "Kafka (kafkajs)",
    "kafka-python": "Kafka (kafka-python)", "confluent-kafka": "Kafka (confluent)", "segmentio/kafka-go": "Kafka (kafka-go)",
    "amqplib": "RabbitMQ (amqplib)", "pika": "RabbitMQ (pika)", "rabbitmq/amqp091-go": "RabbitMQ (amqp091)",
    "@aws-sdk/client-sqs": "SQS", "boto3": "AWS SDK (boto3)", "aws-sdk-go": "AWS SDK (Go)", "redis": "Redis",
    "ioredis": "Redis", "go-redis": "Redis", "sqlalchemy": "SQLAlchemy", "psycopg": "PostgreSQL", "pg": "PostgreSQL",
    "lib/pq": "PostgreSQL", "jackc/pgx": "PostgreSQL", "mongoose": "MongoDB", "pymongo": "MongoDB", "prisma": "Prisma",
    "typeorm": "TypeORM", "gorm": "GORM", "anthropic": "Anthropic SDK (LLM)", "openai": "OpenAI SDK (LLM)",
    "langchain": "LangChain (LLM)", "@anthropic-ai/sdk": "Anthropic SDK (LLM)",
}

# Cloud resources declared in IaC: (provider/kind, compiled regex with group 1 = type, group 2 = name)
IAC_RESOURCES = [
    ("terraform", re.compile(r'^\s*resource\s+"([a-z0-9_]+)"\s+"([^"]+)"')),
    ("terraform-module", re.compile(r'^\s*module\s+"([^"]+)"()')),
    ("cloudformation", re.compile(r"^\s*(?:Type:\s*['\"]?)(AWS::[A-Za-z0-9:]+)()")),
    ("azure-bicep", re.compile(r"^\s*resource\s+(\w+)\s+'([^'@]+)@")),
    ("azure-arm", re.compile(r'"type"\s*:\s*"(Microsoft\.[A-Za-z]+/[A-Za-z/]+)"()')),
    ("gcp-dm", re.compile(r"^\s*-?\s*type:\s*['\"]?([a-z]+\.v\d+\.[A-Za-z]+)()")),
    ("kubernetes", re.compile(r"^kind:\s*(Service|Ingress|Deployment|StatefulSet|CronJob|NetworkPolicy|Secret|ConfigMap|Gateway|VirtualService)\b()")),
]
IAC_FILE = re.compile(r"\.(tf|bicep|jinja|jinja2)$|\.tf\.json$|\.(ya?ml|json)$")

# (kind, language set or None, pattern)
ENTRY = [
    ("main", {"go"}, r"^func main\(\)"),
    ("main", {"python"}, r"^if __name__\s*==\s*['\"]__main__['\"]"),
    ("main", {"rust"}, r"^\s*(pub\s+)?(async\s+)?fn main\(\)"),
    ("main", {"java", "kotlin"}, r"public static void main\(|^fun main\("),
    ("http", {"python"}, r"@(app|router|bp|api|blueprint)\.(get|post|put|patch|delete|route|api_route|websocket)\("),
    ("http", {"python"}, r"\bpath\(\s*['\"]|re_path\(|urlpatterns\s*="),
    ("http", {"javascript", "typescript"}, r"\b(app|router|server|fastify)\.(get|post|put|patch|delete|all|use|route)\(\s*['\"`]/"),
    ("http", {"javascript", "typescript"}, r"@(Get|Post|Put|Patch|Delete|Controller)\("),
    ("http", {"go"}, r"\.(HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Delete|Group)\(\s*\""),
    ("http", {"java", "kotlin"}, r"@(Get|Post|Put|Delete|Patch|Request)Mapping"),
    ("http", {"rust"}, r"#\[(get|post|put|delete|patch)\(|\.route\(\s*\""),
    ("grpc", None, r"Register\w+Server\(|add_\w+Servicer_to_server\(|server\.addService\(|@GrpcService"),
    ("cli", {"python"}, r"argparse\.ArgumentParser\(|@click\.(command|group)|typer\.Typer\("),
    ("cli", {"go"}, r"cobra\.Command\{|flag\.Parse\(\)|urfave/cli"),
    ("cli", {"javascript", "typescript"}, r"require\(['\"]commander['\"]\)|from ['\"]commander['\"]|yargs\("),
    ("cron", None, r"@(Scheduled|periodic_task|cron)\b|cron\.New\(|schedule\.every\(|node-cron|crontab|@app\.task|beat_schedule|CronJob\b|schedule:\s*['\"]?[\d*/]"),
    ("consumer", None, r"\.subscribe\(|\.consume\(|consumer\.run\(|KafkaConsumer\(|basic_consume\(|ReceiveMessage|\.on\(\s*['\"]message['\"]|NewReader\(|@KafkaListener|@RabbitListener|@SqsListener|ConsumeMessages|\.Consume\("),
    ("lambda", None, r"def (lambda_)?handler\(\s*event\s*,\s*context|exports\.handler\s*=|export (const|async function) handler|lambda\.Start\("),
    ("webhook", None, r"(?i)['\"`]/[^'\"`]*webhook[^'\"`]*['\"`]"),
]
EDGES = [
    ("http-client", r"requests\.(get|post|put|patch|delete|request)\(|httpx\.|aiohttp\.ClientSession|urllib\.request|fetch\(|axios[.(]|got\(|http\.(Get|Post|NewRequest)|resty\.|RestTemplate|WebClient|reqwest::"),
    ("grpc-client", r"New\w+Client\(|_pb2_grpc\.\w+Stub\(|\.\w+Client\(\s*['\"][^'\"]+:\d+|grpc\.(Dial|NewClient|insecure_channel|secure_channel)\("),
    ("graphql-client", r"gql`|graphql\(|ApolloClient|query\s*\{"),
    ("publish", r"\.(publish|produce|send|sendMessage|basic_publish|Publish|WriteMessages|SendMessage|put_record)\("),
    ("topic-or-queue", r"(?i)['\"](topic|queue|exchange|stream|subject)[-_.]?[^'\"]{0,40}['\"]|topic\s*[:=]\s*['\"][^'\"]+['\"]|QueueUrl|routing_key"),
    ("db", r"(?i)\b(SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b|\.execute\(|\.query\(|\.Exec\(|\.QueryRow\(|session\.(add|commit)|\.findOne\(|\.insertOne\(|db\.Collection\("),
    ("cache", r"(?i)redis\.|\.setex\(|\.hset\(|memcache|\bcache\.(get|set)\("),
    ("object-store", r"(?i)s3\.|put_object|getObject|PutObject|storage\.Client\(|BlobServiceClient|gcs"),
    ("subprocess", r"subprocess\.(run|Popen|call|check_output)|os\.system\(|child_process|exec\.Command\(|execSync\(|spawn\(|ProcessBuilder|Runtime\.getRuntime\(\)\.exec|std::process::Command"),
    ("ffi", r"ctypes\.|cffi|import \"C\"|extern \"C\"|ffi-napi|node-gyp|#\[no_mangle\]|JNI|cgo|pybind11|PyO3|wasm_bindgen"),
    ("generated-client", r"(?i)(generated|autogenerated|DO NOT EDIT|openapi-generator|swagger-codegen|protoc-gen)"),
    ("llm", r"(?i)anthropic\.|messages\.create\(|openai\.|chat\.completions|ChatOpenAI|ChatAnthropic|bedrock-runtime|generativeai"),
]
CONFIG = [
    ("env", r"os\.environ(\.get)?\s*[\[(]\s*['\"]([A-Z0-9_]+)|os\.getenv\(\s*['\"]([A-Z0-9_]+)|process\.env\.([A-Z0-9_]+)|process\.env\[['\"]([A-Z0-9_]+)|os\.Getenv\(\s*\"([A-Z0-9_]+)|System\.getenv\(\s*\"([A-Z0-9_]+)|env::var\(\s*\"([A-Z0-9_]+)|ENV\[['\"]([A-Z0-9_]+)"),
    ("flag", r"(?i)(feature[_-]?flag|is_enabled|isEnabled|unleash|launchdarkly|flipper|growthbook)\(?\s*['\"]?([\w.-]*)"),
]


def lang_of(rel: str) -> str | None:
    return LANG.get(Path(rel).suffix.lower())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--json-out")
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--max-per-kind", type=int, default=200)
    a = ap.parse_args()
    root = Path(a.root).resolve()
    key = a.key

    langs, loc = Counter(), Counter()
    manifests, infra, contracts, secret_files, binaries = [], [], [], [], []
    entries, edges, configs, cloud = [], [], [], []
    frameworks = {}
    compiled_entry = [(k, ls, re.compile(p, re.M)) for k, ls, p in ENTRY]
    compiled_edges = [(k, re.compile(p)) for k, p in EDGES]
    compiled_cfg = [(k, re.compile(p)) for k, p in CONFIG]

    def cite(rel, ln):
        return f"{key}/{rel}:{ln}"

    files = list(walk_files(root, a.exclude))
    for path, rel in files:
        base = rel.rsplit("/", 1)[-1]
        if is_secret_file(rel):
            secret_files.append(rel)
            continue
        if base in MANIFESTS or base.endswith((".csproj", ".sln")):
            manifests.append(rel)
        for kind, pat in INFRA:
            if pat.search(rel):
                infra.append({"kind": kind, "path": rel, "citation": cite(rel, 1)})
                break
        for kind, pat in CONTRACTS:
            if pat.search(rel):
                contracts.append({"kind": kind, "path": rel, "citation": cite(rel, 1)})
                break
        if is_binary(path):
            binaries.append(rel)
            continue
        lg = lang_of(rel)
        text = read_text(path)
        if text is None:
            continue
        lines = text.splitlines()
        if lg:
            langs[lg] += 1
            loc[lg] += len(lines)
        if base in ("package.json", "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml",
                    "build.gradle", "build.gradle.kts", "Gemfile", "composer.json"):
            for hint, name in FRAMEWORK_HINTS.items():
                m = re.search(r"(?im)(^|[\"'\s/])" + re.escape(hint) + r"[\"'\s=<>~^@:/\[]", text)
                if m:
                    frameworks.setdefault(name, cite(rel, text.count("\n", 0, m.start()) + 1))
        if IAC_FILE.search(rel):
            for i, ln in enumerate(lines, 1):
                for kind, pat in IAC_RESOURCES:
                    m = pat.search(ln)
                    if m and not (kind == "azure-arm" and not rel.endswith(".json")):
                        typ, nm = (m.group(2), m.group(1)) if kind == "azure-bicep" else (m.group(1), m.group(2) or "")
                        cloud.append({"kind": kind, "type": typ, "name": nm, "citation": cite(rel, i)})
                        break
        if not lg or lg in ("sql", "terraform", "protobuf", "graphql"):
            continue
        for i, ln in enumerate(lines, 1):
            if len(ln) > 400:
                continue
            for kind, ls, pat in compiled_entry:
                if (ls is None or lg in ls) and pat.search(ln):
                    entries.append({"kind": kind, "language": lg, "citation": cite(rel, i), "text": redact_text(ln.strip())[:120]})
                    break
            for kind, pat in compiled_edges:
                if pat.search(ln):
                    edges.append({"kind": kind, "language": lg, "citation": cite(rel, i), "text": redact_text(ln.strip())[:120]})
            for kind, pat in compiled_cfg:
                m = pat.search(ln)
                if m:
                    if kind == "env":
                        name = next((g for g in m.groups() if g and re.fullmatch(r"[A-Z0-9_]+", g)), "")
                    else:
                        name = m.group(2) or ""
                    configs.append({"kind": kind, "name": name, "citation": cite(rel, i), "text": redact_text(ln.strip())[:120]})

    def cap(items):
        by = Counter()
        out = []
        for it in items:
            by[it["kind"]] += 1
            if by[it["kind"]] <= a.max_per_kind:
                out.append(it)
        return out, {k: v for k, v in by.items() if v > a.max_per_kind}

    entries, e_trunc = cap(entries)
    edges, g_trunc = cap(edges)
    rep = {
        "repo": key, "root": str(root), "generated": now_iso(), "files": len(files),
        "languages": [{"language": k, "files": v, "lines": loc[k]} for k, v in langs.most_common()],
        "manifests": sorted(manifests), "frameworks": [{"name": k, "citation": v} for k, v in sorted(frameworks.items())],
        "infra": infra, "cloud_resources": cloud[: a.max_per_kind * 3], "contracts": contracts, "entry_point_candidates": entries, "edge_candidates": edges,
        "config_candidates": configs[: a.max_per_kind * 2],
        "excluded": {"secret_files_not_read": secret_files, "binaries": binaries[:200],
                     "symlinks_not_followed": list(walk_symlinks(root))},
        "truncated": {"entry_points": e_trunc, "edges": g_trunc},
        "note": "All candidates are regex matches. Open each cited line and confirm before stating as fact.",
    }
    js = json.dumps(rep, indent=2)
    if a.json_out:
        Path(a.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json_out).write_text(js + "\n")
        print(json.dumps({"repo": key, "files": len(files), "languages": dict(langs), "entry_points": len(entries),
                          "edges": len(edges)}))
    else:
        print(js)
    return 0


if __name__ == "__main__":
    sys.exit(main())
