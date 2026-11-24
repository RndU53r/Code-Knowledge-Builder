#!/usr/bin/env python3
"""Generate the self-contained interactive graph viewer: <out>/graph/index.html

Usage:
  graph_viewer.py --out OUT_DIR [--cap 5000]

Vanilla JS, no CDN, no network: the graph JSON is embedded (with `</`, `<!--` and U+2028/2029 escaped)
and a strict Content-Security-Policy allows only the hashed inline script and style. Target-derived
strings are rendered with textContent only. graph_serve.py reuses render() for live mode.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from graph_common import atomic_write, graph_dir  # noqa: E402

VIEWER = HERE.parent / "shared" / "viewer"


def safe_json(obj) -> str:
    s = json.dumps(obj, separators=(",", ":"))
    return s.replace("</", "<\\/").replace("<!--", "<\\!--").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def sha(s: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'"


def render(graph: dict, live: dict | None = None, cap: int = 5000) -> str:
    html = (VIEWER / "viewer.html").read_text()
    css = (VIEWER / "viewer.css").read_text()
    js = (VIEWER / "viewer.js").read_text()
    data = {"graph": graph, "cap": cap}
    if live:
        data["live"] = live
    connect = "'self'" if live else "'none'"
    csp = (f"default-src 'none'; script-src {sha(js)}; style-src {sha(css)}; img-src data:; connect-src {connect}; "
           "base-uri 'none'; form-action 'none'")  # frame-ancestors only works as a header (server sends X-Frame-Options)
    # replace data last so placeholder-like text inside target strings can't inject markup
    out = html.replace("__CSP__", csp).replace("__CSS__", css).replace("__JS__", js)
    return out.replace("__DATA__", safe_json(data))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cap", type=int, default=5000)
    a = ap.parse_args()
    out = Path(a.out).resolve()
    graph = json.loads((graph_dir(out) / "graph.json").read_text())
    p = graph_dir(out) / "index.html"
    atomic_write(p, render(graph, cap=a.cap))
    print(json.dumps({"viewer": str(p), "nodes": len(graph["nodes"]), "edges": len(graph["edges"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
