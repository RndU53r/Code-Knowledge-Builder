#!/usr/bin/env python3
"""Live (dynamic) graph viewer: a local, read-only HTTP server over the ckb graph.

Usage:
  graph_serve.py --out OUT_DIR [--port 0] [--no-open]

- Binds 127.0.0.1 only, random port by default; prints the URL including a one-time random token.
- Every request needs the token (?token= or X-CKB-Token header); GET/HEAD only; Host header must be
  127.0.0.1/localhost (DNS-rebinding guard); strict CSP; no file serving beyond the viewer and API.
- /            the viewer (same as graph/index.html) in live mode: it polls /api/status and reloads
               the graph when graph.sqlite changes (e.g. after /ckb:update or the auto-update hook)
- /api/<op>    GraphStore ops (status, search, explain, neighbors, path, impact, taint, tour, subgraph,
               graph); arguments as query parameters (lists comma-separated)
"""
from __future__ import annotations

import argparse
import hmac
import json
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from graph_common import resolve_out  # noqa: E402
from graph_query import GraphStore  # noqa: E402
from graph_viewer import render  # noqa: E402

LIST_ARGS = {"kinds", "targets", "ids"}
ALLOWED_OPS = {"status", "search", "node", "explain", "neighbors", "path", "impact", "taint", "tour", "subgraph", "graph", "callgraph", "roles", "entrypoints"}


def make_handler(store: GraphStore, token: str, port_ref: dict):
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        server_version = "ckb-graph"
        sys_version = ""

        def log_message(self, fmt, *args):  # keep tokens out of logs
            return

        def _send(self, code, body: bytes, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            if ctype == "application/json":
                self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _deny(self, code, msg):
            self._send(code, json.dumps({"error": msg}).encode())

        def _authorized(self, qs):
            host = (self.headers.get("Host") or "").split(":")[0]
            if host not in ("127.0.0.1", "localhost"):
                return False, (421, "bad host")
            supplied = self.headers.get("X-CKB-Token") or (qs.get("token") or [""])[0]
            if not hmac.compare_digest(supplied, token):
                return False, (403, "token required")
            return True, None

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            ok, err = self._authorized(qs)
            if not ok:
                return self._deny(*err)
            with lock:
                store.refresh()
            if u.path in ("/", "/index.html"):
                g = json.loads((store.out / "graph" / "graph.json").read_text())
                cgp = store.out / "graph" / "callgraph.json"
                cg = json.loads(cgp.read_text()) if cgp.is_file() else None
                return self._send(200, render(g, live={"token": token}, callgraph=cg).encode(), "text/html")
            if u.path.startswith("/api/"):
                op = u.path[5:]
                if op not in ALLOWED_OPS:
                    return self._deny(404, "unknown op")
                if op == "graph":
                    return self._send(200, (store.out / "graph" / "graph.json").read_bytes())
                args = {}
                for k, v in qs.items():
                    if k == "token":
                        continue
                    args[k] = v[0].split(",") if k in LIST_ARGS else v[0]
                if op == "explain" and "target" not in args and "id" in args:
                    args["target"] = args["id"]
                if op == "search" and "q" not in args:
                    args["q"] = ""
                with lock:
                    res = store.dispatch(op, args)
                if op == "status":
                    res["generated"] = store.meta.get("generated")
                return self._send(200, json.dumps(res, default=str).encode())
            return self._deny(404, "not found")

        do_HEAD = do_GET

        def do_POST(self):
            self._deny(405, "read-only")

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_POST

    return H


def serve(out: Path, port: int = 0, open_browser=True, ready=None):
    store = GraphStore(out)
    token = secrets.token_urlsafe(24)
    ref = {}
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(store, token, ref))
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?token={token}"
    ref["port"] = httpd.server_address[1]
    print(json.dumps({"url": url, "note": "local, read-only; stop with Ctrl-C"}), flush=True)
    if ready:
        ready(httpd, token)
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    try:
        serve(resolve_out(a.out), a.port, not a.no_open)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
