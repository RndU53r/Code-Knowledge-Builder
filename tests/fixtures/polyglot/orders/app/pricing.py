import json
import os
import subprocess

PRICING_BIN = os.environ.get("PRICING_BIN", "/usr/local/bin/pricing")


def price_items(items):
    """Calls the Go pricing binary (fulfillment/cmd/pricing) over stdin/stdout."""
    proc = subprocess.run([PRICING_BIN, "--json"], input=json.dumps(items), capture_output=True, text=True, timeout=5)
    if proc.returncode != 0:
        raise RuntimeError("pricing failed")
    return json.loads(proc.stdout)["total_cents"]
