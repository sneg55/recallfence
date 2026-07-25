#!/usr/bin/env python3
"""RecallFence: the auditor's read-only surface, as an MCP server.

A Model Context Protocol server over stdio (JSON-RPC 2.0), exposing exactly what
the auditor agent can already see: the receipt, the breach matrix, the leaked
rows with provenance, and the hash-chain verdict. It is an additional surface on
top of the direct-SQL auditor read path, never a replacement for it, and it is
never on the tenant data path.

Two properties are load-bearing and both are enforced structurally, not by
prompt:

  * Every query runs as rf_auditor, whose grants are read-only over evidence and
    append-only over receipts. The MCP server holds no wider privilege than the
    account it connects as, so a tool cannot be talked into deleting a memory:
    the credential simply cannot.

  * The tool set is a fixed allow-list of named, parameterless-or-typed reads.
    There is no "run this SQL" tool. A general query tool would move the boundary
    back into this process's judgment, which is the exact mistake the project
    exists to point at.

Stdlib only, no MCP SDK and no pip install, so it runs anywhere python3 does.
It shells out to cli/rf for the evidence bundle rather than reimplementing the
assembly query, so the MCP surface and the CLI and the dashboard all read the
same artifact and cannot drift.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RF = str(ROOT / "cli" / "rf")
VERIFY = str(ROOT / "audit" / "verify.sh")

# Snapshot-first, like the rest of the project. If RF_MCP_BUNDLE names a committed
# replay snapshot, every tool renders from it and the server needs no cluster and
# no credentials. Unset, it reads live from the cluster as rf_auditor. Either way
# it is the same bundle the CLI and the dashboard use.
BUNDLE_FILE = os.environ.get("RF_MCP_BUNDLE") or None

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "recallfence-auditor", "version": "1.0.0"}


# --- the evidence bundle, fetched once and cached for the process -----------

_bundle_cache = {}


def bundle(from_file=None):
    key = from_file or "__db__"
    if key in _bundle_cache:
        return _bundle_cache[key]
    cmd = [RF]
    if from_file:
        cmd += ["--from", from_file]
    cmd += ["snapshot", "/dev/stdout"]
    # `rf snapshot` writes the bundle as JSON and a two-line human summary to
    # stdout after it. Parse the leading JSON object and ignore the trailing
    # lines rather than depending on their exact wording.
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "rf snapshot failed")
    data = _leading_json(out.stdout)
    _bundle_cache[key] = data
    return data


def _leading_json(text):
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(text.lstrip())
    return obj


# --- tools: a fixed allow-list ----------------------------------------------


def tool_receipt(_args):
    b = bundle(BUNDLE_FILE)
    r, m = b["receipt"], b["receipt_meta"]
    return {
        "passed": r["passed"],
        "clauses": r["clauses"],
        "phases": r["phases"],
        "receipt_id": m["receipt_id"],
        "receipt_hash": m["receipt_hash"],
        "prev_receipt_hash": m.get("prev_receipt_hash"),
        "emitted_at": m["emitted_at"],
        "embedding_model": r.get("embedding_model"),
        "breach_definition": r.get("breach_definition"),
    }


def tool_matrix(_args):
    b = bundle(BUNDLE_FILE)
    rows = {}
    for e in b["evidence"]:
        k = (e["principal"], e["probe_type"])
        rows.setdefault(k, {"principal": e["principal"], "probe_type": e["probe_type"]})
        rows[k][e["phase"]] = {
            "breach": e.get("breach"),
            "foreign_rows": e.get("foreign_rows"),
            "status": e.get("status"),
        }
    return {"matrix": list(rows.values()), "phases": b["receipt"]["phases"]}


def tool_evidence(_args):
    b = bundle(BUNDLE_FILE)
    prov = {p["id"]: p for p in b.get("provenance", [])}
    hits = []
    for e in b["evidence"]:
        if e["phase"] != "baseline" or not e.get("breach") or e["probe_type"] == "side_channel":
            continue
        rows = []
        for row in e.get("returned", []):
            if not row.get("tenant") or row["tenant"] == e["principal"]:
                continue
            p = prov.get(row["id"], {})
            rows.append({
                "id": row["id"], "tenant": row["tenant"],
                "origin_tenant": p.get("origin_tenant"),
                "session_id": p.get("session_id"),
                "source": p.get("source"), "trust": p.get("trust"),
                "quarantined": p.get("quarantined", False),
                "content": row.get("content"),
            })
        if rows:
            hits.append({"principal": e["principal"], "probe_type": e["probe_type"],
                         "foreign_rows": rows})
    return {"breaches": hits}


def tool_quarantine(_args):
    b = bundle(BUNDLE_FILE)
    return {"summary": b["receipt"].get("quarantine", {}),
            "rows": b.get("quarantine", [])}


def tool_policy(_args):
    b = bundle(BUNDLE_FILE)
    return {"installed": b["rls"].get("policies", []),
            "enabled": b["rls"].get("enabled"),
            "forced": b["rls"].get("forced"),
            "policy_sql": b["receipt"].get("policy_sql"),
            "policy_sql_sha256": b["receipt"].get("policy_sql_sha256")}


def tool_verify_chain(_args):
    # Verification recomputes every link from the stored receipt bodies, which the
    # rendered bundle does not carry, so this reads the receipts directly. In
    # snapshot mode there is no cluster to read, and saying so plainly beats
    # returning a confident-looking failure.
    if BUNDLE_FILE:
        return {"ok": None,
                "note": "verify_chain reads the receipts themselves and needs the "
                        "cluster or an NDJSON export. In snapshot mode the receipt "
                        "verdict in get_receipt is available, but the chain is "
                        "verified with audit/verify.sh, not from a rendered bundle."}
    out = subprocess.run([VERIFY], capture_output=True, text=True, timeout=120)
    return {"ok": out.returncode == 0,
            "report": out.stdout.strip(),
            "error": out.stderr.strip() or None}


TOOLS = {
    "get_receipt": (tool_receipt,
                    "The latest isolation receipt: verdict, the four pass clauses, and per-phase counts."),
    "get_breach_matrix": (tool_matrix,
                          "The breach matrix: for each principal and probe type, whether it leaked in each phase."),
    "get_breach_evidence": (tool_evidence,
                            "The exact foreign rows that leaked at baseline, each with its provenance."),
    "get_quarantine": (tool_quarantine,
                       "Rows moved out of memories, with reason codes and lineage."),
    "get_policy_set": (tool_policy,
                       "The row-level security policies installed, and the SQL the receipt attests."),
    "verify_chain": (tool_verify_chain,
                     "Recompute the receipt hash chain from the receipts alone and report whether it verifies."),
}


def tools_schema():
    return [{
        "name": name,
        "description": desc,
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    } for name, (_fn, desc) in TOOLS.items()]


# --- JSON-RPC 2.0 over stdio ------------------------------------------------


def handle(req):
    method = req.get("method")
    rid = req.get("id")

    if method == "initialize":
        return ok(rid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })

    if method == "notifications/initialized":
        return None  # notification, no response

    if method == "tools/list":
        return ok(rid, {"tools": tools_schema()})

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        entry = TOOLS.get(name)
        if not entry:
            return err(rid, -32602, f"unknown tool: {name}")
        try:
            result = entry[0](params.get("arguments") or {})
            text = json.dumps(result, indent=2, default=str)
            return ok(rid, {"content": [{"type": "text", "text": text}], "isError": False})
        except Exception as exc:  # a tool failure is data, not a transport error
            return ok(rid, {"content": [{"type": "text", "text": f"error: {exc}"}],
                            "isError": True})

    if rid is None:
        return None  # unknown notification
    return err(rid, -32601, f"method not found: {method}")


def ok(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def err(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            # A malformed line gets a JSON-RPC parse error, not silence. In a
            # project whose whole point is that swallowed errors hide the thing
            # that matters, a server that ate bad input would be the wrong
            # example to set. id is null per the spec when the request could not
            # be parsed.
            resp = err(None, -32700, f"parse error: {exc}")
        else:
            resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
