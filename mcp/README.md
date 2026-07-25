# mcp/

The auditor's read-only surface, as a Model Context Protocol server.

```bash
# live, as rf_auditor, credentials from Secrets Manager
RF_CLUSTER_URL=... python3 mcp/server.py

# cluster-free, from the committed replay snapshot
RF_MCP_BUNDLE=web/public/replay.json python3 mcp/server.py
```

Register it with any MCP client (`claude mcp add recallfence-auditor -- python3 /abs/path/mcp/server.py`) and it exposes six tools:

| Tool | Returns |
|---|---|
| `get_receipt` | The verdict, the four pass clauses, per-phase counts |
| `get_breach_matrix` | Principal x probe x phase, whether each leaked |
| `get_breach_evidence` | The exact foreign rows at baseline, with provenance |
| `get_quarantine` | Rows moved out, with reason codes and lineage |
| `get_policy_set` | The installed RLS policies and the SQL the receipt attests |
| `verify_chain` | Recompute the hash chain from the receipts and report |

## Why this is safe to expose, structurally

Two properties, both enforced by construction rather than by prompt:

**Every query runs as `rf_auditor`.** That account is read-only over the evidence
tables and append-only over receipts. The server holds no privilege wider than
the account it connects as, so no tool, and no clever instruction to a tool, can
delete a memory or read one it should not. The credential cannot, whatever the
model is asked to do.

**The tool set is a fixed allow-list.** There is deliberately no "run this SQL"
tool. A general query tool would move the isolation boundary back into this
process's judgment, which is the exact mistake this project exists to point at.
Every tool is a named, typed read.

It is never on the tenant data path. It is an additional surface on top of the
direct-SQL auditor read path, not a replacement for it, and the design keeps it
off the critical path: the required-technology gate does not depend on it.

## One artifact, three renderers

The server shells out to `cli/rf` for the evidence bundle rather than
reimplementing the assembly query, so the MCP surface, the CLI and the dashboard
all read the same bundle and cannot drift into telling different stories.

`verify_chain` is the exception, because verification recomputes every link from
the stored receipt bodies, which a rendered bundle does not carry. It reads the
receipts directly, and in snapshot mode it says so plainly rather than returning
a confident-looking failure.

## No dependencies

Stdlib Python only: JSON-RPC 2.0 over stdio, no MCP SDK, no `pip install`. It runs
anywhere `python3` does. A malformed request line gets a JSON-RPC parse error
(`-32700`), never silence, for the same reason everything else in this project
asserts the reason a thing failed rather than only that it did.

## Relation to the Cloud Managed MCP Server

The design notes a CockroachDB Cloud Managed MCP Server as a possible third named
tool. That depends on a vendor spike that has not been run, so this is the
concrete, dependency-free surface that makes the MCP claim real today. If the
managed offering lands, it layers alongside this rather than replacing it.
