# Architecture

Three diagrams. The first shows where the fence sits, the second shows how the
proof is constructed, the third shows what the receipt is worth once someone
else is holding it.

They render on GitHub directly. Source is in this file, so a diagram that drifts
from the code is a diff, not a stale PNG nobody can edit.

`docs/diagrams/` holds the same three as `.mmd` source plus exported `.svg` and
`.png`, for places that cannot render Mermaid. Regenerate them after editing this
file rather than editing the exports:

```bash
awk '/^```mermaid$/{n++; b=1; next} /^```$/{b=0} b{print > ("docs/diagrams/tmp-" n ".mmd")}' docs/architecture.md
# then rename tmp-1..3 over the existing .mmd files and:
npx -y @mermaid-js/mermaid-cli@11 -i docs/diagrams/NAME.mmd -o docs/diagrams/NAME.png -b white -w 1800 -s 2
```

## 1. Where the boundary lives

Every caller connects with its own credentials, fetched from Secrets Manager at
run time. There is no shared admin session that later drops privileges, because
a session that can `SET ROLE` can also `RESET ROLE`, and the fence would be one
statement deep.

```mermaid
flowchart TB
    subgraph callers["Callers, each with its own login"]
        T["8 tenant roles<br/>flat, no group membership"]
        AG["rf_agent<br/>writes the retrieval log"]
        H["rf_harness<br/>runs the probes"]
        AU["rf_auditor<br/>independent ground truth"]
        RM["rf_remediation<br/>moves rows to quarantine"]
    end

    SM[["AWS Secrets Manager<br/>per-role credentials, nothing in the repo"]]

    P{{"5 policies under FORCE ROW LEVEL SECURITY<br/>tenant_isolation, tenant_write, auditor_read, remediation_read, quarantine_delete"}}

    subgraph crdb["CockroachDB Cloud"]
        M[("memories<br/>VECTOR 1024, indexed vector_l2_ops")]
        R[("retrievals")]
        Q[("quarantined_memories")]
        RC[("receipts, append-only")]
    end

    S3[["Amazon S3<br/>NDJSON plus resolved markers"]]
    V["audit/verify.sh<br/>re-verifies the chain with no cluster reachable"]

    SM -.->|"role password at run time"| callers
    T --> P
    AG --> P
    H --> P
    AU --> P
    RM --> P
    P --> M
    P --> R
    P --> Q
    P --> RC
    RC -->|"changefeed, envelope wrapped"| S3
    S3 --> V
```

The auditor is the part that is easy to leave out and expensive to omit. RLS
hiding a row and something having deleted the row both produce "zero rows
returned". Without a principal that can still see the rows, a clean result
cannot be told apart from an emptied table.

## 2. How a pass is constructed

Three phases, because exposure and contamination are different defects and
collapsing them would make the result unreadable. If cleanup ran before the
second probe, "no rows returned" would prove nothing.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 560}}}%%
flowchart TB
    S["Seed 8,001 memories across 8 tenants,<br/>including both contamination classes"]
    S --> B["<b>Phase 1: baseline</b>, RLS off<br/>32 probes: 16 breaches, 43 foreign rows"]
    B --> P2["<b>Phase 2: post_rls</b><br/>after ENABLE plus FORCE ROW LEVEL SECURITY<br/>32 probes: 0 breaches, and the auditor still sees the rows"]
    P2 --> P3["<b>Phase 3: post_quarantine</b><br/>after the mover relocates 56 rows in one transaction<br/>32 probes: 0 breaches, and Bob's correct rows are untouched"]
    P3 --> G{"c1 c2 c3 c4<br/>all hold?"}
    G -->|yes| PASS["Receipt: passed"]
    G -->|no| FAIL["Receipt: failed"]
```

Clause 1 is the one that gets forgotten. A harness that errored silently and
recorded nothing also produces no leaks, so the failure has to be demonstrated
before its absence means anything.

Clause 3 is the one that makes the number mean something.

## 3. What the receipt is worth to a stranger

Delivery is not integrity. A changefeed writing to S3 proves the object arrived,
not that it says what it said yesterday. Anyone who can write the bucket,
including the changefeed's own IAM principal, can overwrite an object.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 460}}}%%
flowchart TB
    R1["<b>receipt n-1</b><br/>hash H1"]
    R2["<b>receipt n</b><br/>H2 = SHA-256 of canonical body plus H1"]
    R3["<b>receipt n+1</b><br/>H3 = SHA-256 of canonical body plus H2"]
    ANCHOR["<b>External anchor</b><br/>head hash kept somewhere<br/>the attacker cannot reach"]

    R1 -->|"prev = H1"| R2
    R2 -->|"prev = H2"| R3
    R3 -.->|"audit/verify.sh --head"| ANCHOR
```

What each attack runs into:

| Attack | Caught by |
|---|---|
| Edit a receipt body | Its own link. The stored hash no longer matches the body |
| Edit a body and recompute its hash | The next receipt, which committed to the old hash |
| Delete a receipt from the middle | The orphaned successor, whose `prev` names a hash that is no longer present |
| Rewrite the entire suffix | Nothing internal. Only the external anchor |

The last row is the limit of what a chain can do alone, and
`tests/test_receipt_chain.sh` asserts it: a fully rewritten chain is internally
consistent and verifies clean. That is what `--head` is for. A total rewrite is
caught only by a head hash pinned outside the system.
