# RecallFence

Multi-tenant agentic memory with the isolation boundary in the database rather
than in application code.

An agent that remembers across sessions has to store what it learned somewhere,
and in a multi-tenant product that store is one forgotten `WHERE` clause away
from serving one customer's memory to another. The usual answer is to be careful
in application code. RecallFence puts the boundary in CockroachDB row-level
security instead, then tries to break it on purpose and emits a hash-chained
receipt saying whether it held. Hash-chained, not signed: there is no key and no
signature anywhere in this project, and the tamper-evidence claims below are
scoped to exactly what SHA-256 linkage can support.

What makes that more than an assertion: a deterministic breach harness that
probes the system from every tenant's own credentials, a repair loop that
separates *exposure* from *contamination*, and a hash-chained receipt that a
third party can verify without trusting this repo or the bucket it is stored in.

## The result

Measured on a live CockroachDB Cloud cluster, 8 tenants, 8,001 seeded memories
(7,945 remain in `memories` once quarantine moves 56), `VECTOR(1024)` embeddings,
4 probe types run under each tenant's own login:

```
  principal  probe                baseline  post_rls  post_quarantine
  --------------------------------------------------------------
  alice      direct_id            HIT       ok        ok
  alice      semantic_filtered    ok        ok        ok
  alice      semantic_unfiltered  HIT       ok        ok
  alice      side_channel         ok        ok        ok
  ...  (8 principals x 4 probes x 3 phases = 96 recorded results)

  43 foreign rows at baseline, 0 after RLS, 0 after quarantine.
```

`semantic_filtered` reading `ok` even at baseline is deliberate and is the most
important row in the table. The correctly scoped query was never the problem. The
product exists because the filter on the line above it gets forgotten, and a
matrix where every row failed would prove only that the fixture was broken.

## What a pass actually requires

"No leaks after the fix" is a rubber stamp: a harness that errored silently and
recorded nothing also produces no leaks. A receipt passes only when all four
hold:

1. At least one breach at baseline. The failure has to be demonstrated before its
   absence means anything.
2. Zero breaches after RLS and after quarantine, across every principal and every
   probe type.
3. The auditor still saw the foreign rows at `post_rls`. RLS hiding a row and
   something having deleted the row both produce "zero rows returned". Without
   independent ground truth, a receipt cannot tell a working boundary from an
   emptied table.
4. Every probe in every counted phase has `status = ok`. Fail closed. An
   unexecuted probe is not a passed probe.

Clause 1 is the one that gets forgotten. Clause 3 is the one that makes the
result mean anything.

## Exposure and contamination are different problems

RLS repairs **exposure**: rows that were readable and should not have been.
Quarantine repairs **contamination**: rows that are *wrong*, because they were
written under the wrong tenant, or derived by an agent that had just read a
foreign row.

Keeping them apart is why there are two reruns rather than one. If cleanup ran
first, "no rows returned" would prove nothing, because an emptied table returns
nothing either. Probing after the fence goes up but before the cleanup is what
makes the two effects separable in the receipt.

It also decides what quarantine refuses to touch. Bob's refund ceiling leaked at
baseline and is correct data, correctly attributed to Bob. The defect was in
Alice's query path. Deleting Bob's memory to fix Alice's bug would be a worse bug
than the one being fixed, so exposure alone is never a reason to quarantine
anything. Checkable in the committed bundle: two of Bob's rows were exposed at
baseline, `222075f5` and `60e6eb00`, and neither appears in `quarantine`. Bob's
rows are not absent from it wholesale, and should not be. Ten rows attributed to
Bob were moved, every one for a provenance defect rather than for having leaked.

Contamination is a predicate on provenance, not a phrase match:

| Class | Reason code | Predicate |
|---|---|---|
| 1 | `misattributed_write` | `origin_tenant <> tenant` |
| 2 | `derived_from_foreign_read` | written in a session whose retrieval log returned a foreign row |

Measured: 24 and 32 respectively, 56 rows moved in one transaction, 0 remaining.

## The receipt

The artifact someone else keeps. It carries the full 96-row breach matrix, the
exact policy SQL that repaired the leak, the quarantined row IDs with reason
codes, the four-clause verdict, and a SHA-256 that chains it to its predecessor.

Tamper-evidence comes from the chain, not from the bucket. A changefeed writing
to S3 proves delivery, not integrity: anyone who can write the bucket, including
the changefeed's own IAM principal, can overwrite an object.

| Attack | Caught by |
|---|---|
| Edit a receipt body | Its own link: the stored hash no longer matches the body |
| Edit a body *and* recompute its hash | The **next** receipt, which committed to the old hash |
| Rewrite the entire suffix | Nothing internal. Only an external anchor |

The third row is stated rather than papered over, and `tests/test_receipt_chain.sh`
asserts it: a fully rewritten chain is internally consistent and verifies clean.
What convicts it is a head hash kept somewhere the attacker cannot reach, which
is what `audit/verify.sh --head` is for.

## Quickstart

Requires a CockroachDB connection URL, `jq`, and either a `cockroach` binary or
Apple's `container` runtime. Per-role credentials come from AWS Secrets Manager
at run time; nothing credential-shaped is in this repo.

```bash
export RF_CLUSTER_URL='postgresql://...'      # admin URL, never commit it

./schema/apply.sh tables
./schema/apply.sh roles alice bob carol ...   # asserts non-privileged, aborts if not
./fixtures/seed.sh plan && ./fixtures/seed.sh embed && ./fixtures/seed.sh load
./schema/apply.sh policies                    # order matters, see below

./harness/freeze.sh                           # pin the probe query vectors
./harness/run.sh baseline                     # probe the un-repaired system
./repair/loop.sh <baseline-run-id> --approve  # policy, rerun, quarantine, rerun
./audit/receipt.sh emit <baseline> <post_rls> <post_quarantine>

./cli/rf all                                  # every panel
./audit/verify.sh                             # recompute the hash chain
```

No cluster needed to see the recorded result or to exercise the chain:

```bash
./cli/rf --from web/public/replay.json all
./tests/test_receipt_chain.sh                 # 18 cases, hermetic
```

**Schema order is load-bearing.** Tables, then roles, then the fixture loader,
then policies. Under `FORCE ROW LEVEL SECURITY` an operation with no applicable
policy is denied for every role including the table owner, so seeding after the
fence goes up would require a policy that exists only to let the seeder cheat.
`schema/apply.sh` has no `all` subcommand for exactly this reason.

## Layout

```
schema/     tables, five role classes, the policy set, the changefeed
fixtures/   corpus, canaries, and both contamination classes, seeded deterministically
harness/    the four probes, auditor ground truth, the breach matrix
repair/     policy gate, quarantine mover, the two reruns
audit/      receipt writer, hash chain, chain verification
cli/        the same evidence as the dashboard, no web dependency
tests/      policy enforcement per role per operation, and chain tamper detection
web/        replay dashboard, rendered from a committed snapshot
docs/       architecture.md, three diagrams: the boundary, the proof, the receipt
```

[`docs/architecture.md`](docs/architecture.md) has three diagrams: where the
boundary sits, how a pass is constructed, and what the receipt is worth once
someone else is holding it.

## CockroachDB tools and AWS services used

### CockroachDB

| Tool | Where | What it does here |
|---|---|---|
| **Distributed vector indexing** | `schema/001_tables.sql` | `VECTOR(1024)` on `memories` and `quarantined_memories`, indexed `ON memories (tenant, embedding vector_l2_ops)`. Backs the `semantic_unfiltered` and `semantic_filtered` probes, and produced the measured finding that under `FORCE ROW LEVEL SECURITY` the index stops being usable and retrieval degrades to an exact full scan. |
| **ccloud CLI (agent-ready)** | `schema/apply.sh`, `schema/lib/crsql.sh` | Resolves how to reach the cluster and drives schema application non-interactively. `schema/lib/crsql.sh` falls back to a containerised client on machines with no native binary. |

Row-level security is the boundary itself, applied in `schema/004_policies.sql`
and asserted in `schema/005_assert_roles.sql.tmpl`, which refuses to continue if
any managed role comes back `rolsuper`, `rolbypassrls`, or a member of `admin`.

`mcp/server.py` is a read-only MCP server this project ships so an agent can
query the breach matrix and verify a receipt. It is written against the MCP
stdio protocol directly and is **not** CockroachDB's Cloud Managed MCP Server,
so it is listed here for completeness rather than counted as one of the two
required tools.

### AWS

| Service | Where | What it does here |
|---|---|---|
| **Amazon S3** | `schema/006_changefeed.sql.tmpl`, `audit/verify.sh` | A CockroachDB changefeed streams the `receipts` table to S3 as NDJSON with `resolved` markers, so silence in the bucket means the feed died rather than nothing having happened. `audit/verify.sh --from-s3` re-verifies the whole hash chain straight from the bucket with no cluster reachable; plain `audit/verify.sh` reads the database instead. |
| **AWS Secrets Manager** | `schema/apply.sh`, `tests/`, `agent/` | Every role's credentials are fetched at run time. Tests connect over each role's own credentials rather than `SET ROLE` from a shared admin session. Nothing credential-shaped is in the repo. |
| **AWS IAM** | `infra/provision.sh` | Mints the changefeed's write-only principal: `ListBucket` conditioned on the prefix, and an explicit `Deny` on every delete action, so the audit sink is append-only against its own writer. |
| **Amazon Bedrock** | `agent/lib/model.sh`, `fixtures/embed.sh` | A chat model phrases audit summaries whose facts are computed in SQL. Two endpoints answer differently here: **bedrock-mantle works** and serves `google.gemma-4-31b`, which `model.sh` uses by default; **classic `bedrock-runtime` is restricted on this account** to 0 TPM, and that is the endpoint serving Titan embeddings. `fixtures/embed.sh` targets Titan when reachable and otherwise falls back, which on this account means always. Every receipt records the model ID that produced it. |

Only S3, Secrets Manager and IAM are load-bearing. Bedrock changes embedding and
prose quality, not any result the receipt asserts.

## Two enforcement layers that answer in opposite ways

Worth stating because it shapes every test in this repo. Privileges are checked
before policies:

| Situation | Signal |
|---|---|
| No table privilege | Hard error, SQLSTATE 42501 |
| Privilege held, no applicable policy | Zero rows affected, **no error** |

So "I caught an exception" is not evidence of being blocked. The tests compare
affected-row counts against expectation. A stray `GRANT` converts a loud failure
into a silent one without changing a single policy, which is why the harness
probes the evidence tables from every tenant role in every phase even though the
privilege layer already refuses them.

Tenant roles are flat, with no group memberships, so `SET ROLE` fails and
`RESET ROLE` leaves the connection fenced. Tests connect over each role's own
credentials rather than using `SET ROLE` from a shared admin session, because a
session that can `SET ROLE` can also `RESET ROLE` and the fence would be one
statement deep.

## Honest status

- The corpus in the committed snapshot is embedded with `local-hash-v1`, a
  deterministic local fallback, not Amazon Titan. The fallback is unit-normalized
  and reproducible but carries no semantic structure, so nearest-neighbour results
  are arbitrary rather than meaningful. Every receipt records the model ID it was
  built with, so a receipt cannot present fallback vectors as Titan.
- This is a split between two Bedrock endpoints, not a blanket outage. Agent prose
  runs on a real model, `google.gemma-4-31b` served by the bedrock-mantle endpoint,
  which `agent/lib/model.sh` uses by default. Embeddings are what falls back, for
  two separate reasons: classic `bedrock-runtime`, the endpoint that serves Titan,
  is restricted on this account to 0 TPM on every model; and while bedrock-mantle
  does expose a working `/v1/embeddings` route, its catalogue for this account
  carries 55 models and not one of them is an embedding model, so the route has
  nothing to serve. Both were verified by request, not inferred.
- This is why a breach is scored on "returned a row belonging to another tenant"
  rather than on canary phrases. A phrase-only score reported a 35-row
  cross-tenant leak in `semantic_unfiltered` as clean, because the arbitrary
  nearest neighbours carried no marked phrase. The canary phrase is still
  recorded, as corroboration.
- With RLS active, the vector index on `(tenant, embedding)` is not usable and
  reads become exact full scans. That is a real cost of the boundary, measured
  rather than hidden, and the demo says so out loud.

## License

MIT. See [LICENSE](LICENSE).
