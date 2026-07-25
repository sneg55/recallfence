# harness/

The breach matrix. Four probes, per tenant, per phase, recorded with ground
truth and an explicit status.

Run end to end against the live cluster at 8 tenants and 8000 rows: 32 probe
results per phase, `baseline` showing the leak, `post_rls` showing it closed,
and the auditor column showing the foreign row was hidden rather than deleted.

```bash
harness/freeze.sh              # once: writes queries.json
schema/apply.sh rls off
harness/run.sh baseline
schema/apply.sh rls on
harness/run.sh post_rls
#   <-- repair/ quarantines here
harness/run.sh post_quarantine
harness/run.sh negative_control
```

## The result it produces

Same corpus, same query, same principals, two phases:

| Phase | probe | returned | canary_hit | auditor_sees |
|---|---|---|---|---|
| `baseline` | `direct_id` | 2 | **t** | 2 |
| `post_rls` | `direct_id` | 1 | f | 2 |

Three things are true in that table at once and all three are needed. The
baseline failed, so the receipt is not a rubber stamp. The repaired run did not,
so the boundary works. And the auditor saw two rows in **both** phases, so the
foreign row still exists and RLS hid it rather than something having deleted it.
Without the third column the second row is indistinguishable from an emptied
table, which is the first question a sharp judge asks.

`side_channel` reads 0 of 6 evidence tables as every tenant in every phase, and
6 of 6 as the auditor. Those tables are fenced at the privilege layer, not by
RLS, so the result is identical with the fence up or down. That is the correct
behaviour and the probe exists to notice if a stray `GRANT` ever changes it.

## Three connection classes, and why they are separate

| Role | Does |
|---|---|
| tenant roles | Run the probes, over their own credentials from Secrets Manager |
| `rf_auditor` | Ground truth: the same SQL, at the same moment, unfenced |
| `rf_harness` | Records the matrix, and holds **no privilege on `memories`** |

The account that records the breach cannot read the rows the breach is about.
Nothing uses `SET ROLE` from a shared session, because a session that can
`SET ROLE` can also `RESET ROLE` and the fence would be one statement deep.

Probes take the principal as a **literal**, not `current_user`. That looks like a
weakening and is the opposite: it lets the identical SQL run as `rf_auditor` for
ground truth. Under `current_user` the filtered probe's ground truth would
resolve to `tenant = 'rf_auditor'`, match nothing, and be silently empty in every
phase.

## Determinism

The query vector is frozen into `queries.json` by `freeze.sh` and read from
disk. `run.sh` never calls a model. A harness that embedded at run time would not
be deterministic: a model version change between `baseline` and `post_rls`
silently moves the query point and the phases stop being comparable, with
nothing in the output to say so.

Both `freeze.sh` and `run.sh` refuse to proceed if the corpus and the query were
embedded by different models. That failure is invisible in a result set: the
query point simply sits in a different coordinate system from the rows and every
distance is meaningless.

Bedrock is a build-time dependency **of the harness** and a run-time dependency
of the support agent, which has to embed new content when it writes. Two paths,
two failure modes; freezing covers only the first.

## What a non-semantic embedder changes

With `local-hash-v1` the semantic probes retrieve arbitrary rows, so
`semantic_unfiltered` scores no canary hit and the leak shows through `direct_id`.
Everything structural still holds: row counts, vector width, index behaviour, and
every clause of `passed` except the semantic one.

The scoring path is verified independently of the model. With a query vector that
lands on bob's policy, alice retrieves it fence-down and the scorer returns
`foreign_canary_hit = true`, so the semantic scorer is proven regardless of which
embedder seeded the corpus.

## Two findings this module produced

**The grant matrix refused an upsert, and dropping the upsert was the right
fix.** `rec_result` started as `ON CONFLICT (run_id, principal, probe_type) DO
UPDATE`, for resumability. `rf_harness` holds `SELECT, INSERT` on
`probe_results` and no `UPDATE`, so it failed with 42501. Every run opens a fresh
`run_id`, so the conflict case never arises and the upsert was buying nothing.
Widening the grant would have been the stray-`GRANT` hazard the project exists to
point at, and it would also have converted a duplicate-write bug from a loud key
violation into a silent overwrite of evidence.

**The canary was on the wrong row.** A canary hit is scored on returned content,
so the row a semantic probe retrieves has to be a row that carries a phrase. The
first fixture put the phrase only on the account-note row, which is about a
renewal invoice and nowhere near a query about refund ceilings. The semantic
probe would have retrieved bob's policy, leaked it, and scored
`foreign_canary_hit = false`: reporting on a different document from the one that
leaked. Policies now carry their own tenant's phrase, and
`fixtures/seed.sh verify` asserts both halves of the property, that every
tenant's phrase is covered by one of their own rows and that no row carries
anybody else's.

## Known cost

A phase takes around four minutes at 8 tenants. Each probe opens its own
connection and this machine reaches the cluster through a container runtime, so
a run is roughly a hundred container starts. Batching a principal's statements
into one connection would cut it by most of that. Not done yet, and it is not on
the demo's critical path because replay is served from a snapshot.

## Files

| File | What |
|---|---|
| `run.sh` | Orchestration: one phase, all principals, all probe types |
| `freeze.sh` | Computes and commits the probe-query embedding |
| `queries.json` | The frozen query vector. Committed. |
| `lib/probes.sh` | The four probes, as SQL builders |
| `lib/record.sh` | Opens the run, records results, prints the matrix |

The matrix is printed by reading `probe_results` back **through the auditor**,
not from what the process believes it wrote. A harness that printed its own
in-memory idea of the run would still print a clean matrix after failing to
record one.
