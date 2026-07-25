# repair/

The policy generator, the quarantine mover, and the two reruns that keep their
effects separable.

Run against the live cluster: 56 contaminated rows moved in one transaction,
0 left, and the rows that were merely *exposed* still in place.

```bash
repair/policy.sh propose                    # read the SQL, change nothing
repair/policy.sh apply --approve
harness/run.sh post_rls
repair/quarantine.sh <baseline-run-id>            # report only
repair/quarantine.sh <baseline-run-id> --apply
harness/run.sh post_quarantine

repair/loop.sh <baseline-run-id> --approve  # all four, one command
```

## Two effects, deliberately not collapsed into one

RLS repairs **exposure**. Quarantine repairs **contamination**. Keeping them
apart is the whole reason there are two reruns rather than one.

If cleanup ran first, "no rows returned" would prove nothing, because an emptied
table returns nothing either. Probing after the fence goes up but before the
cleanup is what makes the two effects separable in the receipt.

The same distinction decides what quarantine refuses to touch. Bob's refund
ceiling leaked at baseline and is **correct data, correctly attributed to Bob**.
The defect was in Alice's query path. Deleting Bob's memory to fix Alice's bug
would be a worse bug than the one being fixed, so exposure alone is never a
reason to quarantine anything.

Verified rather than asserted: after the mover ran, bob's policy row and bob's
canary row are both still in `memories` and neither appears in
`quarantined_memories`.

## What counts as contaminated

A predicate, not a phrase. Both classes are keyed on provenance, and both are
defined in one place, `lib/predicate.sh`, so the count, the report, the insert
and the delete cannot drift apart.

| Class | Reason code | Predicate |
|---|---|---|
| 1 | `misattributed_write` | `origin_tenant <> tenant` |
| 2 | `derived_from_foreign_read` | written in a session whose retrieval log returned a foreign row |

Class 2 is why `retrievals` exists. Without a record of which rows a session
actually read, "the agent wrote this after reading a foreign row" is not a
computable predicate, only a suspicion.

Class 1 is excluded explicitly from class 2. The two are disjoint in the shipped
fixture, but relying on that would put a primary key violation one fixture edit
away and the reason codes would stop meaning what they say.

Measured on the seeded corpus:

```
misattributed_write         24
derived_from_foreign_read   32
                            --
                            56 moved, 0 contaminated rows remaining, 8000 -> 7944
```

## A one-time cleanup, not a sanitation process

Worth saying out loud because the design earned it. Once the policy set is
applied, neither class can recur:

- Class 1 is rejected at write time by `tenant_write`'s `WITH CHECK`, which will
  not accept a row whose tenant is not the writer.
- Class 2 becomes impossible upstream, because the agent can no longer read a
  foreign row to derive from.

So quarantine is a one-time cleanup of a bounded historical set. That is a
materially stronger claim than "RLS stops future leaks."

## The approval gate

`policy.sh apply` on its own is refused. An approval gate that can be satisfied
by pressing return is not a gate, so the approval is a word the operator has to
type in the same command.

`loop.sh` takes `--approve` once and passes it down rather than re-asking at each
step. Prompting four times would train the operator to stop reading, which is the
exact failure the gate exists to prevent.

The proposed policy set is read from `schema/004_policies.sql`, not assembled
here. One source of truth: a generator that composed its own version of the
policies could emit SQL the schema does not contain, and that is the one thing
an operator reviewing a security change has to be able to rule out.

`propose` diffs installed policy **names** against proposed ones rather than
diffing `USING` clause text against a catalog rendering. That kind of diff is
mostly formatting noise, and noise trains an operator to skim exactly the review
that matters.

## Idempotent by construction, not by flag

The mover copies and deletes in a single transaction. A second `--apply` on the
same run finds nothing left to move and reports `INSERT 0 0 / INSERT 0 0 /
DELETE 0`. Verified.

## A third case of the grant matrix shaping the code

The `DELETE` repeats the contamination predicate rather than reading back what
was just inserted. `rf_remediation` holds `INSERT` on `quarantined_memories` and
no `SELECT`, so `DELETE ... WHERE id IN (SELECT id FROM quarantined_memories
WHERE quarantined_by_run = ...)` is denied with 42501.

Inside one transaction the repeated predicate selects exactly the rows just
copied, so the narrower grant costs nothing and buys something real: the role
that removes evidence still cannot read the evidence store back.

This is the third time a module wanted a privilege the matrix withholds and the
right answer was to change the module. The first was `rf_harness` and the
`probe_results` upsert; the second was the fixture loader and `FORCE ROW LEVEL
SECURITY`.

## Files

| File | What |
|---|---|
| `policy.sh` | Show current and proposed policy sets, diff, apply behind `--approve` |
| `quarantine.sh` | The mover. Dry by default. |
| `loop.sh` | Policy, rerun, quarantine, rerun |
| `lib/predicate.sh` | The two contamination classes, defined once |

Everything the mover reports afterwards is read back through `rf_auditor`, not
from what the process believes it did, and the script exits non-zero if a
contaminated row survives its own cleanup.

## Note on `fixtures/seed.sh verify` after a quarantine run

It will fail `corpus_rows` and both contamination checks, correctly: those
assertions describe a freshly seeded corpus, and quarantine has by then removed
56 rows on purpose. Reseed before re-verifying.
