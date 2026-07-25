---
name: auditing-multi-tenant-agent-memory
description: Use when auditing, testing, or designing tenant isolation for an AI agent's memory store, vector database, or RAG corpus - covers proving isolation rather than asserting it, distinguishing exposure from contamination, and the failure modes that make an isolation test pass while testing nothing.
---

# Auditing multi-tenant agent memory

An agent that remembers across sessions stores what it learned somewhere. In a
multi-tenant product that store is one forgotten predicate away from serving one
customer's memory to another. This skill is about proving the boundary holds,
and about the specific ways an isolation test convinces you it holds when it does
not.

## Start here: the test is the hard part, not the boundary

Adding row-level security takes an afternoon. Proving it works, and keeping the
proof honest, is where this goes wrong. Most of what follows is about the proof.

## 1. Never infer "I was blocked" from catching an exception

In PostgreSQL and CockroachDB, privileges and policies are two enforcement layers
that answer in **opposite ways**:

| Situation | Signal |
|---|---|
| No table privilege | Hard error, SQLSTATE 42501 |
| Privilege held, no applicable policy | Zero rows affected, **no error** |

A test written as "we expected an exception and got one" passes just as happily
when the table name is misspelled. Worse, a stray `GRANT` silently converts a
loud failure into a quiet one without changing a single policy, and the test
keeps passing while the meaning changes underneath it.

**Do this instead:** compare affected-row counts against an exact expectation,
and when you do assert an error, assert the SQLSTATE or message, not merely that
something was raised.

## 2. Zero rows returned proves nothing on its own

A working boundary returns nothing. An empty table returns nothing. A typo in the
tenant name returns nothing. A deleted row returns nothing.

Every isolation probe needs **independent ground truth**: run the identical
query as a privileged auditor account at the same moment, and record what it
saw alongside what the tenant saw. "The tenant saw 0 and the auditor saw 5" is
evidence. "The tenant saw 0" is not.

## 3. A pass must prove the failure existed first

The obvious pass condition, "no cross-tenant reads after the fix", is a rubber
stamp: a harness that crashed on startup and recorded nothing also produces no
cross-tenant reads.

Require, at minimum:

1. **At least one breach in the baseline run.** The failure has to be
   demonstrated before its absence means anything.
2. **Zero breaches after the fix**, across every principal and every access path.
3. **Ground truth confirming the rows still existed** when the tenant could not
   see them.
4. **Every probe completed.** Fail closed: an unexecuted probe is not a passed
   probe.

Clause 1 is the one that gets forgotten and the one that separates a real result
from a rubber stamp.

## 4. Score on attributes you control, not on markers you hope to retrieve

Seeding canary phrases and scoring "did another tenant's phrase come back" is
appealing and has a sharp failure mode: it only fires if the retrieval actually
returns the marked row. With a weak, stubbed, or simply different embedding
model, nearest-neighbour results are arbitrary and the marked row never surfaces.
The breach happens, and the score says clean.

Score primarily on **"did this principal receive a row whose tenant is not
theirs"**, read off the recorded result set. That is independent of whether the
model cooperated. Keep the canary phrase as corroboration, because "read another
tenant's actual words" is the stronger story when it does fire.

## 5. Exposure and contamination are different problems

- **Exposure**: rows that were readable and should not have been. Repaired by
  the boundary.
- **Contamination**: rows that are *wrong*, because they were written under the
  wrong tenant, or derived by an agent that had just read a foreign row.
  Repaired by quarantine.

They need separate repairs and separate verification. Two rules follow:

**Probe after the boundary goes up but before cleanup.** If cleanup runs first,
"no rows returned" proves nothing, because an emptied table returns nothing too.
Ordering is the argument.

**Exposure alone is never a reason to delete anything.** A row that leaked may be
perfectly correct data belonging to its rightful owner; the defect was in
someone else's query path. Deleting it to fix that is a worse bug than the one
being fixed. Assert this explicitly: after cleanup, check the merely-exposed rows
are still present.

Contamination has to be a predicate on provenance, not a phrase match:

| Class | Predicate |
|---|---|
| Misattributed write | `origin_tenant <> tenant` |
| Derived from foreign read | written in a session whose retrieval log returned a foreign row |

The second is only computable if you log every retrieval. Without that log,
"the agent wrote this after reading a foreign row" is a suspicion, not a query.

## 6. Log retrievals write-only from the agent's side

Grant the agent runtime `INSERT` on the retrieval log and no `SELECT`. The
audited party should not be able to read back, verify, or edit its own audit
trail. The same reasoning applies to whatever records your breach matrix.

## 7. Audit your audit tables

The tables recording the breach are usually **not** protected by the same policy,
and they hold the leaked data in plaintext: canary phrases, the exact foreign
rows returned, cross-tenant read history, the whole matrix.

Probe them from every tenant role in every phase, even though the privilege layer
should already refuse. It costs one row in the matrix and it answers "what about
your own audit log?" before anyone has to ask. It is also a regression guard
against a future stray `GRANT`, which is exactly the kind of change nobody
reviews.

## 8. Provisioning tools may hand out superuser

Verified on a live managed CockroachDB cluster: the vendor CLI's
`cluster user create` returned a role with `rolsuper`, `rolbypassrls`, and
membership in `admin`. A tenant provisioned that way saw every other tenant's
rows and could `SET ROLE` into them. No error, no warning, queries just succeed
and return data.

**Create roles with SQL, revoke `admin` unconditionally, then assert the flags
came back clean and refuse to continue if they did not.** The assertion is
mandatory, not decorative, because the symptom of getting this wrong is silent
and total.

## 9. Keep tenant roles flat

No group roles, no memberships. That is what makes `SET ROLE other_tenant` fail
and `RESET ROLE` leave the connection still fenced: there is nothing to assume
and nothing to fall back to.

For the same reason, tests must connect over **each role's own credentials**. A
session that can `SET ROLE` can also `RESET ROLE`, and a fence you can leave in
one statement is one statement deep.

## 10. Seed before you fence

Under `FORCE ROW LEVEL SECURITY`, an operation with no applicable policy is
denied for **every** role, including the table owner. So load fixtures before
enabling it. Otherwise you need a policy that exists only to let the seeder
cheat, and that policy will outlive the reason for it.

## 11. Expect the boundary to cost something, and measure it

With a policy active, an approximate vector index may become unusable: filtering
an approximate nearest-neighbour candidate set through a row policy could
silently drop rows the tenant is entitled to, so the engine falls back to an
exact scan for correctness.

Do not hide this. Show both query plans and state the numbers. It is the same
mechanism that guarantees the caller never gets a short result, and an auditor
who runs `EXPLAIN` themselves should find exactly what you told them.

## 12. Make the result an artifact someone else can check

Emit a machine-readable receipt: the full matrix, the exact policy applied, what
was quarantined and why, and the verdict with each clause broken out.

If you chain receipts by hash, be precise about what that buys. Editing one
breaks its own link. Editing one and recomputing its hash is caught by the next
receipt, which committed to the old value. **Rewriting the entire suffix is
caught by nothing internal** and needs an external anchor. Write that limitation
down; a tamper-evidence claim that overstates itself is worse than none.

Two details that bite:
- Canonicalize on write **and** on verify. If bodies are stored as JSON, the
  database may reorder keys, and a byte-sensitive digest will then break on
  records nobody touched.
- Verify the round trip **before** committing, especially if the store is
  append-only. Discovering a broken link afterwards leaves something you cannot
  retract.

## Checklist

- [ ] Probes run under each tenant's own credentials, not `SET ROLE`
- [ ] Row counts compared to exact expectations, not "did it throw"
- [ ] Independent ground truth recorded beside every tenant-visible result
- [ ] Baseline demonstrates a real breach before any fix is applied
- [ ] Breach scored on row ownership, not only on retrieved markers
- [ ] Probed after the boundary, before cleanup
- [ ] Merely-exposed rows asserted to have survived cleanup
- [ ] Retrieval log written by an account that cannot read it
- [ ] Audit tables probed from tenant roles in every phase
- [ ] Role flags asserted non-privileged after provisioning
- [ ] Fixtures loaded before the fence goes up
- [ ] Cost of the boundary measured and published
- [ ] Missing probes and missing evidence fail closed, never score as clean
