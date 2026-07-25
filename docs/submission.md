# Devpost submission copy

Paste-ready text for each field. Kept in the repo so the submission and the
README cannot drift apart.

One placeholder left: `VIDEO_URL`, once the recording is uploaded.

---

## Project name

RecallFence

## Elevator pitch

Multi-tenant agent memory where the isolation boundary lives in CockroachDB
row-level security, not application code. Broken on purpose, repaired, and
proven with a hash-chained receipt.

## Built with

`cockroachdb` `row-level-security` `distributed-vector-index` `ccloud`
`amazon-s3` `aws-secrets-manager` `aws-iam` `amazon-bedrock` `bash` `sql`
`model-context-protocol` `cloudflare-pages` `javascript`

## Links

- Demo: https://recallfence.pages.dev
- Video: `VIDEO_URL`
- Repository: https://github.com/sneg55/recallfence

---

## Inspiration

An agent that remembers across sessions has to put what it learned somewhere,
and in a multi-tenant product that store is one forgotten `WHERE` clause away
from serving one customer's memory to another.

The usual answer is to be careful in application code. I don't think careful is
a security control. Every retrieval path, every background job, every debugging
script someone writes at 2am has to remember the filter, forever, and the one
that forgets is the one that ships.

So I wanted to move the boundary somewhere that cannot be forgotten, and then,
more importantly, prove it held. Not assert it. Prove it, in a way that survives
someone else checking the work after the cluster is gone.

## What it does

RecallFence stores agent memory in CockroachDB with row-level security doing the
tenant isolation, then attacks itself and publishes the results.

A deterministic harness runs four probe types under each of eight tenants' own
logins: a direct lookup by ID, a semantic search with the tenant filter, the same
search with the filter missing, and a side-channel read against the evidence
tables. It runs all of it three times: once with the fence down, once with it up,
and once after contaminated rows have been quarantined. That is 96 recorded
results.

The measured outcome from the committed snapshot: 16 breaches and 43 foreign rows
at baseline, zero after RLS, zero after quarantine.

Then it writes a receipt. The receipt carries the full 96-row matrix, the exact
policy SQL that repaired the leak, the quarantined row IDs with reason codes, and
a SHA-256 chaining it to the receipt before it. A changefeed streams receipts to
S3, and `audit/verify.sh` re-verifies the whole chain straight from the bucket
with no cluster reachable at all.

The point of that last part: the artifact outlives the infrastructure. You can
check my work after I have deleted the cluster.

## What a pass actually requires

This is the part I care most about, because "no leaks after the fix" is a rubber
stamp. A harness that errored silently and recorded nothing also produces no
leaks.

A receipt passes only when four clauses hold:

1. At least one breach at baseline. The failure has to be demonstrated before its
   absence means anything.
2. Zero breaches after RLS and after quarantine, every principal, every probe.
3. The auditor still saw the foreign rows at `post_rls`. RLS hiding a row and
   something having deleted the row both return zero rows. Without independent
   ground truth, a receipt cannot tell a working boundary from an emptied table.
4. Every probe in every counted phase has `status = ok`. An unexecuted probe is
   not a passed probe.

Clause 1 is the one people forget. Clause 3 is the one that makes the number mean
anything.

## How I built it

The schema order is load-bearing and took me a while to get right. Tables, then
roles, then the fixture loader, then policies. Under `FORCE ROW LEVEL SECURITY`
an operation with no applicable policy is denied for every role including the
table owner, so seeding after the fence goes up would need a policy that exists
only to let the seeder cheat. The apply script deliberately has no "do
everything" subcommand for that reason.

Tenant roles are flat, with no group memberships. That is what makes `SET ROLE`
fail and `RESET ROLE` leave the connection fenced. Tests connect over each role's
own credentials from Secrets Manager rather than switching roles inside a shared
admin session, because a session that can switch can also switch back.

Exposure and contamination are repaired separately. RLS fixes exposure, meaning
rows that were readable and should not have been. Quarantine fixes contamination,
meaning rows that are wrong: written under the wrong tenant, or derived by an
agent that had just read a foreign row. Those are different defects and I kept
them apart deliberately, which is why there are two reruns instead of one.

It also decides what quarantine refuses to touch. Bob's refund ceiling leaked at
baseline, but it is correct data correctly attributed to Bob. The defect was in
Alice's query path. Deleting Bob's memory to fix Alice's bug would be a worse bug
than the one being fixed, so exposure alone never triggers quarantine. The
committed bundle shows it: the two rows exposed at baseline stayed in `memories`,
while ten other rows attributed to Bob moved for provenance defects.

## Challenges I ran into

The one that shaped every test in the repo: privileges and policies are separate
enforcement layers, and they answer in opposite ways. Missing a table privilege is
a hard error, SQLSTATE 42501. Holding the privilege but matching no policy affects
zero rows and raises nothing at all. So "I caught an exception" is not evidence of
being blocked, and a stray `GRANT` quietly converts a loud failure into a silent
one without touching a single policy. Every test here compares affected-row counts
against expectation instead of catching errors.

Then there was the detector that was lying to me. I first scored a breach on
canary phrases turning up in results, and it looked fine. It kept looking fine
right until I read the raw rows and found `semantic_unfiltered` returning 35 rows
belonging to other tenants at baseline, scored clean, because the fallback
embeddings produce arbitrary nearest neighbours that carry no marked phrase. The
definition is now "returned a row belonging to another tenant", with the canary
kept as corroboration. That one still bothers me. Nothing in the output looked
suspicious.

A smaller version of the same disease: `jsonb_array_elements(NULL)` yields zero
rows, so a probe with null evidence scored as having no foreign rows. Fail-open,
in the one place you least want it. Null evidence counts as a breach now, and a
preflight check refuses to score a run whose probes did not all record evidence.

I also poisoned my own audit sink. A test for append-only behaviour inserted
sentinel receipts, the changefeed dutifully shipped them to S3, and deleting the
database row un-published exactly nothing. Chain verification started failing on
junk my own test suite had written. The sink is append-only by design and its IAM
principal is explicitly denied deletes, so there was no quiet cleanup available.
The test now wraps its inserts in a transaction it rolls back, and the changefeed
writes to a fresh prefix. The old objects are still sitting there permanently,
which is probably the correct punishment.

The last one is not a bug, just an expensive truth. With the fence up the vector
index is no longer usable and reads become exact full scans. I would rather
measure that than meet it in production, so the demo says it out loud. It is a
real cost of putting the boundary in the database, and hiding it would undercut
everything else here.

## Accomplishments I'm proud of

The receipt verifies offline. Hand someone the S3 prefix and a head hash and they
can confirm the entire history without my cluster, my credentials, or any trust in
this repo. That was the whole point of building it, and it actually works.

I have also become oddly attached to a row in the results table where nothing
happens. `semantic_filtered` reads clean even at baseline. The correctly scoped
query was never the problem, and this project exists because the filter on the
line above it gets forgotten. A matrix where every row failed would only prove the
fixture was broken, so the boring row is carrying more weight than the dramatic
ones.

Last, the tamper suite asserts something the design cannot do. A fully rewritten
chain is internally consistent and verifies clean, and the test says so out loud.
The mitigation is an external head anchor. Claiming that a hash chain on its own
defeats a total rewrite would have been a lie I could comfortably have got away
with, and I would rather ship the limitation than the lie.

## What I learned

Test the test. Nearly every real bug I found this build was in the thing doing the
checking, not the thing being checked: a detector scoring a leak as clean, a
verifier that sorted receipts by timestamp instead of following hash links, an
assertion that only checked "it errored" and would have passed just as happily on
a misspelled table name.

Also: two principals failing the same way is not an eliminated variable. I spent
real time convinced a Bedrock problem was not permissions-related because a scoped
IAM user failed exactly like the root account did. They were both blocked by the
same missing thing. Identical failures are evidence of a shared cause.

## What's next

The interesting direction is the cost side. With a policy active the vector index
stops being usable and retrieval degrades to an exact full scan, which I measured
rather than discovered in production. I want to know how much of that a partial
index or a different policy shape buys back without weakening the boundary. That
is a benchmark, not a guess, and this harness is already built to answer it.

The corpus embeds with a deterministic local fallback rather than Titan, because
classic `bedrock-runtime` is restricted to zero throughput on this account and
that is the endpoint serving Titan. The bedrock-mantle endpoint does answer here
and the agents use it for prose; its `/v1/embeddings` route works, but the
account's catalogue carries no embedding model for it to serve. Every receipt
records the model ID that produced it, so a fallback cannot present itself as
Titan, and the isolation results do not depend on embedding quality: a breach is
scored on row ownership, not on what the vector search ranked. Once the
restriction clears, reseeding means rerunning the seed and harness pipeline and
emitting a fresh receipt, with no code change.
