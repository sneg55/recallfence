# fixtures/

The corpus, the canaries, and the contamination the repair engine exists to
clean up. Runs between `schema/apply.sh roles` and `schema/apply.sh policies`.

Loaded and verified against the live CockroachDB Cloud Basic cluster: 8 tenants,
8,001 memories seeded (7,945 remain after quarantine moves 56), all eight fixture
checks passing, and `tests/test_policies.sh` 42/42 with the corpus in place.

## Running it

```bash
export RF_CLUSTER_URL='postgresql://...'
schema/apply.sh rls off        # the loader refuses to run while the fence is up
fixtures/seed.sh load          # plan -> embed -> insert -> manifest -> verify
schema/apply.sh rls on
```

`seed.sh plan` prints the row plan as TSV and touches nothing. `seed.sh clear`
removes everything the loader inserted. `RF_FIXTURES_CONFIG` points at an
alternate `config.json`, which is how the small end-to-end runs were done
without editing the committed one.

## Why the loader refuses to lower the fence itself

Under `FORCE ROW LEVEL SECURITY` the seeder is denied like anyone else, and the
denial is the silent kind: privilege held, no applicable policy, zero rows
affected, no error. So the loader checks `relforcerowsecurity` up front and
stops with the two commands that fix it.

It would have been one line to run `ALTER TABLE memories DISABLE ROW LEVEL
SECURITY` instead. A fixture loader that quietly disables row-level security to
get its work done is the exact convenience this project exists to argue against,
and it would be the first thing a judge found. The operator lowers the fence
explicitly, or not at all.

## What gets seeded, per tenant

| Rows | Kind | Why it exists |
|---|---|---|
| 1 | canary | Unique marker phrase, stable across every run and every phase |
| 1 | refund policy | The row the leak returns |
| 3 | misattributed | Quarantine class 1: `origin_tenant <> tenant` |
| 4 | derived | Quarantine class 2: written in a session that read a foreign row |
| rest | filler | Corpus scale, so the scan cost and the index behaviour are real |

Plus one `canaries` row per tenant and one `retrievals` row per contaminated
session. Those retrieval-log rows are not decoration: without a record of which
rows a session actually read, "the agent wrote this after reading a foreign row"
is not a computable predicate, and quarantine class 2 has nothing to join
against.

`seed.sh verify` asserts all of it against values derived from the config rather
than printing numbers for a human to eyeball. A half-loaded fixture fails loudly
instead of looking plausible.

## The canary phrase constraint, which is not obvious

Class-2 rows paraphrase what the agent read. They must **not** contain the
foreign tenant's canary phrase, and that is a correctness requirement rather
than a stylistic preference.

A canary hit is scored on returned content. A row alice legitimately owns that
quotes bob's purchase-order number would be scored as a foreign canary hit in
the `post_rls` phase, and the receipt would record the fence as having failed
for something the fence is not for. Exposure is repaired by RLS; contamination
is repaired by quarantine one phase later. Letting a contaminated row read as an
exposure failure collapses the exact distinction the two-phase rerun exists to
draw.

## The corpus is selected, and saying so is cheaper than not

Bob's refund policy is written to sit closer to the demo query ("the maximum
refund I can approve for an enterprise customer without escalating") than
alice's own policy does, because alice's business is consumer orders and bob's
is enterprise contracts. The query is ordinary and unplanted. The corpus is
chosen so that a foreign policy is likely to outrank the caller's own.

Claiming the ranking is a lucky accident would be the kind of small dishonesty
that costs more than it buys, and the demo does not need it: the money shot is
the direct-ID probe and the rejected write, both deterministic, neither
depending on an embedding model cooperating on the day.

## Embeddings

`embed.sh` has two backends and writes the one it used into
`memories.embedding_model` on every row.

| Backend | Model ID recorded | Notes |
|---|---|---|
| `bedrock` | `amazon.titan-embed-text-v2:0` | The real one. 1024 dimensions, normalised. |
| `local` | `local-hash-v1` | AES-CTR keystream over zeros, keyed by SHA-256 of the text. |

Backend selection is `auto` by default and **probes the account** rather than
assuming, because Bedrock model access is an account-level flip that is
invisible from the catalog: the model lists as `ACTIVE` and `ON_DEMAND` in-region
and still refuses `InvokeModel` with `Operation not allowed` until access is
granted.

The fallback is not a stand-in pretending to be the model. It preserves
determinism, row count, vector width and index behaviour, so every structural
property of the demo holds under it. It carries no semantics at all, so the
semantic-ranking beat does not survive it. Recording its own identifier per row
is what keeps that honest: a receipt cannot present fallback vectors as Titan
vectors, and `seed.sh verify` fails if a single table ends up holding both.

One distinct text per row, deliberately. A corpus of a few hundred vectors
repeated thousands of times would give the vector index a degenerate
distribution and make the cost-of-the-boundary measurement meaningless. The
filler pools multiply out well past the configured scale; uniqueness is checked
at 6000 rows per tenant, which is the 48k-row configuration spike 1 measured.

The cache is one file per distinct text, ~94MB at the default corpus size, and
is gitignored. `manifest.json` is committed instead: it is small, and it is what
the harness reads.

## manifest.json

Written by every `load`. Records the model actually used, the corpus shape, the
probe limit, and per tenant the canary phrase plus the canary and policy row
IDs.

Those IDs are derived, not captured: `rf_uuid` is the first 128 bits of
SHA-256 over a stable row key, so the same plan always produces the same primary
keys and the harness can ask for "bob's canary" without a handoff file surviving
between two processes. It is a content address that happens to fit the column,
not an RFC 4122 versioned UUID, and nothing treats it as one.

The direct-ID probe depends on those IDs resolving, so `verify` checks that
every ID the manifest promises exists in the table. Verified end to end: alice's
own canary resolves by ID over her own connection, bob's does not, and the
auditor sees both.

## Files

| File | What |
|---|---|
| `config.json` | Tenants, rows per tenant, model, probe limit, contamination counts |
| `seed.sh` | Plan, embed, load, manifest, verify, clear |
| `embed.sh` | Two backends, on-disk cache, parallel fill |
| `lib/corpus.sh` | What text exists: canaries, policies, filler pools |
| `lib/plan.sh` | Which rows exist, and which are deliberately contaminated |
| `lib/verify.sh` | The eight assertions |

## Implementation notes worth keeping

**No `mapfile`.** The system bash on macOS is 3.2. The rest of the repo already
runs there, and a fixture loader that only works under a Homebrew bash is a
portability bug waiting to be discovered by whoever clones the repo.

**SQL generation is perl plus awk, not a bash read loop.** A read loop needs a
`shasum` fork for the cache key and a subshell per quoted field, so at corpus
scale it spends minutes forking. perl adds the content digest and the derived
UUID in one pass, awk does the cache lookup and the quoting in a second, and
both agree with `rf_uuid` by construction because they hash the same key the
same way.

**`count(DISTINCT m.id)` in the class-2 check, not `count(*)`.** Each
contaminated session read two foreign rows, so a plain count returns the size of
the join rather than the number of contaminated memories, and the quarantine
mover would look like it had twice as much to do as it does.
