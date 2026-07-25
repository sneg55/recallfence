# audit/

The receipt writer and the hash chain. This is where the run stops being a
terminal transcript and becomes an artifact someone else can check.

```bash
audit/receipt.sh explain <baseline> <post_rls> <post_quarantine>   # compute, insert nothing
audit/receipt.sh emit    <baseline> <post_rls> <post_quarantine>
audit/receipt.sh show                                              # latest receipt

audit/verify.sh                          # recompute the chain from the DB
audit/verify.sh --from-file f.ndjson     # from a changefeed export, no DB
audit/verify.sh --from-s3                # from the delivered S3 objects
audit/verify.sh --head <hash>            # also pin the head to an external anchor

tests/test_receipt_chain.sh              # 11 cases, no cluster needed
```

Run against the live cluster: a two-link chain over the real baseline /
post_rls / post_quarantine runs, both links verified, `passed = true`.

## What a receipt contains

The whole evidence set, not a pass/fail bit: the 96-row breach matrix across the
three counted phases (what each principal saw, what the auditor saw at the same
instant, and whether it was a hit), the exact policy SQL that repaired the leak,
the 56 quarantined row IDs with their reason codes, and the four-clause verdict.

`negative_control` is deliberately absent. It is recorded like any other phase and
excluded from the pass computation.

## `passed` is four clauses, and clause 1 is the one that gets forgotten

```
c1  at least one foreign canary hit in baseline
c2  zero foreign canary hits in post_rls and post_quarantine
c3  the auditor still saw the foreign rows at post_rls
c4  every probe in every counted phase has status = ok
```

The obvious definition is just c2, and c2 alone is a rubber stamp: a harness that
errored silently and recorded nothing also produces no hits. A pass has to prove
the failure existed before it proves the failure is gone. c3 is the other half of
that: RLS hiding a row and quarantine deleting a row both produce zero rows
returned, so without the auditor's ground truth a receipt cannot tell a working
boundary from an emptied table.

All four live in `lib/clauses.sh` as one query, so the boolean stamped into the
receipt and the boolean an operator recomputes by hand are the same SQL.

**A wellformedness precondition, not a fifth clause.** c2 and c4 are both
satisfied by a phase with no probes in it. So the writer first checks that each
of the three runs recorded `tenants x 4` results and refuses to receipt a
malformed set rather than passing it vacuously.

## The chain

`receipt_hash = SHA-256( canonical(receipt_json) + "\n" + prev_receipt_hash )`

The body is everything the receipt attests. `prev_receipt_hash` and
`receipt_hash` live in their own columns and are not inside the body they secure.

Three details that are load-bearing rather than stylistic:

- **Canonical form is applied on write and on verify.** The body is stored as
  JSONB and the database is free to reorder keys and renormalize whitespace. The
  digest is over `jq -S -c` of the parsed JSON, so it is a function of content,
  not of a byte layout nothing promised to preserve. Any array whose order
  matters is sorted by the SQL that builds it. `emit` proves this per receipt: it
  reads the body back through JSONB, recomputes the link, and refuses to finish
  if the stored hash does not match.
- **The separator is not decoration.** Without a delimiter, body `…abc` onto prev
  `def` and body `…ab` onto prev `cdef` digest identically.
- **Genesis passes an empty prev**, so the first digest is over `<body>\n`.

## Tamper-evidence comes from the chain, not from the bucket

A changefeed writing to S3 proves delivery, not integrity. Anyone who can write
the bucket, including the changefeed's own IAM principal, can overwrite an object.
So the property has to survive an attacker with full write access to the sink, and
it does:

| Attack | Caught by |
|---|---|
| Edit a receipt body | Its own link: the stored hash no longer matches the body |
| Edit a body *and* recompute its hash | The **next** receipt, which committed to the old hash |
| Rewrite the entire suffix | Nothing internal. Only an external anchor (`--head`) |

`tests/test_receipt_chain.sh` asserts all three, plus column tampering,
truncation, forks, and two independent chains sharing one export prefix. It needs
no cluster: it builds synthetic chains with the same `rf_link` the writer uses,
shapes them exactly like a changefeed export, and drives the real verifier over
them.

The verifier reconstructs order by **following the hash links**, not by sorting
on timestamps. An audit sink is a prefix that accumulates, so it will hold more
than one chain, and two receipts can share a timestamp; either would derail a
timestamp sort. It finds roots, walks successors, and refuses a fork where two
receipts claim the same predecessor.

The third row is stated rather than papered over. A fully rewritten chain is
internally consistent, and the test asserts that it verifies clean, because
claiming otherwise would be false. What convicts it is a head hash kept somewhere
the attacker cannot reach: Object Lock on the receipt prefix, or a judge who
wrote the hash down. That is what `--head` is for.

## Why rf_auditor writes it

`rf_auditor` holds SELECT over every evidence table and INSERT on `receipts`, and
nothing else. The account that attests the breach cannot UPDATE or DELETE what it
attested, so the receipt store is append-only to its own writer. That is the one
exception to "the auditor is read-only", and it is the reason the exception
exists.

`RF_AUDITOR_URL` overrides the connection for testing and for operators who keep
credentials outside Secrets Manager. It defaults to the shipped `rf_auditor`
account; the append-only property is proven against that account by the policy
suite, not asserted by the default.

## Two bugs this module found elsewhere

Worth recording because both were silent and one was live.

**`${1//\'/\'\'}` does not double an apostrophe on bash 3.2.** It substitutes a
literal `\'\'` and the statement dies at the backslash. The same construct was in
`harness/lib/record.sh`, under a comment claiming it "removes a whole class of
failure modes", and in `fixtures/seed.sh`. It was latent in both (machine-built
JSON and tenant names contain no apostrophes) and went live here the moment the
receipt embedded policy SQL containing the word `demo's`. All three now route the
quote through a variable. Arbitrary content goes to the cluster base64-encoded
instead, decoded by `convert_from(decode(...))`, so nothing between here and the
database has an opinion about quoting.

**A CSV scalar read on an empty table returns the column name.** The genesis
lookup reported a predecessor hash of `coalesce`, which would have chained the
first receipt to a string instead of to nothing. The header is now dropped before
the value is taken.

## Files

| File | What |
|---|---|
| `receipt.sh` | Build, hash-chain and append a receipt. Read-back verified. |
| `verify.sh` | Recompute the chain from DB, file or S3. Exits non-zero on any break. |
| `lib/hash.sh` | Canonical form and the chain link, shared by writer and verifier |
| `lib/clauses.sh` | The four clauses and the shape guard, defined once |

The changefeed that ships receipts to S3 is `schema/apply.sh changefeed`, not a
script here. Creating it is an admin operation and belongs with the other schema
steps; `verify.sh --from-s3` is this module's half of that story.
