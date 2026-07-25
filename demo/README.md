# demo/

Seven beats, a negative control and a hash-chain reveal, inside 180 seconds.

```bash
demo/run.sh                 # from the committed snapshot, no cluster needed
demo/run.sh --live          # from the cluster
demo/run.sh --no-pause      # straight through, for a timing pass
demo/explain.sh --both      # both query plans (mutates RLS, opt-in, restores on exit)
```

`run.sh` defaults to the snapshot. A rehearsal should never depend on the cluster
being awake, and the recording has to be re-shootable after the cluster is torn
down.

## Timing budget

180 seconds is tight for nine segments, so budget it rather than discovering the
overrun in the edit.

| Beat | Budget | Compressible |
|---|---|---|
| 1. The leak | 25s | No |
| 2. The auditor names it | 20s | Somewhat |
| 3. Operator approves the policy set | 20s | Somewhat |
| 4. The same query, repaired | 30s | No |
| 5. The cost of the boundary | 20s | **Most** |
| 6. Quarantine, and what it refuses to touch | 25s | Somewhat |
| 7. The receipt | 20s | No |
| Hash chain | 15s | Somewhat |
| Negative control | 5s | Yes |

Beats 1 and 4 cannot be compressed: the leak and the repaired rerun are the
proof. Beat 5 goes to the README first if the cut runs long, then the negative
control follows it as a recorded artifact rather than being dropped, since it
proves the product rather than the script and that argument survives in text.

## Things to say out loud, because not saying them looks like hiding them

**The corpus is chosen, the query is not.** A foreign policy is seeded so it sits
semantically closer to the caller's question than the caller's own. The query
itself is ordinary and unplanted. Claiming the ranking is a lucky accident would
be a small dishonesty that costs more than it buys.

**Why Alice knows Bob's UUID.** The harness captured IDs at seeding. The
real-world equivalent is that identifiers leak constantly through logs, URLs,
support tickets and prior over-broad answers: an attacker who has already seen
one over-scoped response has the IDs for the next one. Without that line, the
direct-ID probe reads as contrived.

**`semantic_filtered` passes even at baseline.** Point at it. The correctly scoped
query was never the problem, and a matrix where every row failed would prove only
that the fixture was broken.

**The boundary has a price.** With a policy active, CockroachDB will not filter an
approximate ANN result through RLS, because a row the policy rejects would
silently shorten the result set. It falls back to an exact scan. Captured live at
8k rows:

```
  • top-k
  └── • scan
        estimated row count: 7,944 (100% of the table)
        table: memories@memories_pkey
        spans: FULL SCAN
```

Say the number, then say why it is the right trade: it is the same mechanism that
guarantees the caller never gets a short result. A judge who runs `EXPLAIN`
themselves finds exactly what the demo already showed them.

**The embedding model is the fallback, not Titan.** Every receipt records the
model ID it was built with, so a receipt cannot present fallback vectors as
Titan. Related: this is why a breach is scored on "returned a row belonging to
another tenant" rather than on canary phrases.

## Order is the argument

Probing after RLS but **before** quarantine is what makes exposure and
contamination separable. If cleanup ran first, "no rows returned" would prove
nothing, because an emptied table returns nothing either. Beat 6 comes after beat
4 for that reason and no other.

## `explain.sh --both` mutates global state

RLS is a property of the table, not of a session, so disabling it is visible to
everyone looking at that cluster. The flag is opt-in, requires typing a word, and
restores the fence from an `EXIT` trap so a crash between the two toggles cannot
leave the cluster unfenced. Never run it against the shared demo cluster during
the judging window.
