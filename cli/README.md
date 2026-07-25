# cli/

The same evidence as the dashboard, with no web dependency.

```bash
cli/rf status        corpus, RLS state, receipt verdict, chain head
cli/rf matrix        breach matrix: principal x probe, across all three phases
cli/rf evidence      the exact foreign rows that leaked, with provenance
cli/rf policy        the policy set installed, and the SQL the receipt attests
cli/rf quarantine    rows moved out, with reason and lineage
cli/rf receipt       the receipt, its four clauses, its place in the chain
cli/rf verify        recompute the hash chain
cli/rf all           every panel, in demo order
cli/rf snapshot      write the replay bundle (default web/public/replay.json)

cli/rf --from web/public/replay.json matrix    # render a snapshot, no cluster
```

## The bundle is the architecture

`rf` never renders from a database. It builds one JSON bundle, from the cluster or
from a file, and every panel is a pure function of that bundle.

That is what makes this a real fallback rather than a second implementation. The
same code path serves a live cluster and a committed replay snapshot, so the CLI
and the dashboard cannot drift into telling different stories, and the demo URL
keeps working after the cluster is paused, reclaimed, or torn down by a botched
live run.

`rf snapshot` writes that bundle to `web/public/replay.json`. It is rendered
through `jq -S`, so re-exporting an unchanged run produces no diff: a snapshot
that churns on every run is one nobody reviews before committing it.

## Which runs it reads

The three run IDs come from the latest receipt, not from arguments. The receipt is
what says which runs constitute a result, so anything reading a different set is
reading something the receipt never attested.

The bundle is also assembled in a single query rather than stitched together from
six round trips. Six client-side reads could interleave with a live run and
produce a bundle whose breach matrix and whose RLS state disagree about which
world they are in.

## The matrix

```
  principal  probe                baseline  post_rls  post_quarantine
  --------------------------------------------------------------
  alice      direct_id            HIT       ok        ok
  alice      semantic_filtered    ok        ok        ok
  alice      semantic_unfiltered  HIT       ok        ok
  alice      side_channel         ok        ok        ok

  43 foreign rows at baseline, 0 after RLS, 0 after quarantine.
  canary phrase corroborates on 8 baseline probe(s).
```

`semantic_filtered` reading `ok` at baseline is not a bug and is worth pointing at
during a demo. The correctly scoped application query was never the problem. The
product exists because the filter on the line above it gets forgotten, and a
matrix where every row failed would prove only that the fixture was broken.

`HIT` means the principal received a row belonging to another tenant, computed
from the probe's own evidence by the same expression the receipt's clauses use. A
panel and the verdict printed above it cannot disagree about whether a probe
leaked.

## Colour

Applied by `colorize`, outside jq, and skipped entirely when stdout is not a
terminal. The bundle stays plain data, a redirected run stays greppable, and a
snapshot never picks up escape sequences.

## A bash 3.2 parser trap, recorded because it cost real time

Every jq program here is assigned from a quoted heredoc at file scope, not
written as a multi-line single-quoted string inside a function body. That is not
style. Bash 3.2, which is what macOS ships and what this project runs on,
mis-parses certain multi-line quoted programs in that position: the file passes
`bash -n` cleanly and then fails to source with

```
unexpected EOF while looking for matching `''
```

pointing at the opening quote of a string that is correctly closed twenty lines
later. `shellcheck` also reports the file clean. A quoted heredoc is read
literally, sidesteps the entire class, and has the side benefit that the programs
read as jq rather than as escaped shell.

## Files

| File | What |
|---|---|
| `rf` | Subcommand dispatcher, bundle caching, snapshot export |
| `lib/bundle.sh` | The single query that assembles the evidence bundle |
| `lib/render.sh` | One function per panel, all pure over the bundle |

`rf verify` delegates to `audit/verify.sh` rather than reimplementing the chain
check. A second copy would be a second thing to keep correct, and the hash chain
is the claim least worth risking that on.
