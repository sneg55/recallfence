# web/

The replay dashboard, deployed to Cloudflare Pages at `recallfence.sawinyh.com`.

```
public/index.html    structure
public/styles.css    light and dark, no framework
public/dom.js        pure DOM helpers
public/panels.js     one function per panel
public/app.js        fetch, validate, render
public/replay.json   the committed bundle, written by `cli/rf snapshot`
```

No build step, no bundler, no dependencies. Open `public/index.html` and it works.

## Why static, and why a committed snapshot

The demo URL must stay functional from Aug 19 to Sep 15. The dashboard therefore
renders from `replay.json`, a snapshot committed to this repository, never from a
live query.

That is not a simplification, it is the durability mechanism. A Basic-tier
cluster that gets paused for inactivity, reclaimed, or damaged by a botched
live-run teardown would otherwise take the demo URL down with it, unattended,
during the four weeks that decide the outcome. Snapshot-first replay makes the
URL survive cluster death. The database is an enhancement on top, never a
dependency.

It also answers the concurrency problem. The demo mutates global state: it
enables RLS on a table, and quarantine deletes rows. RLS is a property of the
table, not of a session, so two judges arriving at once would otherwise get an
incoherent or already-repaired system at exactly the moment it is being graded.

## The same bundle drives the CLI

`replay.json` is produced by `cli/rf snapshot`, and `cli/rf --from` renders the
same file. The dashboard and the CLI are two renderers over one artifact, so they
cannot drift into telling different stories about the same run.

Regenerate after emitting a new receipt:

```bash
cli/rf snapshot          # writes web/public/replay.json
```

Written through `jq -S`, so re-exporting an unchanged run produces no diff. A
snapshot that churns on every run is one nobody reviews before committing it.

## Text nodes, never innerHTML

Every value from the bundle reaches the page through `textContent`. The bundle
carries corpus content and tenant-authored strings, and this is a project about
data crossing a boundary it should not. Rendering that content as markup would be
a real hole in the first place a reviewer looks.

## Plain scripts, in order

`dom.js`, then `panels.js`, then `app.js`, as classic scripts rather than ES
modules, so the page also opens straight off the filesystem with no server. The
split is by concern: pure helpers, one function per panel, and bootstrap.

A failed fetch is reported in the verdict slot rather than leaving a page that
looks like it rendered and happens to be empty. Fail visibly.

## Deploy

```bash
wrangler pages deploy web/public --project-name recallfence --branch main
```

The custom domain is attached at the Pages project level. The zone lives in the
same Cloudflare account, so the CNAME is managed there.

## Live runs

Not served from here, and currently advertised as disabled, which is the honest
state. A live run would call an AWS Lambda Function URL, rate-limited and
single-flight, with a hard ceiling on total runs for the window, teardown that
runs on failure as well as success, and a kill switch that degrades this site to
replay-only. If that backend ever misbehaves during judging, the correct response
is to turn it off and keep a working demo URL, not to debug under grading.

The negative control (RLS disabled) belongs only inside an isolated live run,
never against the shared replay corpus.
