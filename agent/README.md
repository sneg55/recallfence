# agent/

The support agent that causes the leak, and the auditor agent that explains it.

```bash
agent/support.sh alice "what is the maximum refund I can approve"            # the leak
agent/support.sh alice "..." --filtered                                      # correctly scoped
agent/support.sh alice "..." --write                                         # write a memory back
agent/support.sh alice "..." --write-as bob                                  # rejected by WITH CHECK

agent/auditor.sh explain [<run-id>]   what leaked, to whom, by which path
agent/auditor.sh propose              the policy set it recommends, and why
agent/auditor.sh narrate              the receipt, in plain language
```

## The model is never on the access-control path

Every fact either agent states is computed in SQL. The model is only ever handed
finished facts and asked to render them as prose, which is why `lib/model.sh`
exposes `model_polish <facts>` and deliberately has no function that takes a
question and returns an answer.

So an unavailable model changes the voice and nothing else. With no model
reachable the facts print verbatim, labelled `local-template-v1`, and every
number is identical. The banner says which voice produced the transcript, for the
same reason the receipt records its embedding model: a transcript must not be
able to present template output as model output.

Three backends are tried in order: **mantle**, the bedrock-mantle endpoint, which
is the one that answers on this account; **bedrock**, classic `bedrock-runtime`
Converse, still probed because the restriction blocking it is expected to clear;
then **template**. Set `RF_TEXT_BACKEND` to pin one and skip the probes.

Mantle authenticates with an API key rather than SigV4. Supply it as
`RF_MANTLE_API_KEY`, or in Secrets Manager under `<prefix>/service/bedrock-mantle`
with field `api_key`. The key is passed to `curl` through a config on stdin
rather than as an argument, because arguments are readable in `ps` for the life
of the call.

The default model is `google.gemma-4-31b` over `/openai/v1/chat/completions`.
Three things about that route were learned the hard way and are worth knowing
before changing `RF_MANTLE_TEXT_MODEL`: Anthropic models authenticate but return
`permission_error` on this account, an `OpenAI-Project` header makes valid
requests fail, and `openai.gpt-oss-*` ids are recognised yet rejected with
"isn't supported on this route". Being in the catalogue does not mean this route
serves it, so probe before switching.

The polish prompt says "do not add any fact that is not present". Worth being
clear-eyed that this is an instruction and not a guarantee, which is precisely
why the boundary is enforced in the database and every number in the receipt is
computed in SQL rather than asserted by a model.

## The support agent uses two connections, and that is the point

| Connection | What it may do |
|---|---|
| the tenant role | read and write `memories`, fenced by RLS |
| `rf_harness` | append to `retrievals`, with no SELECT on it |

The agent therefore cannot read back, verify or edit its own retrieval log. That
log is what makes class-2 contamination computable afterwards, so the audited
party holding write-only access to it is not an implementation detail.

## The write path is not decoration

Without it, every operation in this system is a read over a statically seeded
corpus, which is exactly the "database-security demo with an agent attached"
reading the design names as the likeliest way to lose.

A live write does three things narration cannot. It makes the memory agentic
rather than pre-loaded. It makes provenance captured at write time rather than
backfilled: `written_by`, `origin_tenant`, `session_id`, `source=agent_summary`,
`trust=model_derived` are set by the writer, in the row, at the moment it is
created. And it lets the boundary be shown holding on writes as well as reads.

`--write-as bob` is that last beat. An agent trying to write into another
tenant's memory is rejected by `tenant_write`'s `WITH CHECK` during query
execution, the same way a read is denied. The script treats a *successful*
foreign write as a fatal error, because that is what it would be.

## The auditor cites provenance, not just tenancy

Its output names `written_by`, `session_id`, `source` and `trust` for every
leaked row:

```
Principal alice retrieved row 21631392 belonging to tenant heidi, via the
semantic_unfiltered path. That row was written by fixture_loader on session
sess-heidi-33, source tool_call, trust external.
```

"This leaked row was model-derived, not user-confirmed, and was written by the
summarizer on Bob's session" is a materially better sentence than "this row
belongs to Bob", and it is the difference between provenance columns that are
used and provenance columns that are decoration.

It runs as `rf_auditor`: read-only over every evidence table, append-only over
receipts, and no privilege on the tenant data path at all. It discovers the
breach from `probe_results` rather than being told about it.

`propose` reads the policy set from `schema/004_policies.sql` rather than
composing its own, and it does not apply anything. A generator that wrote its own
version of the policies could emit SQL the schema does not contain, and that is
the one thing a reviewer of a security change has to be able to rule out.

## Files

| File | What |
|---|---|
| `support.sh` | Retrieve, log, answer, write back with provenance |
| `auditor.sh` | Explain the breach, propose the policy set, narrate the receipt |
| `lib/model.sh` | Bedrock with a deterministic fallback, and the honesty banner |
