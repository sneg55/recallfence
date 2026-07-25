# skills/

An Agent Skill distilled from building this project.

```
auditing-multi-tenant-agent-memory/SKILL.md
```

## What it is

Portable guidance for auditing, testing or designing tenant isolation in an
agent's memory store: proving isolation rather than asserting it, telling
exposure apart from contamination, and the specific ways an isolation test can
pass while testing nothing.

Install by copying the directory into `~/.claude/skills/`, or point your agent
harness at it wherever it looks for skills.

## Why it is not a summary of this repo

Every item in it is a mistake that was actually made here, or a trap that was
actually hit, and each is stated so it transfers to a different stack. Nothing in
it depends on CockroachDB, on this schema, or on bash.

The ones that cost the most time:

- Two enforcement layers that answer in opposite ways, so "I caught an exception"
  is not evidence of being blocked, and a stray `GRANT` silently converts a loud
  failure into a quiet one.
- Zero rows returned proves nothing without independent ground truth, because a
  working boundary, an empty table and a typo are indistinguishable from the
  caller's side.
- A canary-phrase score only fires if retrieval returns the marked row. With a
  non-semantic fallback embedder it did not, and a 35-row cross-tenant leak was
  reported clean. Score on row ownership; keep the phrase as corroboration.
- The vendor CLI handed out `rolsuper` and `rolbypassrls` by default, which is the
  exact failure this project exists to prevent, introduced by the tool used to
  set it up.
- Missing probes and NULL evidence scored as clean until a review found it. Fail
  closed, or a verdict eventually describes something other than what it claims.

## Scope

Guidance only. It contains no credentials, no cluster details, and nothing
specific to this deployment.
