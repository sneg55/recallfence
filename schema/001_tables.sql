-- RecallFence, step 1 of 4: tables.
--
-- Row-level security is deliberately NOT enabled here. The fixture loader runs
-- between this file and 004_policies.sql, which is why it needs no policy of its
-- own. Under FORCE ROW LEVEL SECURITY an operation with no applicable policy is
-- denied for every role including the table owner, so seeding after the policies
-- are in place would require a policy that exists only to let us cheat.
--
-- Idempotent. Safe to re-run.

-- ---------------------------------------------------------------------------
-- memories: the tenant-facing retrieval table, and the only table RLS fences.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS memories (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Also the RLS boundary key and the vector index prefix. Must equal a login
  -- role name: the policy compares `tenant = current_user`.
  tenant          STRING NOT NULL,
  content         STRING NOT NULL,

  -- 1024 is Titan Text Embeddings V2's default width and the width exercised at
  -- 48k rows in spikes 1 and 3. Spike 1 built a vector index at every width from
  -- 256 to 32,768, so the dimension is a model decision, not an index limit.
  embedding       VECTOR(1024),

  -- The exact Bedrock model ID that produced this row's embedding. Mixing model
  -- versions inside one vector index degrades retrieval with no error and no
  -- visible symptom. Recording it per row makes drift detectable.
  embedding_model STRING NOT NULL,

  -- Provenance (graft 1). `origin_tenant <> tenant` is a mis-attributed write:
  -- content produced while serving one customer that landed in another
  -- customer's memory. That divergence is quarantine class 1.
  written_by      STRING,
  origin_tenant   STRING,
  session_id      STRING,
  source          STRING,  -- tool_call | user_message | summarizer | import | agent_summary
  trust           STRING,  -- user_confirmed | model_derived | external
  ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prefix vector index. Retained deliberately even though the RLS query path
-- cannot use it: it serves the negative-control phase (RLS off) and it is where
-- the demo's "cost of the boundary" measurement comes from.
--
-- Spike 1, v26.2.0: with ANY RLS policy active CockroachDB will not use this
-- index. It is structurally excluded, not merely deprioritized on cost, and an
-- index hint under RLS errors with "cannot be used for this query". The apparent
-- reason is a correctness guarantee, since RLS-filtering an approximate ANN
-- candidate set could silently drop rows the tenant is entitled to. The tenant
-- gets an exact scan instead. Nothing downstream may assume this index is on the
-- fenced read path.
CREATE VECTOR INDEX IF NOT EXISTS memories_tenant_embedding_idx
  ON memories (tenant, embedding vector_l2_ops);

CREATE INDEX IF NOT EXISTS memories_session_idx ON memories (session_id);

-- ---------------------------------------------------------------------------
-- quarantined_memories (graft 3): out of the retrieval path entirely.
--
-- No RLS here, by design. The table is fenced at the privilege layer instead:
-- no tenant role holds any grant on it. Enabling FORCE RLS would reintroduce the
-- exact spike-2 failure this schema exists to avoid, where a missing policy
-- makes the quarantine mover report success and move zero rows.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS quarantined_memories (
  id                  UUID PRIMARY KEY,
  tenant              STRING NOT NULL,
  content             STRING NOT NULL,
  embedding           VECTOR(1024),
  embedding_model     STRING NOT NULL,
  written_by          STRING,
  origin_tenant       STRING,
  session_id          STRING,
  source              STRING,
  trust               STRING,
  ingested_at         TIMESTAMPTZ,

  quarantined_by_run  UUID NOT NULL,
  quarantine_reason   STRING NOT NULL,
  contaminated_into   STRING,
  quarantined_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT quarantine_reason_known CHECK (
    quarantine_reason IN ('misattributed_write', 'derived_from_foreign_read')
  )
);

-- ---------------------------------------------------------------------------
-- canaries: unique marker phrases per tenant, seeded once and stable across
-- every run, so a canary hit is comparable between phases. Not per-run.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS canaries (
  id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant    STRING NOT NULL,
  phrase    STRING NOT NULL UNIQUE,
  seeded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- probe_runs / probe_results: the breach matrix.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS probe_runs (
  run_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  phase       STRING NOT NULL,

  -- Carries the pinned embedding model ID, corpus size and probe LIMIT, so a
  -- receipt stays interpretable without the code that produced it.
  config      JSONB NOT NULL DEFAULT '{}'::JSONB,

  -- negative_control is the RLS-disabled control run. It is recorded like any
  -- other phase and excluded from the receipt's pass computation.
  CONSTRAINT phase_known CHECK (
    phase IN ('baseline', 'post_rls', 'post_quarantine', 'negative_control')
  )
);

CREATE TABLE IF NOT EXISTS probe_results (
  run_id               UUID NOT NULL REFERENCES probe_runs (run_id),
  principal            STRING NOT NULL,
  probe_type           STRING NOT NULL,
  returned_ids         UUID[],
  foreign_canary_hit   BOOL NOT NULL DEFAULT false,

  -- What the auditor role sees for the same predicate at the same moment.
  -- Load-bearing: RLS hiding a row and quarantine deleting a row both produce
  -- zero rows returned, so a tenant-visible "nothing" proves nothing on its own.
  -- Without this the receipt cannot tell a working boundary from an emptied table.
  auditor_ground_truth JSONB,

  -- Fail closed. An unexecuted probe is not a passed probe, and without a status
  -- column an exception and a clean pass are indistinguishable in the schema.
  status               STRING NOT NULL,
  error_text           STRING,
  evidence_json        JSONB,

  PRIMARY KEY (run_id, principal, probe_type),

  CONSTRAINT probe_type_known CHECK (
    probe_type IN ('semantic_unfiltered', 'semantic_filtered', 'direct_id', 'side_channel')
  ),
  CONSTRAINT status_known CHECK (status IN ('ok', 'error')),
  CONSTRAINT error_text_present_iff_error CHECK (
    (status = 'error') = (error_text IS NOT NULL)
  )
);

-- ---------------------------------------------------------------------------
-- retrievals: the agent's own read log, distinct from probe results.
--
-- This is what makes quarantine class 2 executable at all. Without a record of
-- which rows a session actually read, "the agent wrote this after reading a
-- foreign row" is not a computable predicate.
--
-- Append-only from the agent's side: the harness role holds INSERT and no
-- SELECT, so the audited party cannot read back or verify its own audit trail.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS retrievals (
  retrieval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id   STRING NOT NULL,
  principal    STRING NOT NULL,
  tenant       STRING NOT NULL,
  returned_ids UUID[],
  at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS retrievals_session_idx ON retrievals (session_id);

-- ---------------------------------------------------------------------------
-- receipts: the artifact a judge or a customer keeps. Changefeed source.
--
-- receipt_hash is a digest over the receipt body plus prev_receipt_hash, so
-- altering any earlier receipt breaks every later one. The chain, not the
-- bucket, is what makes the record tamper-evident.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS receipts (
  receipt_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  baseline_run        UUID REFERENCES probe_runs (run_id),
  post_rls_run        UUID REFERENCES probe_runs (run_id),
  post_quarantine_run UUID REFERENCES probe_runs (run_id),
  policy_sql          STRING,
  quarantined_ids     UUID[],
  passed              BOOL NOT NULL,
  emitted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  receipt_json        JSONB NOT NULL,
  prev_receipt_hash   STRING,
  receipt_hash        STRING NOT NULL UNIQUE
);
