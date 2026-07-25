#!/usr/bin/env bash
# RecallFence: the evidence bundle.
#
# Sourced by cli/rf. One JSON document holding everything the dashboard shows:
# the receipt, the breach matrix, the leaked rows with their provenance, the
# quarantine lineage, the policy set and the live RLS state.
#
# The bundle exists so that rendering never depends on a database. `rf` builds it
# from the cluster or loads it from a file and renders identically either way,
# which is what makes the CLI a real fallback for the web layer rather than a
# second implementation of it, and what lets the deployed site replay a recorded
# run after the cluster is paused, reclaimed or torn down.
#
# The three run IDs come from the latest receipt rather than from arguments. The
# receipt is what says which runs constitute a result, so anything reading a
# different set is reading something the receipt never attested.
#
# No `set -e`. This file is sourced and options leak into the caller.

# bundle_sql -> SQL returning the whole bundle as one JSON value.
#
# Built in the database rather than stitched together in bash. Six round trips
# assembled client-side could interleave with a live run and produce a bundle
# whose matrix and whose RLS state disagree about which world they are in.
bundle_sql() {
  cat <<SQL
WITH r AS (
  SELECT * FROM receipts ORDER BY emitted_at DESC, receipt_id DESC LIMIT 1
), ids AS (
  SELECT (SELECT baseline_run FROM r)        AS b,
         (SELECT post_rls_run FROM r)        AS p,
         (SELECT post_quarantine_run FROM r) AS q
), ev AS (
  -- foreign_rows and breach are the very expressions the receipt's clauses use,
  -- interpolated from audit/lib/clauses.sh rather than restated here. They were
  -- restated once, and two copies of a security predicate agree only until
  -- someone edits one of them.
  SELECT rr.phase, pr.principal, pr.probe_type, pr.foreign_canary_hit,
         pr.status, pr.evidence_json, pr.returned_ids,
         $PR_FOREIGN_ROWS                                           AS foreign_rows,
         $PR_BREACH                                                 AS breach,
         (pr.auditor_ground_truth->>'visible_to_auditor')::INT      AS auditor_sees
    FROM probe_results pr
    JOIN probe_runs rr ON rr.run_id = pr.run_id
   WHERE pr.run_id IN ((SELECT b FROM ids), (SELECT p FROM ids), (SELECT q FROM ids))
), leaked AS (
  -- Rows a foreign principal actually saw at baseline. This is the set the
  -- evidence panel is about, so provenance is fetched for exactly it.
  SELECT DISTINCT unnest(returned_ids) AS id
    FROM ev WHERE phase = 'baseline' AND breach
)
SELECT jsonb_build_object(
  'receipt',      (SELECT receipt_json FROM r),
  'receipt_meta', (SELECT jsonb_build_object(
                     'receipt_id', receipt_id, 'receipt_hash', receipt_hash,
                     'prev_receipt_hash', prev_receipt_hash, 'emitted_at', emitted_at)
                   FROM r),
  'evidence',     (SELECT coalesce(jsonb_agg(jsonb_build_object(
                     'phase', phase, 'principal', principal, 'probe_type', probe_type,
                     'breach', breach, 'foreign_rows', foreign_rows,
                     'canary_hit', foreign_canary_hit, 'status', status,
                     'auditor_sees', auditor_sees, 'returned', evidence_json)
                     ORDER BY phase, principal, probe_type), '[]'::JSONB) FROM ev),

  -- Provenance is graft 1 surfacing: a leaked row can say who wrote it, in which
  -- session, from what source and at what trust level. Read from memories and
  -- from quarantined_memories both, because a row that was moved out is still
  -- part of the lineage and would otherwise vanish from the evidence panel.
  'provenance',   (SELECT coalesce(jsonb_agg(pv ORDER BY pv->>'tenant', pv->>'id'), '[]'::JSONB)
                   FROM (
                     SELECT jsonb_build_object(
                       'id', m.id, 'tenant', m.tenant, 'origin_tenant', m.origin_tenant,
                       'session_id', m.session_id, 'source', m.source, 'trust', m.trust,
                       'written_by', m.written_by, 'ingested_at', m.ingested_at,
                       'content', m.content, 'quarantined', false) AS pv
                       FROM memories m WHERE m.id IN (SELECT id FROM leaked)
                     UNION ALL
                     SELECT jsonb_build_object(
                       'id', q.id, 'tenant', q.tenant, 'origin_tenant', q.origin_tenant,
                       'session_id', q.session_id, 'source', q.source, 'trust', q.trust,
                       'written_by', q.written_by, 'ingested_at', q.ingested_at,
                       'content', q.content, 'quarantined', true)
                       FROM quarantined_memories q WHERE q.id IN (SELECT id FROM leaked)
                   ) s),

  'quarantine',   (SELECT coalesce(jsonb_agg(jsonb_build_object(
                     'id', id, 'tenant', tenant, 'origin_tenant', origin_tenant,
                     'session_id', session_id, 'source', source, 'trust', trust,
                     'reason', quarantine_reason, 'contaminated_into', contaminated_into)
                     ORDER BY quarantine_reason, id), '[]'::JSONB)
                   FROM quarantined_memories
                   WHERE quarantined_by_run = (SELECT b FROM ids)),

  'corpus',       jsonb_build_object(
                     'rows',    (SELECT count(*) FROM memories),
                     'tenants', (SELECT coalesce(jsonb_agg(DISTINCT tenant), '[]'::JSONB) FROM memories),
                     'model',   (SELECT DISTINCT embedding_model FROM memories LIMIT 1)),

  -- Measured, not assumed. A bundle that reported the policy set from a file
  -- would describe the repo rather than the cluster, and the one question this
  -- panel answers is whether the fence is actually up right now.
  'rls',          jsonb_build_object(
                     'enabled',  (SELECT relrowsecurity FROM pg_class WHERE relname = 'memories'),
                     'forced',   (SELECT relforcerowsecurity FROM pg_class WHERE relname = 'memories'),
                     'policies', (SELECT coalesce(jsonb_agg(policyname ORDER BY policyname), '[]'::JSONB)
                                    FROM pg_policies WHERE tablename = 'memories'))
)
SQL
}

# bundle_from_db <auditor url> -> bundle JSON on stdout
bundle_from_db() { sql_b64 "$1" "($(bundle_sql))"; }
