#!/usr/bin/env bash
# RecallFence: what `passed` means, as SQL, in one place.
#
# Sourced by receipt.sh. The four clauses below are the spec's definition of a
# passing receipt, and they are defined here once so the boolean stamped into the
# receipt and the boolean an operator can recompute by hand are the same query.
#
# The obvious definition ("no foreign canary hits after repair") is insufficient,
# and clause 1 is the reason. A harness that errored silently and recorded nothing
# also produces no hits, so "no hits" alone rubber-stamps a run that never ran.
# A pass has to prove the failure existed first.
#
# Every fragment is parameterized by the three run IDs and reads only from
# probe_runs / probe_results, which rf_auditor may SELECT. `negative_control` is
# deliberately absent: it is recorded like any phase and excluded from the pass.
#
# No `set -e`. This file is sourced and options leak into the caller.

# What counts as a breach, defined once.
#
# The primary signal is a row the caller should never have been able to read:
# present in that probe's own evidence, belonging to a different tenant. It is
# read off the recorded evidence rather than off a phrase match, which makes it
# independent of whether the embedding model cooperated on the day. The canary
# phrase remains recorded and is reported alongside, but it is corroboration
# rather than the criterion: with a non-semantic fallback embedder the nearest
# neighbours are arbitrary filler rows that carry no phrase, so a phrase-only
# score reported a 35-row cross-tenant leak in `semantic_unfiltered` as clean.
#
# The side_channel disjunct is load-bearing. That probe's evidence is a list of
# tables, not of rows, so it carries no tenant key and contributes zero foreign
# rows however badly it fails. Dropping the disjunct would silently retire the
# regression guard against a stray GRANT on the evidence tables, which is exactly
# the change nobody reviews.
PR_FOREIGN_ROWS="(SELECT count(*) FROM jsonb_array_elements(coalesce(pr.evidence_json, '[]'::JSONB)) fr
                   WHERE fr->>'tenant' IS NOT NULL
                     AND fr->>'tenant' <> pr.principal)"

# The side_channel term reads the evidence, not just the recorded boolean.
#
# That probe's evidence is a list of tables carrying `readable`, so the boolean
# and the evidence can in principle disagree. They are OR'd rather than trusted
# individually, which resolves any contradiction towards "breach". Fail closed:
# the wrong direction here reports isolation that was never demonstrated.
PR_SIDE_READ="(pr.probe_type = 'side_channel' AND (
                 pr.foreign_canary_hit
                 OR EXISTS (SELECT 1
                              FROM jsonb_array_elements(coalesce(pr.evidence_json, '[]'::JSONB)) sc
                             WHERE sc->>'readable' = 'true')))"

# NULL evidence is a breach, not a clean probe.
#
# `jsonb_array_elements(NULL)` yields zero rows, so without this a probe whose
# evidence went missing would count zero foreign rows and be scored clean. That is
# fail-open in the one place this project cannot afford it. The wellformedness
# guard below rejects such a run outright; this term means that even if something
# ever routed around the guard, the error lands on the safe side.
PR_BREACH="($PR_FOREIGN_ROWS > 0
            OR $PR_SIDE_READ
            OR pr.evidence_json IS NULL)"

# clauses_sql <baseline> <post_rls> <post_quarantine>
#
# Emits one row: c1, c2, c3, c4, passed. All booleans.
clauses_sql() {
  local base="$1" prls="$2" pq="$3"
  cat <<SQL
WITH clauses AS (
  SELECT
    -- 1. At least one breach in baseline. The clause that separates a receipt
    --    from a rubber stamp: a demonstrated failure to repair.
    (SELECT count(*) FILTER (WHERE $PR_BREACH) > 0
       FROM probe_results pr WHERE pr.run_id = '$base')                          AS c1,

    -- 2. Zero breaches in post_rls and post_quarantine, across every principal
    --    and every probe type, side_channel included.
    (SELECT count(*) FILTER (WHERE $PR_BREACH) = 0
       FROM probe_results pr WHERE pr.run_id IN ('$prls', '$pq'))                AS c2,

    -- 3. The auditor still saw the foreign rows at post_rls, proving the boundary
    --    hid them rather than something having deleted them. Quarantine has not
    --    run yet at post_rls, so a foreign row in the auditor's ground truth is a
    --    row that still physically exists while the tenant reads nothing.
    (SELECT count(*) > 0 FROM probe_results
       WHERE run_id = '$prls'
         AND EXISTS (
           SELECT 1 FROM jsonb_array_elements(auditor_ground_truth->'rows') AS gt
            WHERE gt->>'tenant' <> principal))                                   AS c3,

    -- 4. Every probe in every counted phase has status = ok. Fail closed: an
    --    unexecuted probe is not a passed probe.
    (SELECT count(*) FILTER (WHERE pr.status <> 'ok') = 0
       FROM probe_results pr WHERE pr.run_id IN ('$base', '$prls', '$pq'))       AS c4
)
SELECT c1, c2, c3, c4, (c1 AND c2 AND c3 AND c4) AS passed FROM clauses;
SQL
}

# shape_sql <baseline> <post_rls> <post_quarantine>
#
# A wellformedness precondition, not a fifth clause. It emits one row per phase
# with the probe count and the tenant count the run's own config claims, so the
# writer can refuse to receipt a malformed set of runs rather than pass it
# vacuously. Clauses 2 and 4 are both satisfied by an empty phase; this is what
# stops "no rows recorded" from being read as "no failures found".
#
# `null_ev` is the other half of that. A probe row with no evidence records
# nothing about what the principal saw, and every signal computed from evidence
# reads it as clean. A phase is wellformed only if every probe in it actually
# carries its evidence.
shape_sql() {
  local base="$1" prls="$2" pq="$3"
  cat <<SQL
SELECT r.phase,
       count(*)                                          AS probes,
       (r.config->>'tenants')::INT * 4                   AS expected,
       count(*) FILTER (WHERE pr.evidence_json IS NULL)  AS null_ev,
       (count(*) = (r.config->>'tenants')::INT * 4
        AND count(*) FILTER (WHERE pr.evidence_json IS NULL) = 0) AS ok
  FROM probe_results pr JOIN probe_runs r ON r.run_id = pr.run_id
 WHERE pr.run_id IN ('$base', '$prls', '$pq')
 GROUP BY r.phase, r.config
 ORDER BY r.phase;
SQL
}

# matrix_sql <baseline> <post_rls> <post_quarantine>
#
# The full breach matrix across the three counted phases as a single JSON array,
# ordered deterministically so the array is canonical content and the receipt
# hash is stable across a read-back through JSONB. This array is the evidence a
# judge or a customer keeps: 96 rows saying exactly what each principal saw, what
# the auditor saw at the same instant, and whether it was a hit.
#
# No trailing semicolon: this is always consumed as a scalar subquery by the
# receipt writer's base64 reader, never run on its own. `m` is the row alias;
# `row` is a reserved word in CockroachDB and cannot be one.
matrix_sql() {
  local base="$1" prls="$2" pq="$3"
  cat <<SQL
SELECT coalesce(jsonb_agg(m ORDER BY phase, principal, probe_type), '[]'::JSONB)
  FROM (
    SELECT r.phase,
           pr.principal,
           pr.probe_type,
           coalesce(array_length(pr.returned_ids, 1), 0)              AS returned,
           $PR_FOREIGN_ROWS                                           AS foreign_rows,
           $PR_BREACH                                                 AS breach,
           pr.foreign_canary_hit                                      AS canary_hit,
           (pr.auditor_ground_truth->>'visible_to_auditor')::INT      AS auditor_sees,
           pr.status
      FROM probe_results pr JOIN probe_runs r ON r.run_id = pr.run_id
     WHERE pr.run_id IN ('$base', '$prls', '$pq')
  ) m
SQL
}
