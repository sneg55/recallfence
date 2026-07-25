#!/usr/bin/env bash
# RecallFence: are these three runs a thing worth receipting at all?
#
# Sourced by receipt.sh, and run before any clause is evaluated. Separate from
# clauses.sh on purpose: that file scores evidence, this one decides whether the
# evidence is admissible. Scoring inadmissible input is how a verdict ends up
# describing something other than what it claims to describe.
#
# Every check here exists because it failed. A code review of the first version
# found that swapping the post_rls and post_quarantine arguments produced a
# passing receipt whose labelled fields named the wrong runs, and that nothing
# required the supplied runs to have the phases they were passed as, to be
# finished, or to cover the same principals.
#
# All checks fail closed: unknown, missing or NULL is not ok.
#
# No `set -e`. This file is sourced and options leak into the caller.

# preflight_sql <baseline> <post_rls> <post_quarantine>
#
# One row per check: check_name, ok. The caller refuses to emit if any ok is not
# true, and prints the failing names.
preflight_sql() {
  local base="$1" prls="$2" pq="$3"
  cat <<SQL
WITH want(pos, run_id, want_phase) AS (
  VALUES (1, '$base'::UUID, 'baseline'),
         (2, '$prls'::UUID, 'post_rls'),
         (3, '$pq'::UUID,   'post_quarantine')
),
runs AS (
  SELECT w.pos, w.run_id, w.want_phase, r.phase AS got_phase, r.finished_at,
         (r.config->>'tenants')::INT AS cfg_tenants
    FROM want w LEFT JOIN probe_runs r ON r.run_id = w.run_id
),
res AS (
  SELECT w.run_id, w.want_phase, x.principal, x.probe_type, x.evidence_json
    FROM want w JOIN probe_results x ON x.run_id = w.run_id
),
perrun AS (
  SELECT run_id, want_phase,
         count(*)                                          AS n,
         count(DISTINCT principal)                         AS principals,
         count(DISTINCT probe_type)                        AS ptypes,
         count(*) FILTER (WHERE evidence_json IS NULL)      AS null_ev
    FROM res GROUP BY run_id, want_phase
)
-- Three different run IDs. Passing one ID three times must not look like three
-- phases that happen to agree with each other.
SELECT 'runs_distinct' AS check_name,
       ((SELECT count(DISTINCT run_id) FROM want) = 3) AS ok
UNION ALL SELECT 'runs_exist',
       NOT EXISTS (SELECT 1 FROM runs WHERE got_phase IS NULL)
-- The run passed as the baseline must actually BE the baseline. Without this a
-- negative_control run, recorded with RLS deliberately disabled, can be handed
-- in as the baseline and the receipt will happily attest it.
UNION ALL SELECT 'phase_matches_position',
       NOT EXISTS (SELECT 1 FROM runs WHERE got_phase IS DISTINCT FROM want_phase)
-- An unfinished run is still being written to. Its counts are not a result yet.
UNION ALL SELECT 'runs_finished',
       NOT EXISTS (SELECT 1 FROM runs WHERE finished_at IS NULL)
UNION ALL SELECT 'all_three_have_results',
       ((SELECT count(*) FROM perrun) = 3)
UNION ALL SELECT 'four_probe_types_each',
       NOT EXISTS (SELECT 1 FROM perrun WHERE ptypes <> 4)
-- count(*) = principals x probe_types, rather than count(*) = config.tenants x 4.
-- The old form let a missing probe for one principal be offset by an extra row
-- for another, and took the expected total from a config the run asserts about
-- itself.
UNION ALL SELECT 'no_missing_or_extra_probes',
       NOT EXISTS (SELECT 1 FROM perrun WHERE n <> principals * ptypes)
UNION ALL SELECT 'evidence_present',
       NOT EXISTS (SELECT 1 FROM perrun WHERE null_ev > 0)
UNION ALL SELECT 'principal_count_matches_config',
       NOT EXISTS (SELECT 1 FROM perrun p JOIN runs r ON r.run_id = p.run_id
                    WHERE p.principals IS DISTINCT FROM r.cfg_tenants)
-- Comparing phases only means anything if they probed the same principals.
UNION ALL SELECT 'principal_in_all_three_phases',
       NOT EXISTS (SELECT 1 FROM res GROUP BY principal
                    HAVING count(DISTINCT want_phase) <> 3)

-- Ground truth for "who should have been probed", from a table the harness may
-- read and may not write.
--
-- Every other completeness check above measures the run against numbers the run
-- reports about itself, so three runs each claiming a tenant count of 1 and
-- containing one principal by four probes satisfied all of them. An entire
-- tenant could be omitted, or replaced by an invented principal present in all
-- three phases, and nothing noticed. The canaries table holds one row per real
-- tenant, seeded once, and rf_harness holds only SELECT on it.
--
-- No backticks anywhere below this line: the heredoc carrying this SQL is
-- unquoted so the run IDs interpolate, which means a backtick would be command
-- substitution and its output would land in the middle of the statement.
UNION ALL SELECT 'probed_every_seeded_tenant',
       NOT EXISTS (SELECT tenant FROM canaries
                    EXCEPT SELECT DISTINCT principal FROM res)
UNION ALL SELECT 'no_invented_principals',
       NOT EXISTS (SELECT DISTINCT principal FROM res
                    EXCEPT SELECT tenant FROM canaries);
SQL
}
