#!/usr/bin/env bash
# RecallFence: the quarantine mover.
#
#   ./repair/quarantine.sh <detecting-run-id>            report only, changes nothing
#   ./repair/quarantine.sh <detecting-run-id> --apply    move the rows, in one transaction
#
# Runs as rf_remediation, the only role that can remove a memory. Dry by default:
# a tool whose entire output is a receipt saying the cleanup happened should make
# the operator ask for the cleanup.
#
# Contaminated rows are copied into `quarantined_memories` and deleted from
# `memories` in a single transaction, keyed to the run that detected the breach.
# Idempotent by construction rather than by flag: the second run finds nothing
# left to move, because the first one moved it.
#
# Once the policy set is applied neither class can recur. Class 1 is rejected at
# write time by tenant_write's WITH CHECK, which will not accept a row whose
# tenant is not the writer. Class 2 becomes impossible upstream, because the
# agent can no longer read a foreign row to derive from. So this is a one-time
# cleanup of a bounded historical set, not an ongoing sanitation process.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$HERE/../schema/lib/crsql.sh"
# shellcheck source=../schema/lib/creds.sh
source "$HERE/../schema/lib/creds.sh"
# shellcheck source=lib/predicate.sh
source "$HERE/lib/predicate.sh"

RUN_ID="${1:-}"
APPLY="${2:-}"
[[ -n "$RUN_ID" ]] || { sed -n '2,6p' "${BASH_SOURCE[0]}" >&2; exit 1; }

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n=== %s\n' "$*"; }

crsql_require
REMEDIATION_URL="$(url_for rf_remediation service)"
AUDITOR_URL="$(url_for rf_auditor service)"

# The run has to exist, or the quarantine is keyed to nothing and the receipt
# cannot say what detected it.
[[ "$(run_as "$AUDITOR_URL" \
      "SELECT count(*) FROM probe_runs WHERE run_id = '$RUN_ID';" | tail -1)" == 1 ]] \
  || die "no probe_run with run_id $RUN_ID. Quarantine is keyed to the run that detected the breach."

# ---------------------------------------------------------------------------

say "candidates (as rf_remediation, which sees every row via remediation_read)"
run_as "$REMEDIATION_URL" "
SELECT 'misattributed_write' AS reason, count(*) AS rows
  FROM memories m WHERE $PRED_CLASS1
UNION ALL
SELECT 'derived_from_foreign_read', count(*)
  FROM memories m WHERE $PRED_CLASS2;" | tr ',' '\t' | expand -t 30

say "provenance of what would move"
run_as "$REMEDIATION_URL" "
SELECT m.tenant, m.origin_tenant, m.written_by, m.source, m.trust, count(*) AS rows
  FROM memories m WHERE $PRED_EITHER
 GROUP BY 1,2,3,4,5 ORDER BY 1,2;" | tr ',' '\t' | expand -t 16

if [[ "$APPLY" != "--apply" ]]; then
  printf '\nreport only. Re-run with --apply to move these rows.\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# The move. One transaction, so the copy and the delete cannot disagree.
#
# The DELETE repeats the predicate rather than reading back what was just
# inserted, and that is the grant matrix showing through rather than sloppiness.
# rf_remediation holds INSERT on quarantined_memories and no SELECT, so
# `DELETE ... WHERE id IN (SELECT id FROM quarantined_memories ...)` is denied
# with 42501. Inside one transaction the repeated predicate selects exactly the
# rows just copied, so the narrower grant costs nothing: the role that removes
# evidence still cannot read the evidence store back.
# ---------------------------------------------------------------------------

say "moving"
OUT="$(run_as "$REMEDIATION_URL" "
BEGIN;

INSERT INTO quarantined_memories
  (id, tenant, content, embedding, embedding_model, written_by, origin_tenant,
   session_id, source, trust, ingested_at,
   quarantined_by_run, quarantine_reason, contaminated_into)
SELECT m.id, m.tenant, m.content, m.embedding, m.embedding_model, m.written_by,
       m.origin_tenant, m.session_id, m.source, m.trust, m.ingested_at,
       '$RUN_ID'::UUID, 'misattributed_write', NULL
  FROM memories m WHERE $PRED_CLASS1;

INSERT INTO quarantined_memories
  (id, tenant, content, embedding, embedding_model, written_by, origin_tenant,
   session_id, source, trust, ingested_at,
   quarantined_by_run, quarantine_reason, contaminated_into)
SELECT m.id, m.tenant, m.content, m.embedding, m.embedding_model, m.written_by,
       m.origin_tenant, m.session_id, m.source, m.trust, m.ingested_at,
       '$RUN_ID'::UUID, 'derived_from_foreign_read', m.tenant
  FROM memories m WHERE $PRED_CLASS2;

DELETE FROM memories m WHERE $PRED_EITHER;

COMMIT;")" || die "quarantine transaction failed: $(tr '\n' '|' <<<"$OUT")"
printf '%s\n' "$OUT"

# ---------------------------------------------------------------------------
# Verified through the auditor, not from what this process believes it did.
# ---------------------------------------------------------------------------

say "after (as rf_auditor)"
RF_SQL_URL="$AUDITOR_URL" crsql_stdin --format=table <<SQL
SELECT quarantine_reason, count(*) AS quarantined, count(DISTINCT tenant) AS tenants
  FROM quarantined_memories WHERE quarantined_by_run = '$RUN_ID'
 GROUP BY 1 ORDER BY 1;
SELECT (SELECT count(*) FROM memories m WHERE $PRED_EITHER) AS contaminated_left,
       (SELECT count(*) FROM memories)                      AS memories_now;
SQL

LEFT="$(run_as "$AUDITOR_URL" "SELECT count(*) FROM memories m WHERE $PRED_EITHER;" | tail -1)"
[[ "$LEFT" == 0 ]] || die "quarantine ran but $LEFT contaminated row(s) remain"
printf '\nno contaminated rows remain\n'
