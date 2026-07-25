#!/usr/bin/env bash
# RecallFence: the auditor agent.
#
#   agent/auditor.sh explain [<run-id>]   what leaked, to whom, by which path
#   agent/auditor.sh propose              the policy set it recommends, and why
#   agent/auditor.sh narrate              read the receipt back in plain language
#
# Runs as rf_auditor: read-only over every evidence table, append-only over
# receipts, and no privilege on the tenant data path at all.
#
# It cites `written_by` and `trust` by name rather than only the tenant. "This
# leaked row was model-derived, not user-confirmed, and was written by the
# summarizer on Bob's session" is a materially better sentence than "this row
# belongs to Bob", and it is the difference between provenance columns that are
# used and provenance columns that are decoration.
#
# Every fact below is computed in SQL. The model is only ever handed finished
# facts to rephrase, so an unavailable model changes the voice and nothing else.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$ROOT/schema/lib/crsql.sh"
# shellcheck source=../schema/lib/creds.sh
source "$ROOT/schema/lib/creds.sh"
# shellcheck source=../audit/lib/sqlio.sh
source "$ROOT/audit/lib/sqlio.sh"
# shellcheck source=../audit/lib/clauses.sh
source "$ROOT/audit/lib/clauses.sh"
# shellcheck source=lib/model.sh
source "$HERE/lib/model.sh"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

crsql_require || exit 1
AUDITOR_URL="${RF_AUDITOR_URL:-$(url_for rf_auditor service)}"

# The most recent baseline run, unless one is named.
run_id() {
  [[ -n "${1:-}" ]] && { printf '%s' "$1"; return 0; }
  sql_scalar "$AUDITOR_URL" "SELECT run_id FROM probe_runs
                              WHERE phase = 'baseline' AND finished_at IS NOT NULL
                              ORDER BY started_at DESC LIMIT 1;"
}

cmd_explain() {
  local run; run="$(run_id "${1:-}")"
  [[ -n "$run" ]] || die "no finished baseline run to explain"
  say "breach report for run $run"
  model_banner

  # The leaked rows, with the provenance of each. One query; the agent discovers
  # the breach from probe_results rather than being told about it.
  local facts
  facts="$(sql_b64 "$AUDITOR_URL" "(
    SELECT coalesce(string_agg(line, E'\n'), 'no breaches recorded in this run')
      FROM (
        SELECT DISTINCT
          'Principal ' || pr.principal || ' retrieved row ' || left(m.id::STRING, 8) ||
          ' belonging to tenant ' || m.tenant ||
          ', via the ' || pr.probe_type || ' path.' ||
          ' That row was written by ' || coalesce(m.written_by, 'unknown') ||
          ' on session ' || coalesce(m.session_id, 'unknown') ||
          ', source ' || coalesce(m.source, 'unknown') ||
          ', trust ' || coalesce(m.trust, 'unknown') || '.' AS line
        FROM probe_results pr
        JOIN probe_runs r ON r.run_id = pr.run_id
        CROSS JOIN LATERAL jsonb_array_elements(coalesce(pr.evidence_json, '[]'::JSONB)) ev
        JOIN memories m ON m.id = (ev->>'id')::UUID
       WHERE pr.run_id = $(lit "$run")
         AND ev->>'tenant' IS NOT NULL
         AND ev->>'tenant' <> pr.principal
       LIMIT 12) s)")" || die "could not read the evidence"

  printf '%s\n' "$facts" | sed 's/^/  /'

  say "what this means"
  model_polish "$facts" \
    "Summarise this breach for an operator in three sentences. Say which query path caused it, and name the trust level of the leaked rows." \
  | sed 's/^/  /'

  say "the distinction that matters"
  printf '  A row leaking is exposure. A row being wrong is contamination.\n'
  printf '  RLS repairs the first. Quarantine repairs the second. They are\n'
  printf '  repaired separately and probed separately, or neither result means\n'
  printf '  anything: an emptied table also returns no rows.\n'
}

cmd_propose() {
  say "proposed policy set"
  model_banner
  printf '  Read from schema/004_policies.sql, not composed here. A generator that\n'
  printf '  wrote its own version could emit SQL the schema does not contain, and\n'
  printf '  that is the one thing a reviewer has to be able to rule out.\n\n'
  sed -n '/^CREATE POLICY/,/;/p' "$ROOT/schema/004_policies.sql" | sed 's/^/  /'

  say "why each one"
  cat <<'WHY' | sed 's/^/  /'
tenant_isolation   SELECT, tenant = current_user. The boundary itself.
tenant_write       INSERT WITH CHECK, tenant = current_user. Rejects a write
                   aimed at another tenant during query execution.
auditor_read       SELECT for rf_auditor. Without it the auditor's ground truth
                   is empty in every phase and the receipt cannot tell a working
                   boundary from an emptied table.
remediation_read   SELECT for rf_remediation, so the mover can find what it moves.
quarantine_delete  DELETE for rf_remediation. The only role that can remove a row.
WHY

  say "approval"
  printf '  This tool proposes. It does not apply.\n'
  printf '  Run: repair/policy.sh apply --approve\n'
}

cmd_narrate() {
  local body
  body="$(sql_b64 "$AUDITOR_URL" "(SELECT receipt_json FROM receipts
                                    ORDER BY emitted_at DESC, receipt_id DESC LIMIT 1)")"
  [[ -n "$body" && "$body" != null ]] || die "no receipt yet. Run audit/receipt.sh emit first."

  say "receipt"
  model_banner
  local facts
  facts="$(jq -r '
    "Verdict: passed=\(.passed).",
    "Baseline recorded \(.phases.baseline.breaches) breaching probes over \(.phases.baseline.foreign_rows) foreign rows.",
    "After RLS: \(.phases.post_rls.breaches) breaches. After quarantine: \(.phases.post_quarantine.breaches).",
    "Quarantine moved \(.quarantine.count) rows: \(.quarantine.misattributed_write) misattributed writes and \(.quarantine.derived_from_foreign_read) derived from a foreign read.",
    "All four clauses: \([.clauses | to_entries[] | "\(.key)=\(.value)"] | join(", "))."
    ' <<<"$body")"
  printf '%s\n' "$facts" | sed 's/^/  /'

  say "in plain language"
  model_polish "$facts" \
    "Explain this isolation receipt to a customer in four sentences. Be clear that a pass required proving the failure existed first." \
  | sed 's/^/  /'
}

case "${1:-}" in
  explain) shift; cmd_explain "$@" ;;
  propose) shift; cmd_propose "$@" ;;
  narrate) shift; cmd_narrate "$@" ;;
  *) sed -n '2,7p' "${BASH_SOURCE[0]}" >&2; exit 1 ;;
esac
