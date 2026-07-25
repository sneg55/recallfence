#!/usr/bin/env bash
# RecallFence: recording the breach matrix.
#
# Sourced by run.sh. Everything here writes as rf_harness, which holds no
# privilege on `memories` at all: the account that records the breach cannot
# read the rows the breach is about.
#
# No `set -e`. This file is sourced and options leak into the caller.

# SQL string literal. Evidence JSON is machine-built and free of apostrophes
# today; doubling them anyway costs nothing and removes a whole class of
# "why did the harness stop mid-run" from the failure modes.
#
# The quote goes through a variable rather than a backslash escape. This was
# written as `${1//\'/\'\'}`, which looks equivalent and is not: on bash 3.2 that
# substitutes a literal \'\' and the statement dies at the backslash. So the
# doubling this comment claims was not happening, and the failure class it claims
# to remove was still open. Found when the receipt writer hit it for real on
# policy SQL containing an apostrophe.
rec_lit() { local q="'" s="$1"; s="${s//$q/$q$q}"; printf '%s%s%s' "$q" "$s" "$q"; }

# rec_open <harness url> <phase> <config json> -> run_id on stdout
rec_open() {
  local url="$1" phase="$2" config="$3" out
  out="$(run_as "$url" "INSERT INTO probe_runs (phase, config)
                        VALUES ($(rec_lit "$phase"), $(rec_lit "$config")::JSONB)
                        RETURNING run_id;")" || { printf '%s\n' "$out" >&2; return 1; }
  printf '%s' "$out" | tail -n 1 | tr -d '[:space:]'
}

rec_close() {
  run_as "$1" "UPDATE probe_runs SET finished_at = now() WHERE run_id = $(rec_lit "$2");" >/dev/null
}

# rec_result <harness url> <run_id> <principal> <probe_type> <returned_ids csv>
#            <hit t|f> <ground truth json> <status> <error text> <evidence json>
#
# A plain INSERT, deliberately. This started as an upsert on the
# (run_id, principal, probe_type) key, for resumability, and the grant matrix
# refused it: rf_harness holds SELECT and INSERT on probe_results and no UPDATE,
# so ON CONFLICT DO UPDATE fails with 42501.
#
# The right response was to drop the upsert, not to widen the grant. Every run
# opens a fresh run_id, so the conflict case never arises in practice, and the
# upsert was buying nothing. Widening a grant to enable an unused convenience is
# exactly the stray-GRANT hazard this project exists to point at: it would also
# have converted a duplicate-write bug from a loud key violation into a silent
# overwrite of evidence.
rec_result() {
  local url="$1" run="$2" principal="$3" ptype="$4" ids="$5" hit="$6" \
        truth="$7" status="$8" err="$9" evidence="${10}" idlit errlit

  if [[ -n "$ids" ]]; then idlit="ARRAY[$ids]::UUID[]"; else idlit="ARRAY[]::UUID[]"; fi
  if [[ "$status" == error ]]; then errlit="$(rec_lit "$err")"; else errlit="NULL"; fi

  # A boolean this function cannot recognise means a caller computed it wrong,
  # and an empty string here produces a SQL syntax error rather than a row. The
  # first version of this discarded that error, so a whole run recorded nothing
  # while printing a clean-looking matrix. Fail on the value, not on the SQL.
  case "$hit" in true|false) ;; *) printf 'rec_result: bad foreign_canary_hit %q for %s/%s\n' \
    "$hit" "$principal" "$ptype" >&2; return 1 ;; esac

  local out
  out="$(run_as "$url" "INSERT INTO probe_results
      (run_id, principal, probe_type, returned_ids, foreign_canary_hit,
       auditor_ground_truth, status, error_text, evidence_json)
    VALUES ($(rec_lit "$run"), $(rec_lit "$principal"), $(rec_lit "$ptype"),
            $idlit, $hit, $(rec_lit "$truth")::JSONB, $(rec_lit "$status"),
            $errlit, $(rec_lit "$evidence")::JSONB);")" || {
    printf 'rec_result: could not record %s/%s: %s\n' \
      "$principal" "$ptype" "$(tr '\n' '|' <<<"$out")" >&2
    return 1
  }
}

# rec_matrix <auditor url> <run_id>
#
# Read back through the auditor, not from what this process believes it wrote.
# A harness that prints its own in-memory idea of the matrix would still print a
# clean run after failing to record one.
rec_matrix() {
  RF_SQL_URL="$1" crsql_stdin --format=table <<SQL
SELECT principal, probe_type,
       coalesce(array_length(returned_ids, 1), 0) AS returned,
       foreign_canary_hit AS canary_hit,
       (auditor_ground_truth->>'visible_to_auditor')::INT AS auditor_sees,
       status
  FROM probe_results WHERE run_id = $(rec_lit "$2")
 ORDER BY principal, probe_type;
SQL
}
