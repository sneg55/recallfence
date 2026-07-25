#!/usr/bin/env bash
# RecallFence: the isolation receipt.
#
#   ./audit/receipt.sh emit    <baseline> <post_rls> <post_quarantine>
#   ./audit/receipt.sh explain <baseline> <post_rls> <post_quarantine>
#   ./audit/receipt.sh show    [<receipt_id>]
#
# Builds the artifact a judge or a customer keeps: the full breach matrix across
# all three counted phases, the policy set that repaired the leak, the IDs that
# were quarantined, the four-clause pass verdict, and a hash that chains this
# receipt to its predecessor. `emit` writes it, `explain` computes it and inserts
# nothing, `show` prints one back.
#
# Written by rf_auditor, which holds SELECT over every evidence table and INSERT
# on `receipts` and nothing else. The account that attests the breach cannot
# UPDATE or DELETE what it attested: the receipt store is append-only to its own
# writer, which is the whole point of an audit log.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$HERE/../schema/lib/crsql.sh"
# shellcheck source=../schema/lib/creds.sh
source "$HERE/../schema/lib/creds.sh"
# shellcheck source=lib/hash.sh
source "$HERE/lib/hash.sh"
# shellcheck source=lib/clauses.sh
source "$HERE/lib/clauses.sh"
# shellcheck source=lib/preflight.sh
source "$HERE/lib/preflight.sh"
# shellcheck source=lib/sqlio.sh
source "$HERE/lib/sqlio.sh"

POLICY_FILE="$HERE/../schema/004_policies.sql"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n=== %s\n' "$*"; }

# Production writes as rf_auditor. RF_AUDITOR_URL overrides the connection for
# testing and for operators who manage credentials outside Secrets Manager; it
# defaults to the shipped rf_auditor account, and the append-only property is
# proven separately against that account, not asserted by this line.
auditor_url() { printf '%s' "${RF_AUDITOR_URL:-$(url_for rf_auditor service)}"; }

# lit, sqltext, jbool, sql_b64 and sql_scalar come from lib/sqlio.sh. These two
# bind the connection so the call sites below stay about the receipt.
b64()    { sql_b64    "$AUDITOR_URL" "$1"; }
scalar() { sql_scalar "$AUDITOR_URL" "$1"; }

# ---------------------------------------------------------------------------
# build <baseline> <post_rls> <post_quarantine>
#
# Assembles the receipt body and the pass verdict from the three runs. Sets:
# BODY (canonical receipt_json), PASSED (t|f), QIDS_SQL (ARRAY[...]::UUID[]),
# POLICY_SQL, EMITTED. Reads only; inserts nothing.
# ---------------------------------------------------------------------------
build() {
  local base="$1" prls="$2" pq="$3"
  uuid_or_die "$base"; uuid_or_die "$prls"; uuid_or_die "$pq"

  # Admissibility, before anything is scored. These are preconditions rather than
  # a fifth clause: the four clauses define what a pass means, and this decides
  # whether the input is a thing that may be scored at all. Fails closed.
  local pf bad
  pf="$(run_as "$AUDITOR_URL" "$(preflight_sql "$base" "$prls" "$pq")")" \
    || die "preflight query failed: $pf"
  bad="$(printf '%s\n' "$pf" | tail -n +2 | awk -F, '$2!="t" {print "  " $1}')"
  [[ -z "$bad" ]] || die "these runs are not admissible:"$'\n'"$bad"

  local cl; cl="$(scalar "$(clauses_sql "$base" "$prls" "$pq")")"
  local c1 c2 c3 c4 p; IFS=, read -r c1 c2 c3 c4 p <<<"$cl"
  c1="$(jbool "$c1")"; c2="$(jbool "$c2")"; c3="$(jbool "$c3")"; c4="$(jbool "$c4")"
  PASSED="$(jbool "$p")"

  local matrix model query
  matrix="$(b64 "$(matrix_sql "$base" "$prls" "$pq")")"
  model="$(b64 "(SELECT config->>'embedding_model' FROM probe_runs WHERE run_id = '$base')")"
  query="$(b64 "(SELECT config->>'query'           FROM probe_runs WHERE run_id = '$base')")"

  local quar
  quar="$(b64 "(
    SELECT jsonb_build_object(
      'count', count(*),
      'misattributed_write',       count(*) FILTER (WHERE quarantine_reason = 'misattributed_write'),
      'derived_from_foreign_read', count(*) FILTER (WHERE quarantine_reason = 'derived_from_foreign_read'),
      'ids', coalesce(jsonb_agg(id::STRING ORDER BY id::STRING), '[]'::JSONB))
    FROM quarantined_memories WHERE quarantined_by_run = '$base')")"

  # Built from the JSON just decoded, not from a second query. A CSV scalar is the
  # wrong channel for this: the value is a comma-separated list, so CSV wraps it in
  # double quotes and the array literal arrives as a quoted identifier that no
  # column matches. Same idiom as the harness's ev_ids.
  local qids
  qids="$(jq -r '.ids[]' <<<"$quar" | sed "s/^/'/;s/$/'/" | paste -sd, -)"
  if [[ -n "$qids" ]]; then QIDS_SQL="ARRAY[$qids]::UUID[]"; else QIDS_SQL="ARRAY[]::UUID[]"; fi

  POLICY_SQL="$(cat "$POLICY_FILE")"
  local policy_sha; policy_sha="$(printf '%s' "$POLICY_SQL" | rf_sha256)"
  EMITTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # The body is everything the receipt attests, EXCEPT prev_receipt_hash and
  # receipt_hash, which live in their own columns and are what the hash chains
  # over. Arrays inside are pre-sorted by their SQL builders, so this canonical
  # form is stable across a read-back through JSONB.
  BODY="$(jq -c -n \
    --arg base "$base" --arg prls "$prls" --arg pq "$pq" \
    --arg model "$model" --arg query "$query" --arg emitted "$EMITTED" \
    --arg policy "$POLICY_SQL" --arg policy_sha "$policy_sha" \
    --argjson c1 "$c1" --argjson c2 "$c2" --argjson c3 "$c3" --argjson c4 "$c4" \
    --argjson passed "$PASSED" \
    --argjson matrix "$matrix" --argjson quar "$quar" '
    {
      version: "rf-receipt-1",
      emitted_at: $emitted,
      baseline_run: $base, post_rls_run: $prls, post_quarantine_run: $pq,
      embedding_model: $model, leak_query: $query,
      passed: $passed,
      clauses: {
        c1_baseline_demonstrated_failure:  $c1,
        c2_zero_breaches_after_repair:     $c2,
        c3_auditor_confirmed_rows_survived_rls: $c3,
        c4_all_probes_ok:                  $c4
      },
      # Stated in the receipt so it stays interpretable without the code that
      # produced it, and so nobody has to guess which signal the verdict is on.
      breach_definition: ("a probe returned a row belonging to a tenant other "
        + "than the calling principal, or a side_channel probe read an evidence "
        + "table. The canary phrase is recorded as corroboration, not as the "
        + "criterion: it depends on the embedding model retrieving the marked row."),
      phases: ($matrix | group_by(.phase) | map({
        key: .[0].phase,
        value: {
          probes: length,
          breaches: (map(select(.breach)) | length),
          foreign_rows: (map(.foreign_rows) | add),
          canary_hits: (map(select(.canary_hit)) | length),
          errors: (map(select(.status != "ok")) | length)
        }}) | from_entries),
      matrix: $matrix,
      quarantine: $quar,
      policy_sql: $policy, policy_sql_sha256: $policy_sha
    }' | rf_canon)"
}

cmd_emit() {
  [[ $# -eq 3 ]] || die "usage: receipt.sh emit <baseline> <post_rls> <post_quarantine>"
  AUDITOR_URL="$(auditor_url)"
  build "$@"

  local prev; prev="$(scalar "SELECT coalesce(receipt_hash, '') FROM receipts
                                ORDER BY emitted_at DESC, receipt_id DESC LIMIT 1;")"
  local hash; hash="$(printf '%s' "$BODY" | rf_link "$prev")"
  local prev_sql; if [[ -n "$prev" ]]; then prev_sql="$(lit "$prev")"; else prev_sql="NULL"; fi

  # Prove the canonical form survives JSONB BEFORE anything is stored.
  #
  # This check used to run after the INSERT had committed, which was the wrong
  # order: `receipts` is append-only to rf_auditor by design, so discovering a
  # broken link at that point leaves an unverifiable receipt in the table and
  # eligible for changefeed delivery, with no way to retract it. Casting the body
  # through JSONB and back without storing it exercises exactly the same
  # normalization.
  local dry
  dry="$(b64 "$(sqltext "$BODY")::JSONB")" || die "could not round-trip the body"
  [[ "$(printf '%s' "$dry" | rf_link "$prev")" == "$hash" ]] \
    || die "the body does not survive a JSONB round trip; refusing to store an unverifiable receipt"

  say "emitting receipt (passed=$PASSED, prev=${prev:-<genesis>})"
  local rid
  rid="$(run_as "$AUDITOR_URL" "INSERT INTO receipts
      (baseline_run, post_rls_run, post_quarantine_run, policy_sql, quarantined_ids,
       passed, emitted_at, receipt_json, prev_receipt_hash, receipt_hash)
    VALUES ($(lit "$1"), $(lit "$2"), $(lit "$3"), $(sqltext "$POLICY_SQL"), $QIDS_SQL,
            $PASSED, $(lit "$EMITTED")::TIMESTAMPTZ, $(sqltext "$BODY")::JSONB,
            $prev_sql, $(lit "$hash"))
    RETURNING receipt_id;")" || die "insert failed (rf_auditor may lack INSERT on receipts): $rid"
  rid="$(printf '%s' "$rid" | tail -n1 | tr -d '[:space:]')"

  # Read the body back through JSONB and recompute the link. If the stored hash
  # does not match, the canonical form did not survive the round-trip and the
  # chain would be unverifiable. Fail closed rather than ship a broken link.
  local rt; rt="$(b64 "(SELECT receipt_json FROM receipts WHERE receipt_id = '$rid')")"
  local recomputed; recomputed="$(printf '%s' "$rt" | rf_link "$prev")"
  [[ "$recomputed" == "$hash" ]] || die "read-back hash mismatch: stored $hash, recomputed $recomputed"

  printf 'receipt_id   %s\npassed       %s\nreceipt_hash %s\nprev_hash    %s\nverified     read-back link matches\n' \
    "$rid" "$PASSED" "$hash" "${prev:-<genesis>}"
}

cmd_explain() {
  [[ $# -eq 3 ]] || die "usage: receipt.sh explain <baseline> <post_rls> <post_quarantine>"
  AUDITOR_URL="$(auditor_url)"
  build "$@"
  say "receipt body (not inserted)"
  printf '%s\n' "$BODY" | jq '.'
  printf '\npassed: %s\n' "$PASSED"
}

cmd_show() {
  AUDITOR_URL="$(auditor_url)"
  local where="ORDER BY emitted_at DESC, receipt_id DESC LIMIT 1"
  [[ $# -eq 1 ]] && where="WHERE receipt_id = $(lit "$1")"
  local body; body="$(b64 "(SELECT receipt_json FROM receipts $where)")"
  [[ -n "$body" ]] || die "no receipt found"
  printf '%s\n' "$body" | jq '.'
}

# Run IDs are interpolated into SQL by clauses.sh and preflight.sh, so they are
# validated as UUIDs at the boundary rather than trusted because a ::UUID cast
# appears later in the statement. The cast runs after parsing; it cannot stop a
# quote from closing the literal early. Everything else crossing into SQL from
# here goes through lit() or base64.
uuid_or_die() {
  [[ "$1" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || die "not a run id: $(printf %q "$1")"
}

crsql_require || exit 1
[[ -f "$POLICY_FILE" ]] || die "no $POLICY_FILE"
sub="${1:-}"; shift || true
case "$sub" in
  emit)    cmd_emit "$@" ;;
  explain) cmd_explain "$@" ;;
  show)    cmd_show "$@" ;;
  *) sed -n '2,10p' "${BASH_SOURCE[0]}" >&2; exit 1 ;;
esac
