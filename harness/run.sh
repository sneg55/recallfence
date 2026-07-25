#!/usr/bin/env bash
# RecallFence: the breach harness.
#
#   ./harness/run.sh baseline           probe the un-repaired system
#   ./harness/run.sh post_rls           probe after the policy set is applied
#   ./harness/run.sh post_quarantine    probe after contaminated rows are moved
#   ./harness/run.sh negative_control   probe with RLS deliberately disabled
#
# Deterministic. No model judgment anywhere on the access-control path, and no
# model call at all: the query vector is frozen in queries.json by freeze.sh.
#
# Three connection classes, and the separation is the point:
#
#   tenant roles  run the probes, over their own credentials
#   rf_auditor    supplies ground truth for the same predicate at the same moment
#   rf_harness    records the matrix, and holds no privilege on `memories`
#
# A probe that errors is recorded as an error and fails the run. It is never
# silently absent: without a status column an exception and a clean pass are
# indistinguishable in the schema.

set -uo pipefail  # not -e: side-channel probes are supposed to be denied

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$HERE/../schema/lib/crsql.sh"
# shellcheck source=../schema/lib/creds.sh
source "$HERE/../schema/lib/creds.sh"
# shellcheck source=lib/probes.sh
source "$HERE/lib/probes.sh"
# shellcheck source=lib/record.sh
source "$HERE/lib/record.sh"

MANIFEST="$HERE/../fixtures/manifest.json"
QUERIES="$HERE/queries.json"

PHASE="${1:-}"
case "$PHASE" in
  baseline|post_rls|post_quarantine|negative_control) ;;
  *) sed -n '2,8p' "${BASH_SOURCE[0]}" >&2; exit 1 ;;
esac

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n=== %s\n' "$*"; }

crsql_require || exit 1
[[ -f "$MANIFEST" ]] || die "no fixtures/manifest.json. Run fixtures/seed.sh load first."
[[ -f "$QUERIES"  ]] || die "no harness/queries.json. Run harness/freeze.sh first."

# The query and the corpus have to come from the same embedding model, or the
# query point sits in a different coordinate system from the rows and every
# distance is meaningless with nothing visible in the result set to say so.
CORPUS_MODEL="$(jq -r .embedding_model "$MANIFEST")"
QUERY_MODEL="$(jq -r .embedding_model "$QUERIES")"
[[ "$CORPUS_MODEL" == "$QUERY_MODEL" ]] || die \
  "corpus embedded with $CORPUS_MODEL, query with $QUERY_MODEL. Re-freeze or reseed."

VEC="$(jq -c '.queries.leak.vector' "$QUERIES" | tr -d ' ')"
LIMIT="$(jq -r .probe_limit "$MANIFEST")"
PHRASES="$(jq -c '.tenants | with_entries(.value = .value.canary_phrase)' "$MANIFEST")"
TENANTS=()
while IFS= read -r _t; do TENANTS+=("$_t"); done < <(jq -r '.tenants | keys_unsorted[]' "$MANIFEST")

# ---------------------------------------------------------------------------
# Evidence handling. The database builds the JSON and base64s it; nothing
# between here and there has an opinion about quoting.
# ---------------------------------------------------------------------------

decode_ev() { printf '%s' "$1" | tail -n +2 | tr -d '\n"' | base64 -d 2>/dev/null || printf '[]'; }

ev_ids() { jq -r '.[].id' <<<"$1" | sed "s/^/'/;s/$/'/" | paste -sd, -; }

# A canary hit is scored on returned content: any phrase belonging to a tenant
# other than the caller. Content-based rather than ID-based, because the leak
# that matters is the caller reading someone else's words, whichever row carried
# them.
ev_foreign_hit() {
  # `.value as $phrase` before the inner comprehension, not `contains(.value)`
  # inside it: within `[ $texts[] | ... ]` the input is the text, so `.value`
  # would be indexing a string and jq aborts the whole expression.
  jq -r --argjson ph "$PHRASES" --arg me "$2" '
    [ .[].content // "" ] as $texts
    | [ $ph | to_entries[] | select(.key != $me) | .value as $phrase
        | select( [ $texts[] | contains($phrase) ] | any ) ]
    | (length > 0)' <<<"$1"
}

# ---------------------------------------------------------------------------

say "phase: $PHASE"
HARNESS_URL="$(url_for rf_harness service)"
AUDITOR_URL="$(url_for rf_auditor service)"

CONFIG="$(jq -c -n \
  --arg phase "$PHASE" --arg model "$CORPUS_MODEL" \
  --argjson dim "$(jq -r .embedding_dim "$MANIFEST")" \
  --argjson rows "$(jq -r .corpus_rows "$MANIFEST")" \
  --argjson per "$(jq -r .rows_per_tenant "$MANIFEST")" \
  --argjson limit "$LIMIT" --argjson tenants "${#TENANTS[@]}" \
  --arg query "$(jq -r .queries.leak.text "$QUERIES")" \
  '{phase: $phase, embedding_model: $model, embedding_dim: $dim, corpus_rows: $rows,
    rows_per_tenant: $per, probe_limit: $limit, tenants: $tenants, query: $query}')"

RUN_ID="$(rec_open "$HARNESS_URL" "$PHASE" "$CONFIG")" || die "could not open a probe run"
printf 'run_id %s\n' "$RUN_ID"

# How many of the evidence tables the auditor can actually read, measured rather
# than assumed. It is the side-channel probe's ground truth: the tables hold
# every tenant's data and the auditor reaches all of them, so a tenant reaching
# zero is a boundary holding, not an empty database.
AUDITOR_SIDE_TABLES=0
for _t in "${PROBE_SIDE_TABLES[@]}"; do
  run_as "$AUDITOR_URL" "$(probe_sql_side_channel_one "$_t")" >/dev/null \
    && AUDITOR_SIDE_TABLES=$(( AUDITOR_SIDE_TABLES + 1 ))
done

# ---------------------------------------------------------------------------
# probe <principal> <probe_type> <sql>
#
# Runs the same SQL twice: once through the tenant's own fenced connection, once
# as rf_auditor. The auditor half is not a nicety. RLS hiding a row and
# quarantine deleting a row both produce zero rows returned, so a tenant-visible
# "nothing" proves nothing on its own, and without this column the receipt
# cannot tell a working boundary from an emptied table.
# ---------------------------------------------------------------------------

probe() {
  local principal="$1" ptype="$2" sql="$3" url="$4" out ev truth_out truth hit status err ids
  status=ok; err=""

  if out="$(run_as "$url" "$sql")"; then
    ev="$(decode_ev "$out")"
  else
    status=error; err="$(tr '\n' '|' <<<"$out")"; ev='[]'
  fi

  truth_out="$(run_as "$AUDITOR_URL" "$sql")" && truth="$(decode_ev "$truth_out")" || truth='[]'
  hit="$(ev_foreign_hit "$ev" "$principal")"
  ids="$(ev_ids "$ev")"

  # Failing to record is fatal. The harness fails closed: an unexecuted or
  # unrecorded probe is not a passed probe, and a run that prints a clean matrix
  # while having written nothing is the worst possible outcome.
  rec_result "$HARNESS_URL" "$RUN_ID" "$principal" "$ptype" "$ids" "$hit" \
    "$(jq -c '{visible_to_auditor: length, rows: [.[] | {id, tenant}]}' <<<"$truth")" \
    "$status" "$err" "$ev" || die "aborting: $principal/$ptype was not recorded"

  printf '  %-7s %-20s returned=%-3s canary_hit=%-5s auditor=%-3s %s\n' \
    "$principal" "$ptype" "$(jq 'length' <<<"$ev")" "$hit" \
    "$(jq 'length' <<<"$truth")" "$status"
}

# The side channel is its own shape: one statement per table, and a denial is the
# expected result rather than an error. Status stays ok; what is recorded is
# which tables answered. A tenant who can read `canaries` holds every tenant's
# marker phrase, so readability here is itself a foreign canary hit.
probe_side_channel() {
  local principal="$1" url="$2" t out readable=() ev truth
  for t in "${PROBE_SIDE_TABLES[@]}"; do
    if out="$(run_as "$url" "$(probe_sql_side_channel_one "$t")")"; then
      readable+=("$t")
      ev="$(jq -c --arg t "$t" --arg n "$(tail -n1 <<<"$out" | tr -d '[:space:]')" \
              '. + [{table: $t, readable: true, rows: $n}]' <<<"${ev:-[]}")"
    else
      ev="$(jq -c --arg t "$t" --arg e "$(tr '\n' '|' <<<"$out" | cut -c1-160)" \
              '. + [{table: $t, readable: false, denied_with: $e}]' <<<"${ev:-[]}")"
    fi
  done
  truth="$(jq -c -n --argjson n "$AUDITOR_SIDE_TABLES" \
            '{visible_to_auditor: $n,
              note: "fenced at the privilege layer, not by RLS"}')"
  rec_result "$HARNESS_URL" "$RUN_ID" "$principal" side_channel "" \
    "$( (( ${#readable[@]} > 0 )) && echo true || echo false )" \
    "$truth" ok "" "$ev" || die "aborting: $principal/side_channel was not recorded"
  printf '  %-7s %-20s readable=%-3s canary_hit=%-5s\n' \
    "$principal" side_channel "${#readable[@]}" \
    "$( (( ${#readable[@]} > 0 )) && echo true || echo false )"
}

# ---------------------------------------------------------------------------

say "probing ${#TENANTS[@]} principals x ${#PROBE_TYPES[@]} probe types"

for i in "${!TENANTS[@]}"; do
  p="${TENANTS[$i]}"
  foreign="${TENANTS[$(( (i + 1) % ${#TENANTS[@]} ))]}"
  url="$(url_for "$p" tenant)"
  own_id="$(jq -r --arg t "$p" '.tenants[$t].canary_id' "$MANIFEST")"
  foreign_id="$(jq -r --arg t "$foreign" '.tenants[$t].canary_id' "$MANIFEST")"

  probe "$p" semantic_unfiltered "$(probe_sql_semantic_unfiltered "$p" "$VEC" "$LIMIT")" "$url"
  probe "$p" semantic_filtered   "$(probe_sql_semantic_filtered   "$p" "$VEC" "$LIMIT")" "$url"
  probe "$p" direct_id           "$(probe_sql_direct_id "$p" "$own_id" "$foreign_id")"   "$url"
  probe_side_channel "$p" "$url"
done

rec_close "$HARNESS_URL" "$RUN_ID"

say "matrix (read back through the auditor)"
rec_matrix "$AUDITOR_URL" "$RUN_ID"
printf '\nrun_id %s\n' "$RUN_ID"
