#!/usr/bin/env bash
# RecallFence: seed the corpus, the canaries, and the deliberate contamination.
#
#   ./fixtures/seed.sh plan       write the row plan to stdout as TSV, load nothing
#   ./fixtures/seed.sh embed      fill the embedding cache for the current plan
#   ./fixtures/seed.sh load       embed if needed, then insert into the cluster
#   ./fixtures/seed.sh manifest   write fixtures/manifest.json (IDs the harness names)
#   ./fixtures/seed.sh verify     row counts, canary coverage, both contamination classes
#   ./fixtures/seed.sh clear      delete everything this loader inserted
#
# Runs between `schema/apply.sh roles` and `schema/apply.sh policies`. It refuses
# to run while the fence is up rather than lowering it: under FORCE ROW LEVEL
# SECURITY the seeder is denied like anyone else, and a fixture loader that
# quietly disables row-level security to get its work done would be the exact
# convenience this project exists to argue against. The operator lowers it
# explicitly, or not at all.
#
# Environment:
#   RF_CLUSTER_URL    required. Admin connection URL.
#   RF_EMBED_BACKEND  auto | bedrock | local. See fixtures/embed.sh.
#   RF_BATCH_ROWS     default 100. Rows per INSERT statement.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$HERE/../schema/lib/crsql.sh"
# shellcheck source=lib/corpus.sh
source "$HERE/lib/corpus.sh"
# shellcheck source=lib/plan.sh
source "$HERE/lib/plan.sh"
# shellcheck source=lib/verify.sh
source "$HERE/lib/verify.sh"
# shellcheck source=embed.sh
source "$HERE/embed.sh"

CONFIG="${RF_FIXTURES_CONFIG:-$HERE/config.json}"
RF_BATCH_ROWS="${RF_BATCH_ROWS:-100}"

# Not `mapfile`: the system bash on macOS is 3.2, where it does not exist. The
# rest of this repo already runs there, and a fixture loader that only works
# under a Homebrew bash is a portability bug waiting to be discovered by
# whoever clones the repo.
PLAN_TENANTS=()
while IFS= read -r _tenant; do PLAN_TENANTS+=("$_tenant"); done < <(jq -r '.tenants[]' "$CONFIG")
PLAN_ROWS_PER_TENANT="$(jq -r .rows_per_tenant "$CONFIG")"
# Read by lib/plan.sh, in arithmetic contexts shellcheck does not count as uses.
# shellcheck disable=SC2034
PLAN_MISATTRIBUTED="$(jq -r .contamination.misattributed_per_tenant "$CONFIG")"
# shellcheck disable=SC2034
PLAN_DERIVED_SESSIONS="$(jq -r .contamination.derived_sessions_per_tenant "$CONFIG")"
# shellcheck disable=SC2034
PLAN_ROWS_PER_SESSION="$(jq -r .contamination.rows_per_derived_session "$CONFIG")"

say() { printf '\n=== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Identity and quoting.
# ---------------------------------------------------------------------------

# A row key that something else has to name later becomes a UUID by digest, so
# the harness can ask for "bob's canary" without a handoff file surviving between
# two processes. Not an RFC 4122 versioned UUID and nothing treats it as one: it
# is a content address that happens to fit the column.
rf_uuid() {
  local h; h="$(printf '%s' "$1" | shasum -a 256 | cut -c1-32)"
  printf '%s-%s-%s-%s-%s' "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"
}

# The quote goes through a variable, not a backslash escape: on bash 3.2
# `${1//\'/\'\'}` substitutes a literal \'\' rather than doubling the quote. Only
# ever called here on tenant names, UUIDs and session IDs, so the bug was latent
# rather than live (row content takes the perl/awk path, which quotes its own),
# but it is the same defect the receipt writer hit for real.
sql_lit() { local q="'" s="$1"; s="${s//$q/$q$q}"; printf '%s%s%s' "$q" "$s" "$q"; }

# ---------------------------------------------------------------------------
# Preconditions. Both failures are silent-by-default without this check: a
# forced fence denies the seeder with zero rows affected and no error, and a
# tenant whose name is not a login role produces a table that looks seeded and
# an RLS predicate that matches nothing.
# ---------------------------------------------------------------------------

check_fence_down() {
  local forced
  forced="$(crsql_query "SELECT relforcerowsecurity FROM pg_class WHERE relname = 'memories';" | tail -1)"
  [[ "$forced" == f || "$forced" == false ]] || die \
"row-level security is still forced on memories. Seeding runs before the fence:
       schema/apply.sh rls off && fixtures/seed.sh load && schema/apply.sh rls on"
}

check_roles() {
  local missing=() t
  for t in "${PLAN_TENANTS[@]}"; do
    [[ "$(crsql_query "SELECT count(*) FROM pg_roles WHERE rolname = $(sql_lit "$t");" | tail -1)" == 1 ]] \
      || missing+=("$t")
  done
  (( ${#missing[@]} == 0 )) || printf \
    'warning: no login role for: %s\n         RLS compares tenant = current_user, so those rows will be unreachable.\n         Fix with: schema/apply.sh roles %s\n' \
    "${missing[*]}" "${missing[*]}" >&2
}

# ---------------------------------------------------------------------------
# Plan, embed, load.
# ---------------------------------------------------------------------------

cmd_plan() { plan_rows; }

build_plan() {
  plan_rows >"$WORK/rows.tsv"
  cut -f8 <"$WORK/rows.tsv" | sort -u >"$WORK/texts.txt"
  printf '%s rows, %s distinct texts\n' \
    "$(wc -l <"$WORK/rows.tsv" | tr -d ' ')" "$(wc -l <"$WORK/texts.txt" | tr -d ' ')" >&2
}

cmd_embed() {
  say "plan"
  build_plan
  say "embed"
  embed_fill <"$WORK/texts.txt"
}

# Emits INSERT statements on stdout. Vectors come from the cache, so this is a
# file read per row rather than a model call per row, and re-running the loader
# after a failed load costs nothing.
#
# Two processes rather than a bash loop, which is not premature optimisation: a
# read loop needs a `shasum` fork for the cache key and a subshell per quoted
# field, so at corpus scale it spends minutes forking. perl adds the content
# digest and the derived UUID in one pass, awk does the lookup and the quoting
# in a second, and both agree with rf_uuid by construction because they hash the
# same key the same way.
emit_memories() {
  local model dir
  model="$(embed_model_id)"
  dir="$RF_CACHE_DIR/${model//[^A-Za-z0-9._-]/_}"
  perl -MDigest::SHA=sha256_hex -F'\t' -lane '
      my $h = sha256_hex($F[7]);
      my $u = "";
      if (length $F[1]) {
        my $k = sha256_hex($F[1]);
        $u = join("-", substr($k,0,8), substr($k,8,4), substr($k,12,4),
                       substr($k,16,4), substr($k,20,12));
      }
      print join("\t", @F, $h, $u);' <"$WORK/rows.tsv" \
  | awk -F'\t' -v dir="$dir" -v model="$model" -v batch="$RF_BATCH_ROWS" '
      function q(s) { gsub(/'\''/, "'\'''\''", s); return "'\''" s "'\''" }
      {
        path = dir "/" substr($9,1,2) "/" $9 ".vec"
        if ((getline vec < path) <= 0) {
          printf "missing cached vector for row %d (%s)\n", NR, path > "/dev/stderr"; exit 1
        }
        close(path)
        if (n % batch == 0) {
          if (n > 0) printf ";\n"
          printf "INSERT INTO memories (id, tenant, content, embedding, embedding_model, written_by, origin_tenant, session_id, source, trust) VALUES\n"
        } else printf ",\n"
        printf "(%s, %s, %s, %s::VECTOR(1024), %s, '\''fixture_loader'\'', %s, %s, %s, %s)",
          ($10 == "" ? "gen_random_uuid()" : q($10) "::UUID"),
          q($3), q($8), q(vec), q(model), q($4), q($5), q($6), q($7)
        n++
      }
      END { if (n > 0) printf ";\n" }'
}

emit_canaries() {
  local t
  printf 'INSERT INTO canaries (id, tenant, phrase) VALUES\n'
  for t in "${PLAN_TENANTS[@]}"; do
    [[ "$t" == "${PLAN_TENANTS[0]}" ]] || printf ',\n'
    printf '(%s::UUID, %s, %s)' \
      "$(sql_lit "$(rf_uuid "canaryrow:$t")")" "$(sql_lit "$t")" \
      "$(sql_lit "$(corpus_canary_phrase "$t")")"
  done
  printf '\nON CONFLICT (phrase) DO NOTHING;\n'
}

# The retrieval log entry that makes quarantine class 2 computable: this session,
# on this tenant, returned a row belonging to someone else.
emit_retrievals() {
  local session principal tenant foreign first=1
  printf 'INSERT INTO retrievals (session_id, principal, tenant, returned_ids) VALUES\n'
  while IFS=$'\t' read -r session principal tenant foreign; do
    (( first )) || printf ',\n'; first=0
    printf '(%s, %s, %s, ARRAY[%s::UUID, %s::UUID])' \
      "$(sql_lit "$session")" "$(sql_lit "$principal")" "$(sql_lit "$tenant")" \
      "$(sql_lit "$(rf_uuid "canary:$foreign")")" "$(sql_lit "$(rf_uuid "policy:$foreign")")"
  done < <(plan_retrievals)
  printf ';\n'
}

cmd_load() {
  crsql_require
  check_fence_down
  check_roles
  cmd_embed
  say "load"
  { emit_canaries; emit_retrievals; emit_memories; } | crsql_stdin
  cmd_manifest
  cmd_verify
}

# ---------------------------------------------------------------------------
# Manifest: the IDs and phrases the harness, the auditor and the demo name by
# hand. Derivable from the plan, written out anyway so nothing downstream has to
# reimplement rf_uuid to ask for bob's canary.
# ---------------------------------------------------------------------------

cmd_manifest() {
  local t
  { printf '{\n  "embedding_model": %s,\n' "$(jq -Rn --arg m "$(embed_model_id)" '$m')"
    printf '  "embedding_dim": %s,\n' "$RF_EMBED_DIM"
    printf '  "rows_per_tenant": %s,\n' "$PLAN_ROWS_PER_TENANT"
    printf '  "corpus_rows": %s,\n' "$(( ${#PLAN_TENANTS[@]} * PLAN_ROWS_PER_TENANT ))"
    printf '  "probe_limit": %s,\n' "$(jq -r .probe_limit "$CONFIG")"
    printf '  "leak": %s,\n' "$(jq -c .leak "$CONFIG")"
    printf '  "tenants": {\n'
    for t in "${PLAN_TENANTS[@]}"; do
      [[ "$t" == "${PLAN_TENANTS[0]}" ]] || printf ',\n'
      printf '    %s: {"canary_id": "%s", "policy_id": "%s", "canary_phrase": %s}' \
        "$(jq -Rn --arg t "$t" '$t')" "$(rf_uuid "canary:$t")" "$(rf_uuid "policy:$t")" \
        "$(jq -Rn --arg p "$(corpus_canary_phrase "$t")" '$p')"
    done
    printf '\n  }\n}\n'
  } >"$HERE/manifest.json"
  jq . "$HERE/manifest.json" >/dev/null || die "manifest.json is not valid JSON"
  printf 'wrote %s\n' "$HERE/manifest.json"
}


cmd_clear() {
  crsql_require
  check_fence_down
  say "clear"
  crsql_stdin <<'SQL'
DELETE FROM retrievals WHERE session_id LIKE 'leak-%' OR session_id LIKE 'sess-%';
DELETE FROM memories WHERE written_by = 'fixture_loader';
DELETE FROM canaries WHERE true;
SQL
}

case "${1:-}" in
  plan)     cmd_plan ;;
  embed)    cmd_embed ;;
  load)     cmd_load ;;
  manifest) cmd_manifest ;;
  verify)   crsql_require; cmd_verify ;;
  clear)    cmd_clear ;;
  *)        sed -n '2,10p' "${BASH_SOURCE[0]}" >&2; exit 1 ;;
esac
