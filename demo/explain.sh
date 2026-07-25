#!/usr/bin/env bash
# RecallFence: the cost of the boundary.
#
#   ./demo/explain.sh            plan as the system currently stands
#   ./demo/explain.sh --both     toggle RLS off, plan, toggle back on, plan
#
# The beat this supports: the boundary has a price, here it is, and a judge who
# runs EXPLAIN themselves finds exactly what the demo showed them.
#
# With a policy active on `memories`, CockroachDB will not filter an approximate
# ANN result through RLS, because a row the policy rejects would silently shorten
# the result set. It falls back to an exact scan for correctness. So the vector
# index stops being used and the same query becomes a FULL SCAN. That is the
# intended trade, not a regression: it is the same mechanism that guarantees the
# caller never gets a short result.
#
# `--both` mutates global state. RLS is a property of the table, not of a
# session, so this is never safe to run against a shared demo cluster while
# anyone else is looking at it. It restores the fence on exit, including on
# failure, because leaving a cluster unfenced after a demo script crashed is the
# worst outcome available here.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$ROOT/schema/lib/crsql.sh"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

crsql_require || exit 1
[[ -f "$ROOT/harness/queries.json" ]] || die "no harness/queries.json. Run harness/freeze.sh first."

VEC="$(jq -c '.queries.leak.vector' "$ROOT/harness/queries.json" | tr -d ' ')"

plan() {
  crsql_stdin --format=table <<SQL 2>&1 | sed 's/^/  /'
EXPLAIN SELECT id, tenant FROM memories
 ORDER BY embedding <-> '$VEC'::VECTOR(1024) LIMIT 5;
SQL
}

rls_state() {
  crsql_query "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'memories';" \
    | tail -n1
}

say "RLS state (relrowsecurity, relforcerowsecurity): $(rls_state)"
say "plan as the system currently stands"
plan

[[ "${1:-}" == "--both" ]] || {
  printf '\n  Pass --both to also show the plan with RLS disabled.\n'
  printf '  That mutates the table for everyone, so it is opt-in.\n'
  exit 0
}

printf '\n\033[33mThis disables RLS on the memories table for the whole cluster.\033[0m\n'
printf 'Type "unfence" to continue: '
read -r reply
[[ "$reply" == "unfence" ]] || die "not confirmed, nothing changed"

# Restore on any exit path. A demo script that dies between the toggles must not
# leave the fence down.
restore() {
  printf '\n\033[1mrestoring the fence\033[0m\n'
  "$ROOT/schema/apply.sh" rls on >/dev/null 2>&1 \
    && printf '  RLS state now: %s\n' "$(rls_state)" \
    || printf '  \033[31mFAILED to restore RLS. Run: schema/apply.sh rls on\033[0m\n'
}
trap restore EXIT

"$ROOT/schema/apply.sh" rls off >/dev/null || die "could not disable RLS"
say "plan with RLS disabled (the vector index is usable again)"
plan
say "RLS state (relrowsecurity, relforcerowsecurity): $(rls_state)"
