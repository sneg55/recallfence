#!/usr/bin/env bash
# RecallFence: the demo, beat by beat.
#
#   ./demo/run.sh                        from the committed snapshot, no cluster
#   ./demo/run.sh --live                 from the cluster
#   ./demo/run.sh --no-pause             run straight through, for a dry timing pass
#
# Seven beats, a negative control and a hash-chain reveal. The order is the
# argument, not decoration: probing after RLS but before quarantine is what makes
# exposure and contamination separable. If cleanup ran first, "no rows returned"
# would prove nothing, because an emptied table returns nothing either.
#
# Defaults to the snapshot so a rehearsal never depends on the cluster being
# awake, and so the recording can be re-shot after the cluster is torn down.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SNAPSHOT="$ROOT/web/public/replay.json"

SRC=(--from "$SNAPSHOT")
PAUSE=1
for a in "$@"; do
  case "$a" in
    --live)     SRC=() ;;
    --no-pause) PAUSE=0 ;;
    *) printf 'unknown argument: %s\n' "$a" >&2; exit 1 ;;
  esac
done

[[ ${#SRC[@]} -eq 0 || -f "$SNAPSHOT" ]] || {
  printf 'no snapshot at %s. Run: cli/rf snapshot\n' "$SNAPSHOT" >&2; exit 1
}

rf() { "$ROOT/cli/rf" "${SRC[@]+"${SRC[@]}"}" "$@"; }

beat() {
  printf '\n\033[1;36m%s\033[0m\n' "$1"
  printf '\033[2m%s\033[0m\n' "$2"
  [[ "$PAUSE" == 1 ]] && { printf '\033[2m[enter]\033[0m'; read -r _; } || true
}

# ---------------------------------------------------------------------------

beat "1/7  The leak" \
  "Alice asks about enterprise refunds. She gets Bob's rows back. Ordinary query, no planted prompt."
rf evidence | head -20

beat "2/7  The auditor names it" \
  "Not just that a row leaked: which principal, by which path, whose row, written in whose session."
rf evidence | sed -n '1,6p'
printf '\n  Every leaked row above carries origin, session, source and trust.\n'
printf '  That is what makes the receipt a lineage record rather than a pass/fail bit.\n'

beat "3/7  The operator approves the policy set" \
  "Generated from schema/004_policies.sql, the same file the schema applies. Approval is a word you type, not a keypress."
rf policy | head -14

beat "4/7  The same query, repaired" \
  "Identical SQL. And alongside it, the auditor still sees Bob's row: the boundary hid it, nothing was deleted."
rf matrix

beat "5/7  The cost of the boundary" \
  "With a policy active, CockroachDB will not filter an approximate ANN result through RLS, so it falls back to an exact scan."
if [[ ${#SRC[@]} -eq 0 ]]; then
  "$HERE/explain.sh"
else
  cat <<'PLAN'
  With RLS active the vector index is not usable and the query becomes:

      • top-k
      └── • scan
            estimated row count: 7,944 (100% of the table)
            table: memories@memories_pkey
            spans: FULL SCAN

  Captured live. Run `demo/explain.sh --both` against a cluster to see both plans.
  This is the same mechanism that guarantees the caller never gets a short result.
PLAN
fi

beat "6/7  Quarantine, and what it refuses to touch" \
  "Only now are contaminated rows moved. Bob's refund ceiling is correct data correctly attributed, so it stays."
rf quarantine | head -14

beat "7/7  The receipt" \
  "Four clauses, not one. A pass with no demonstrated baseline failure is a rubber stamp."
rf receipt

beat "Hash chain" \
  "Verification needs nothing but the receipts. Editing one breaks its own link; editing one and recomputing its hash breaks the next."
if [[ ${#SRC[@]} -eq 0 ]]; then
  "$ROOT/audit/verify.sh"
else
  "$ROOT/tests/test_receipt_chain.sh" | tail -20
fi

beat "Negative control" \
  "The same application with RLS disabled: the leak persists and cleanup is guesswork. This proves the product, not the script."
printf '  Runs only inside an isolated live run, never against the shared corpus.\n'
printf '  Concurrent visitors each get an isolated run; the shared corpus stays read-only.\n'

printf '\n\033[1mdone.\033[0m\n'
