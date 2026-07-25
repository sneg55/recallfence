#!/usr/bin/env bash
# RecallFence: deploy the replay dashboard to Cloudflare Pages.
#
#   infra/deploy-web.sh              refresh the snapshot, then deploy
#   infra/deploy-web.sh --no-refresh deploy exactly what is committed
#
# The dashboard is static and renders from web/public/replay.json, so "deploy" is
# a file upload with one precondition: the snapshot must be current. A stale
# snapshot is the one way a static demo silently lies, showing an old receipt
# while claiming to be live, so this refreshes it from the cluster first unless
# told not to, and refuses to deploy a snapshot whose receipt is not the newest
# one in the database.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$ROOT/schema/lib/crsql.sh"
# shellcheck source=../schema/lib/creds.sh
source "$ROOT/schema/lib/creds.sh"
# shellcheck source=../audit/lib/sqlio.sh
source "$ROOT/audit/lib/sqlio.sh"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

SNAPSHOT="$ROOT/web/public/replay.json"
PROJECT="${RF_PAGES_PROJECT:-recallfence}"
REFRESH=1
[[ "${1:-}" == "--no-refresh" ]] && REFRESH=0

command -v wrangler >/dev/null 2>&1 || command -v npx >/dev/null 2>&1 \
  || die "need wrangler (or npx) to deploy to Cloudflare Pages"
wr() { if command -v wrangler >/dev/null 2>&1; then wrangler "$@"; else npx wrangler "$@"; fi; }

if (( REFRESH )); then
  crsql_require || exit 1
  say "refreshing the snapshot from the cluster"
  "$ROOT/cli/rf" snapshot "$SNAPSHOT"
else
  [[ -f "$SNAPSHOT" ]] || die "no snapshot at $SNAPSHOT and --no-refresh was given"
fi

# Guard against shipping a stale snapshot. If the cluster is reachable, the
# snapshot's receipt must be the newest receipt in the database.
if [[ -n "${RF_CLUSTER_URL:-}" ]] && crsql_query "SELECT 1;" >/dev/null 2>&1; then
  local_id="$(jq -r .receipt_meta.receipt_id "$SNAPSHOT")"
  db_id="$(sql_scalar "${RF_AUDITOR_URL:-$(url_for rf_auditor service)}" \
            "SELECT receipt_id FROM receipts ORDER BY emitted_at DESC, receipt_id DESC LIMIT 1;")"
  if [[ -n "$db_id" && "$local_id" != "$db_id" ]]; then
    die "snapshot receipt $local_id is not the newest ($db_id). Re-run without --no-refresh."
  fi
  say "snapshot receipt $local_id matches the database head"
fi

say "deploying web/public to Cloudflare Pages project '$PROJECT'"
wr pages deploy "$ROOT/web/public" --project-name "$PROJECT" --branch main

printf '\ndone. The custom domain is attached at the Pages project level.\n'
