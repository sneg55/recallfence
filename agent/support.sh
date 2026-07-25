#!/usr/bin/env bash
# RecallFence: the support agent.
#
#   agent/support.sh <tenant> "<question>"              unfiltered retrieval (the leak)
#   agent/support.sh <tenant> "<question>" --filtered    correctly scoped retrieval
#   agent/support.sh <tenant> "<question>" --write       also write a memory back
#   agent/support.sh <tenant> "<question>" --write-as <other>   attempt a foreign write
#
# The realistic fixture. It answers a customer question by semantic retrieval over
# `memories`, logs what it retrieved, and can write a memory back with provenance
# captured at write time rather than backfilled.
#
# Two connections, and the split is the point:
#
#   the tenant role   reads and writes `memories`, fenced by RLS
#   rf_agent          appends to `retrievals`, and can do nothing else
#
# The agent therefore cannot read back or edit its own retrieval log. That log is
# what makes downstream contamination computable later, so the audited party
# having write-only access to it is not a detail.
#
# rf_agent, not rf_harness. A review found that rf_harness can also read
# `canaries` and `probe_results`, which hold cross-tenant evidence in plaintext,
# so handing this tenant-facing process that credential let it read around the
# RLS boundary. rf_agent holds exactly one privilege: INSERT on retrievals.
#
# The write path is not decoration. Without it every operation in this system is
# a read over a statically seeded corpus, which is exactly the "database-security
# demo with an agent attached" reading the design names as the likeliest way to
# lose. A live write makes the memory agentic rather than pre-loaded, makes
# provenance captured rather than backfilled, and lets the boundary be shown
# holding on writes as well as reads.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$ROOT/schema/lib/crsql.sh"
# shellcheck source=../schema/lib/creds.sh
source "$ROOT/schema/lib/creds.sh"
# shellcheck source=../audit/lib/sqlio.sh
source "$ROOT/audit/lib/sqlio.sh"
# shellcheck source=lib/model.sh
source "$HERE/lib/model.sh"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

TENANT="${1:-}"; QUESTION="${2:-}"
[[ -n "$TENANT" && -n "$QUESTION" ]] || { sed -n '2,9p' "${BASH_SOURCE[0]}" >&2; exit 1; }
shift 2

FILTERED=0 WRITE=0 WRITE_AS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --filtered) FILTERED=1; shift ;;
    --write)    WRITE=1; shift ;;
    --write-as) [[ $# -ge 2 ]] || die "--write-as needs a tenant"; WRITE_AS="$2"; WRITE=1; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

crsql_require || exit 1

MANIFEST="$ROOT/fixtures/manifest.json"
[[ -f "$MANIFEST" ]] || die "no fixtures/manifest.json. Run fixtures/seed.sh load first."
LIMIT="$(jq -r .probe_limit "$MANIFEST")"

TENANT_URL="$(url_for "$TENANT" tenant)"    || die "no credentials for tenant $TENANT"
AGENT_URL="$(url_for rf_agent service)"     || die "no credentials for rf_agent"

SESSION="agent-$TENANT-$(date -u +%Y%m%dT%H%M%SZ)"

# The question is embedded with the same model the corpus was, or the query point
# sits in a different coordinate system from the rows and every distance is
# meaningless with nothing in the result set to say so.
say "session $SESSION"
model_banner
VEC="$("$ROOT/fixtures/embed.sh" one "$QUESTION")" || die "could not embed the question"

# ---------------------------------------------------------------------------
# Retrieve. Unfiltered by default: this is the query an application writes when
# someone forgets the tenant predicate, and at baseline it is what returns
# another customer's memory. --filtered is the same query written correctly, and
# it passes even at baseline, which is the point of having both.
# ---------------------------------------------------------------------------

if (( FILTERED )); then
  WHERE="WHERE tenant = $(lit "$TENANT")"
  MODE="filtered (correctly scoped)"
else
  WHERE=""
  MODE="unfiltered (the forgotten predicate)"
fi

say "retrieval: $MODE"
ROWS="$(sql_b64 "$TENANT_URL" "(
  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'id', id, 'tenant', tenant, 'content', content,
           'written_by', written_by, 'source', source, 'trust', trust)), '[]'::JSONB)
    FROM (SELECT id, tenant, content, written_by, source, trust
            FROM memories $WHERE
           ORDER BY embedding <-> '$VEC'::VECTOR(1024)
           LIMIT $LIMIT) s)")" || die "retrieval failed"

N="$(jq 'length' <<<"$ROWS")"
FOREIGN="$(jq --arg me "$TENANT" '[.[] | select(.tenant != $me)] | length' <<<"$ROWS")"
printf '  %s row(s) returned, %s belonging to another tenant\n' "$N" "$FOREIGN"
jq -r --arg me "$TENANT" '.[] | "  - [\(.tenant)\(if .tenant != $me then " FOREIGN" else "" end)] \(.content[0:110])"' <<<"$ROWS"

# Log every retrieval, as rf_harness. Append-only from the agent's side.
IDS="$(jq -r '.[].id' <<<"$ROWS" | sed "s/^/'/;s/$/'/" | paste -sd, -)"
[[ -n "$IDS" ]] || IDS=""
run_as "$AGENT_URL" "INSERT INTO retrievals (session_id, principal, tenant, returned_ids)
  VALUES ($(lit "$SESSION"), $(lit "$TENANT"), $(lit "$TENANT"),
          $(if [[ -n "$IDS" ]]; then printf 'ARRAY[%s]::UUID[]' "$IDS"; else printf 'ARRAY[]::UUID[]'; fi));" \
  >/dev/null || die "could not log the retrieval"
printf '  logged to retrievals as rf_agent (write-only: the agent cannot read this back)\n'

# ---------------------------------------------------------------------------
# Answer. Facts from SQL, prose from the model, and never the other way round.
# ---------------------------------------------------------------------------

say "answer"
FACTS="Question: $QUESTION
Answering for tenant $TENANT. Retrieved $N memories, of which $FOREIGN belong to
a different tenant. Retrieved content:
$(jq -r '.[] | "- (tenant=\(.tenant), trust=\(.trust)) \(.content)"' <<<"$ROWS")"
model_polish "$FACTS" "Answer the customer question using only the retrieved memories. Cite the tenant each fact came from." \
  | sed 's/^/  /'

if (( FOREIGN > 0 )); then
  printf '\n  \033[31mThis answer cites %s row(s) belonging to another tenant.\033[0m\n' "$FOREIGN"
  printf '  That is the leak, and no application code above this line is at fault.\n'
fi

# ---------------------------------------------------------------------------
# Write back, with provenance captured at write time.
# ---------------------------------------------------------------------------

(( WRITE )) || exit 0

TARGET="${WRITE_AS:-$TENANT}"
say "writing a memory back as tenant=$TARGET"
SUMMARY="Agent summary for session $SESSION: customer asked about \"$QUESTION\". $N memories consulted."

OUT="$(run_as "$TENANT_URL" "INSERT INTO memories
    (tenant, content, embedding, embedding_model, written_by, origin_tenant,
     session_id, source, trust)
  VALUES ($(lit "$TARGET"), $(lit "$SUMMARY"), '$VEC'::VECTOR(1024),
          $(lit "$(jq -r .embedding_model "$MANIFEST")"), $(lit "$TENANT"), $(lit "$TENANT"),
          $(lit "$SESSION"), 'agent_summary', 'model_derived');" 2>&1)"
STATUS=$?

if [[ "$TARGET" != "$TENANT" ]]; then
  # The interesting case. tenant_write's WITH CHECK rejects a row whose tenant is
  # not the writer, during query execution, the same way the read is denied.
  #
  # Assert the reason, not just the failure. A write can also fail on a bad
  # password, a dropped connection, a malformed vector or a missing grant, and
  # every one of those would print "rejected, as it should be" while proving
  # nothing about the boundary. The claim is specifically that RLS refused it, so
  # the error has to say so: a row-level security violation, SQLSTATE 42501.
  if (( STATUS == 0 )); then
    printf '  \033[31mFOREIGN WRITE SUCCEEDED. The boundary is not holding.\033[0m\n'
    exit 1
  fi
  if [[ "$OUT" == *"row-level security"* && "$OUT" == *"42501"* ]]; then
    printf '  rejected by the boundary, for the right reason:\n'
    printf '%s\n' "$OUT" | sed 's/^/    /' | head -2
    printf '  tenant_write WITH CHECK (tenant = current_user) refused the row (SQLSTATE 42501).\n'
    exit 0
  fi
  printf '  \033[33mwrite failed, but NOT with an RLS policy violation. This does not\n'
  printf '  demonstrate the boundary; it is some other error:\033[0m\n'
  printf '%s\n' "$OUT" | sed 's/^/    /' | head -3
  exit 1
fi

(( STATUS == 0 )) || { printf '%s\n' "$OUT" | sed 's/^/  /'; die "write failed"; }
printf '  written. provenance captured at write time, not backfilled:\n'
printf '    written_by=%s  origin_tenant=%s  session=%s\n' "$TENANT" "$TENANT" "$SESSION"
printf '    source=agent_summary  trust=model_derived\n'
