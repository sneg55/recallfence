#!/usr/bin/env bash
# RecallFence: fixture verification.
#
# Sourced by seed.sh. Split out for the same reason tests/lib/assert.sh was: the
# checks are a different concern from the loading, and a check that only prints
# a number passes just as happily when the number is wrong. Every assertion here
# names an expected value derived from the config, so a fixture that silently
# half-loaded fails loudly instead of looking plausible.
#
# No `set -e`. This file is sourced and options leak into the caller.

# ---------------------------------------------------------------------------
# Verify. Asserts the two things a silently broken fixture gets wrong: a canary
# per tenant, and both contamination classes non-empty. A quarantine step with
# nothing to act on shows an empty table on camera and proves nothing.
# ---------------------------------------------------------------------------

cmd_verify() {
  local n=${#PLAN_TENANTS[@]} got want fails=0

  say "verify"
  crsql_stdin --format=table <<'SQL'
SELECT tenant, count(*) AS rows, count(DISTINCT embedding_model) AS models
  FROM memories GROUP BY tenant ORDER BY tenant;
SQL

  check() {
    got="$(crsql_query "$2" | tail -1)"; want="$3"
    if [[ "$got" == "$want" ]]; then
      printf '  ok    %-22s %s\n' "$1" "$got"
    else
      printf '  FAIL  %-22s got %s, want %s\n' "$1" "$got" "$want"; fails=$(( fails + 1 ))
    fi
  }

  check corpus_rows "SELECT count(*) FROM memories WHERE written_by = 'fixture_loader';" \
        "$(( n * PLAN_ROWS_PER_TENANT ))"
  check canaries "SELECT count(*) FROM canaries;" "$n"

  # Every tenant's phrase is carried by at least one of that tenant's own rows.
  # Counting rows that merely look like a purchase order was the earlier version
  # and it broke the moment policy rows started carrying phrases too, which is a
  # sign it was asserting the wrong thing: the property is coverage per tenant,
  # not a row total.
  check canary_phrase_covered \
        "SELECT count(*) FROM canaries c WHERE EXISTS (
           SELECT 1 FROM memories m
            WHERE m.tenant = c.tenant AND m.content LIKE '%' || c.phrase || '%');" "$n"

  # And no tenant's row carries somebody else's phrase. This is the constraint
  # that keeps the phases meaningful: a canary hit is scored on returned content,
  # so a row alice legitimately owns that quoted bob's phrase would be scored as
  # a foreign canary hit in post_rls, and the receipt would record the fence as
  # having failed for something the fence is not for.
  check no_cross_tenant_phrase \
        "SELECT count(*) FROM memories m JOIN canaries c
            ON m.content LIKE '%' || c.phrase || '%'
         WHERE m.tenant <> c.tenant;" 0
  check class1_misattributed \
        "SELECT count(*) FROM memories WHERE origin_tenant <> tenant;" \
        "$(( n * PLAN_MISATTRIBUTED ))"
  # count(DISTINCT m.id), not count(*). Each contaminated session read two
  # foreign rows, so a plain count returns the size of the join rather than the
  # number of contaminated memories, and the quarantine mover would look like it
  # had twice as much to do as it does.
  check class2_derived \
        "SELECT count(DISTINCT m.id) FROM memories m
           JOIN retrievals r ON r.session_id = m.session_id
           JOIN memories f ON f.id = ANY (r.returned_ids)
          WHERE f.tenant <> m.tenant;" \
        "$(( n * PLAN_DERIVED_SESSIONS * PLAN_ROWS_PER_SESSION ))"
  # One model across the table or the vector index is quietly mixing coordinate
  # systems, which degrades retrieval with no error and no visible symptom.
  check distinct_models "SELECT count(DISTINCT embedding_model) FROM memories;" 1

  # Every ID the manifest promises the harness has to resolve to a real row, or
  # the direct-ID probe tests nothing and passes.
  local ids
  ids="$(jq -r '.tenants[].canary_id' "$HERE/manifest.json" | sed "s/^/'/;s/$/'/" | paste -sd, -)"
  check manifest_canary_ids "SELECT count(*) FROM memories WHERE id IN ($ids);" "$n"

  (( fails == 0 )) || die "$fails fixture check(s) failed"
}
