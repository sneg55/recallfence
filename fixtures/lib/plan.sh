#!/usr/bin/env bash
# RecallFence: the row plan.
#
# corpus.sh decides what text exists. This file decides which rows exist, who
# they are attributed to, and which of them are deliberately contaminated.
#
# Sourced by seed.sh. Emits tab-separated records on stdout:
#
#   kind  id_key  tenant  origin_tenant  session_id  source  trust  content
#
# `id_key` is empty for filler. Only rows something else has to name later (a
# canary the harness probes by ID, a policy the demo cites) get a derived,
# stable primary key; the rest take the table's gen_random_uuid() default. That
# keeps the hashing cost proportional to the rows that need it rather than to
# the corpus, which at 48k rows is the difference between a pause and a wait.
#
# No `set -e`. This file is sourced and options leak into the caller.

# plan_foreign <index> <count> -> the tenant this one leaks from, cyclically
plan_foreign() { local i="$1" n="$2"; printf '%s' "${PLAN_TENANTS[$(( (i + 1) % n ))]}"; }

# ---------------------------------------------------------------------------
# plan_rows
#
# Reads PLAN_TENANTS, PLAN_ROWS_PER_TENANT, PLAN_MISATTRIBUTED,
# PLAN_DERIVED_SESSIONS, PLAN_ROWS_PER_SESSION from the environment.
# ---------------------------------------------------------------------------

plan_rows() {
  local n=${#PLAN_TENANTS[@]} t i tenant foreign fill_from row=0

  for (( t = 0; t < n; t++ )); do
    tenant="${PLAN_TENANTS[$t]}"
    foreign="$(plan_foreign "$t" "$n")"

    # 1. The canary. Stable ID: the direct-ID probe names this row across every
    #    phase, and the whole point of a canary is that it does not move.
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      canary "canary:$tenant" "$tenant" "$tenant" "seed-$tenant" import user_confirmed \
      "$(corpus_canary_content "$tenant")"

    # 2. The refund policy. Stable ID so the demo and the auditor can cite the
    #    exact row that leaked rather than "whatever came back first".
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      policy "policy:$tenant" "$tenant" "$tenant" "seed-$tenant" import user_confirmed \
      "$(corpus_policy_content "$tenant")"

    # 3. Quarantine class 1, misattributed writes: origin_tenant <> tenant.
    #    Content produced while serving one customer that landed in another
    #    customer's memory. No session_id that appears in `retrievals`, so these
    #    match class 1 and only class 1.
    for (( i = 0; i < PLAN_MISATTRIBUTED; i++ )); do
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        misattributed "misattr:$tenant:$i" "$tenant" "$foreign" "drift-$tenant-$i" \
        summarizer model_derived \
        "Escalation summary drafted while working ticket ${foreign:0:1}$(( 4100 + i * 37 )) for $(corpus_display "$foreign"): the account owner wants the credit applied before the renewal date, and asked for the reason code in writing."
    done

    # 4. Quarantine class 2, downstream contamination. origin_tenant equals
    #    tenant on purpose, so class 1 does not also catch these: the only thing
    #    that marks them is the session's retrieval history, which is exactly
    #    the predicate `retrievals` exists to make computable.
    #
    #    These rows paraphrase what the agent read. They must NOT carry the
    #    foreign canary phrase itself, and that is a hard constraint rather than
    #    a stylistic choice. A canary hit is scored on the returned content, so a
    #    row alice legitimately owns that quotes bob's purchase-order number
    #    would be scored as a foreign canary hit in the post_rls phase, and the
    #    receipt would record the fence as having failed for something the fence
    #    is not for. Contamination is repaired by quarantine, one phase later;
    #    letting it read as an exposure failure would collapse the very
    #    distinction the two-phase rerun exists to draw.
    for (( i = 0; i < PLAN_DERIVED_SESSIONS; i++ )); do
      local j
      for (( j = 0; j < PLAN_ROWS_PER_SESSION; j++ )); do
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          derived "derived:$tenant:$i:$j" "$tenant" "$tenant" "leak-$tenant-$i" \
          agent_summary model_derived \
          "Answer recorded for the customer on ticket ${tenant:0:1}$(( 7300 + i * 53 + j )): the approval ceiling that applies here is 25,000 USD per incident before a director has to sign off, and anything above that goes to the escalation queue. Noted for the next agent picking up this account."
      done
    done

    # 5. Filler, to the configured scale. Unique content per row, so unique
    #    embeddings: a corpus of a few hundred vectors repeated thousands of
    #    times would give the vector index a degenerate distribution and make
    #    the cost-of-the-boundary measurement meaningless.
    fill_from=$(( 2 + PLAN_MISATTRIBUTED + PLAN_DERIVED_SESSIONS * PLAN_ROWS_PER_SESSION ))
    for (( i = fill_from; i < PLAN_ROWS_PER_TENANT; i++ )); do
      printf '%s\t\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        filler "$tenant" "$tenant" "sess-$tenant-$(( i / 20 ))" \
        "${CORPUS_SOURCES[$(( (row + i) % ${#CORPUS_SOURCES[@]} ))]}" \
        "${CORPUS_TRUST[$(( (row + i) % ${#CORPUS_TRUST[@]} ))]}" \
        "$(corpus_filler_content "$tenant" "$(( t * PLAN_ROWS_PER_TENANT + i ))")"
    done
    row=$(( row + PLAN_ROWS_PER_TENANT ))
  done
}

# ---------------------------------------------------------------------------
# plan_retrievals
#
# One record per contaminated session, tab-separated:
#
#   session_id  principal  tenant  foreign_tenant
#
# The foreign tenant is resolved to that tenant's canary row ID by seed.sh, so
# the retrieval log says "this session read a row belonging to someone else".
# Without these rows the class-2 predicate has nothing to join against and the
# quarantine panel shows an empty table on camera.
# ---------------------------------------------------------------------------

plan_retrievals() {
  local n=${#PLAN_TENANTS[@]} t i tenant foreign
  for (( t = 0; t < n; t++ )); do
    tenant="${PLAN_TENANTS[$t]}"
    foreign="$(plan_foreign "$t" "$n")"
    for (( i = 0; i < PLAN_DERIVED_SESSIONS; i++ )); do
      printf '%s\t%s\t%s\t%s\n' "leak-$tenant-$i" "$tenant" "$tenant" "$foreign"
    done
  done
}
