#!/usr/bin/env bash
# RecallFence: what counts as contaminated.
#
# Sourced by quarantine.sh. One definition, used by the count, the report, the
# insert and the delete, so those four can never drift apart. Every fragment
# assumes the candidate table is aliased `m`.
#
# This has to be a predicate, not a phrase. Quarantine targets two classes, both
# keyed on provenance, and the thing it deliberately does NOT target is the
# reason both classes are defined this narrowly.
#
# No `set -e`. This file is sourced and options leak into the caller.

# ---------------------------------------------------------------------------
# Class 1: mis-attributed writes.
#
# Content produced while serving one customer, stored under another. The
# divergence is the signal, and it is visible in the row itself.
# ---------------------------------------------------------------------------

PRED_CLASS1="m.origin_tenant IS NOT NULL AND m.origin_tenant <> m.tenant"

# ---------------------------------------------------------------------------
# Class 2: downstream contamination.
#
# Rows the agent wrote into tenant A after a retrieval in the same session
# returned a row belonging to tenant B. This is why `retrievals` exists: without
# a record of which rows a session actually read, "the agent wrote this after
# reading a foreign row" is not a computable predicate, only a suspicion.
#
# Class 1 is excluded explicitly. The two are disjoint in the shipped fixture,
# but relying on that would put a primary key violation one fixture edit away,
# and the reason codes would stop meaning what they say.
# ---------------------------------------------------------------------------

PRED_CLASS2="NOT ($PRED_CLASS1) AND EXISTS (
    SELECT 1 FROM retrievals r
      JOIN memories f ON f.id = ANY (r.returned_ids)
     WHERE r.session_id = m.session_id
       AND f.tenant <> m.tenant)"

# ---------------------------------------------------------------------------
# What is explicitly NOT quarantined, stated here because a predicate is also
# defined by what it leaves alone:
#
# A row that was merely exposed to a foreign principal. Bob's refund ceiling is
# correct data, correctly attributed to Bob. The defect was in Alice's query
# path, and deleting Bob's memory to fix Alice's bug would be a worse bug than
# the one being fixed.
#
# RLS repairs exposure. Quarantine repairs contamination. Keeping the two apart
# is the whole point of having both, and it is what makes the two-phase rerun
# say anything: if cleanup ran first, "no rows returned" would prove nothing,
# because an emptied table returns nothing either.
# ---------------------------------------------------------------------------

# Read by quarantine.sh, which sources this file; shellcheck cannot see across
# that boundary.
# shellcheck disable=SC2034
PRED_EITHER="($PRED_CLASS1) OR ($PRED_CLASS2)"
