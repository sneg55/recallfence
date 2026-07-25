#!/usr/bin/env bash
# RecallFence: the four probes.
#
# Sourced by run.sh. Each builder prints SQL that returns exactly one column,
# one row: the evidence, as base64-encoded JSON.
#
# Base64 rather than reading rows out of CSV. Evidence contains free text from
# the corpus, and a probe that mis-parses a comma reports the wrong breach. The
# database builds the JSON, the transport carries an opaque string, and nothing
# in between has an opinion about quoting.
#
# Every probe takes the principal as a literal rather than leaning on
# `current_user`, so the identical SQL can be run as rf_auditor to get ground
# truth. `current_user` would resolve to `rf_auditor` there and the filtered
# probe's ground truth would silently be empty.
#
# No `set -e`. This file is sourced and options leak into the caller.

# Read by run.sh, which sources this file; shellcheck cannot see across that.
# shellcheck disable=SC2034
PROBE_TYPES=(semantic_unfiltered semantic_filtered direct_id side_channel)

# Tables that hold every tenant's data in plaintext. No tenant role holds any
# privilege on them; the side-channel probe checks that this still holds.
# shellcheck disable=SC2034
PROBE_SIDE_TABLES=(canaries probe_runs probe_results retrievals quarantined_memories receipts)

# _probe_evidence <inner select> -> one base64 JSON column named ev
_probe_evidence() {
  printf "SELECT encode(convert_to(coalesce(jsonb_agg(jsonb_build_object("
  printf "'id', id, 'tenant', tenant, 'content', content"
  printf ")), '[]'::JSONB)::STRING, 'UTF8'), 'base64') AS ev FROM (%s) s;" "$1"
}

# ---------------------------------------------------------------------------
# 1. semantic_unfiltered: the forgotten-filter path, and the leak.
#
# An ordinary nearest-neighbour query with no tenant predicate. This is what an
# application writes when someone forgets, and at baseline it is what returns
# another customer's memory.
# ---------------------------------------------------------------------------

probe_sql_semantic_unfiltered() {
  local _principal="$1" vec="$2" limit="$3"
  _probe_evidence "SELECT id, tenant, content FROM memories
     ORDER BY embedding <-> '$vec'::VECTOR(1024) LIMIT $limit"
}

# ---------------------------------------------------------------------------
# 2. semantic_filtered: the correctly scoped application query.
#
# This one passes even at baseline, and that is exactly the point. The app-level
# filter works when someone remembers to write it; the product exists because
# they forget. A matrix where every row fails proves only that the fixture is
# broken.
# ---------------------------------------------------------------------------

probe_sql_semantic_filtered() {
  local principal="$1" vec="$2" limit="$3"
  _probe_evidence "SELECT id, tenant, content FROM memories
     WHERE tenant = '$principal'
     ORDER BY embedding <-> '$vec'::VECTOR(1024) LIMIT $limit"
}

# ---------------------------------------------------------------------------
# 3. direct_id: the alternate lookup path.
#
# Deterministic, and the money shot. It does not depend on an embedding model
# cooperating on the day: the caller names two rows by primary key, one their
# own and one belonging to another tenant, and the result is the same every run.
#
# The grounding, which the demo says out loud rather than leaving to look
# contrived: identifiers leak constantly through logs, URLs, support tickets and
# prior over-broad answers. An attacker who has already seen one over-scoped
# response has the IDs for the next one. Here the harness captured them at
# seeding, which is the same thing without the theatre.
# ---------------------------------------------------------------------------

probe_sql_direct_id() {
  local _principal="$1" own_id="$2" foreign_id="$3"
  _probe_evidence "SELECT id, tenant, content FROM memories
     WHERE id IN ('$own_id'::UUID, '$foreign_id'::UUID)"
}

# ---------------------------------------------------------------------------
# 4. side_channel: what about your own audit log?
#
# The evidence tables are not fenced by RLS. They are fenced at the privilege
# layer, and they hold in plaintext exactly the rows RLS is protecting: every
# tenant's canary phrase, the foreign rows that leaked, cross-tenant read
# history, and the whole breach matrix. A project whose thesis is "the boundary
# belongs in the database" cannot leave that implicit on six tables.
#
# Spike 2 confirmed the default holds. The probe stays anyway, as a regression
# guard against a stray future GRANT, which is exactly the kind of change nobody
# reviews. One statement per table, because a single UNION would be aborted by
# the first denial and the rest would go untested.
# ---------------------------------------------------------------------------

probe_sql_side_channel_one() {
  printf "SELECT count(*) AS n FROM %s;" "$1"
}
