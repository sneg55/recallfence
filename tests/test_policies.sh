#!/usr/bin/env bash
# RecallFence: policy enforcement, per role per operation.
#
#   RF_CLUSTER_URL=... ./tests/test_policies.sh
#
# This is the evidence behind the Production Readiness claim. Every case
# connects over that role's own credentials, fetched from Secrets Manager. None
# of them use SET ROLE from a shared admin session, because a session that can
# SET ROLE can also RESET ROLE and the fence would be one statement deep. Spike 5
# established the difference; this file keeps it from regressing.
#
# Requires the schema to be applied and RLS to be on:
#   schema/apply.sh tables && schema/apply.sh roles alice bob carol
#   schema/apply.sh policies
#
# Seeding runs as the admin URL, which bypasses RLS. That is the same bypass the
# real fixture loader relies on, and it is only ever used to put rows in. Every
# assertion below reads through a fenced connection.

set -uo pipefail  # deliberately not -e: over half these cases expect a failure

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$HERE/../schema/lib/crsql.sh"

# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"

# ---------------------------------------------------------------------------

crsql_require || exit 1

group "seeding fixture rows (admin connection, RLS bypassed, writes only)"
run_as "$RF_CLUSTER_URL" "
DELETE FROM memories WHERE session_id = 'test_policies';
INSERT INTO memories (tenant, content, embedding_model, written_by, origin_tenant, session_id, source, trust) VALUES
  ('alice', 'alice refund ceiling is 200', 'test', 'alice', 'alice', 'test_policies', 'user_message', 'user_confirmed'),
  ('alice', 'alice prefers email contact',  'test', 'alice', 'alice', 'test_policies', 'user_message', 'user_confirmed'),
  ('bob',   'bob refund ceiling is 5000',   'test', 'bob',   'bob',   'test_policies', 'user_message', 'user_confirmed'),
  ('bob',   'bob escalates to legal',       'test', 'bob',   'bob',   'test_policies', 'user_message', 'user_confirmed'),
  ('carol', 'carol is on the trial plan',   'test', 'carol', 'carol', 'test_policies', 'user_message', 'user_confirmed'),
  ('alice', 'ceiling raised per bob call',  'test', 'agent', 'bob',   'test_policies', 'agent_summary', 'model_derived');
" >/dev/null || { echo "seeding failed" >&2; exit 1; }
echo "  6 rows: 3 alice (one mis-attributed), 2 bob, 1 carol"

ALICE_URL="$(url_for alice tenant)"
BOB_URL="$(url_for bob tenant)"
AUDITOR_URL="$(url_for rf_auditor service)"
REMEDIATION_URL="$(url_for rf_remediation service)"
HARNESS_URL="$(url_for rf_harness service)"

# ---------------------------------------------------------------------------
group "tenant role: the boundary is a property of the connection"
# ---------------------------------------------------------------------------

expect_count "alice sees exactly her own 3 rows" "$ALICE_URL" \
  "SELECT count(*) FROM memories WHERE session_id='test_policies';" "3"

expect_count "alice's session_user is alice, not a superuser wearing a costume" "$ALICE_URL" \
  "SELECT current_user = session_user AND current_user = 'alice' AS ok;" "t"

# Asking for bob's rows by name returns nothing rather than erroring. The policy
# is a filter, not a gate: there is no query alice can write to reach them.
expect_count "alice asking for bob's rows by name gets zero" "$ALICE_URL" \
  "SELECT count(*) FROM memories WHERE tenant='bob';" "0"

expect_count "bob sees exactly his own 2 rows" "$BOB_URL" \
  "SELECT count(*) FROM memories WHERE session_id='test_policies';" "2"

# The escape hatch is absent, not merely discouraged. Alice holds membership in
# no other role, so there is nothing to assume.
expect_denied "alice cannot SET ROLE bob" "$ALICE_URL" \
  "SET ROLE bob;" "permission denied"

expect_denied "alice cannot SET ROLE root" "$ALICE_URL" \
  "SET ROLE root;" "only root can become root"

expect_count "RESET ROLE leaves alice still fenced" "$ALICE_URL" \
  "RESET ROLE; SELECT count(*) FROM memories WHERE session_id='test_policies';" "3"

# ---------------------------------------------------------------------------
group "tenant role: writes"
# ---------------------------------------------------------------------------

# Loud, during execution. This is what makes quarantine class 1 unrepeatable
# once the policy set is applied.
expect_denied "alice cannot INSERT into bob's memory" "$ALICE_URL" \
  "INSERT INTO memories (tenant, content, embedding_model) VALUES ('bob','injected','test');" \
  "policy"

expect_ok "alice can INSERT into her own memory" "$ALICE_URL" \
  "INSERT INTO memories (tenant, content, embedding_model, session_id) VALUES ('alice','own write','test','test_policies_write');" \
  "INSERT"

# Alice owns these rows and still cannot touch them. In the shipped grant matrix
# this denial is LOUD, because she holds no UPDATE or DELETE privilege at all and
# the privilege layer answers before RLS is ever consulted.
expect_denied "alice cannot UPDATE even her own rows" "$ALICE_URL" \
  "UPDATE memories SET content='tampered' WHERE session_id='test_policies';" "42501"

expect_denied "alice cannot DELETE even her own rows" "$ALICE_URL" \
  "DELETE FROM memories WHERE session_id='test_policies';" "42501"

expect_count "and her rows are all still there afterwards" "$ALICE_URL" \
  "SELECT count(*) FROM memories WHERE session_id='test_policies' AND content <> 'tampered';" "3"

# ---------------------------------------------------------------------------
group "the silent-denial trap (why the grant matrix is load-bearing, not belt-and-braces)"
# ---------------------------------------------------------------------------

# Two enforcement layers answer in order: privileges first, then policies. The
# two fail in opposite ways, and only one of them tells the caller.
#
#   no privilege          -> hard error, SQLSTATE 42501
#   privilege, no policy  -> zero rows affected, NO error
#
# Everything above lands in the first case. This block deliberately walks into
# the second, by granting alice the UPDATE privilege the shipped matrix withholds
# and leaving the policy set alone. The write is still blocked, but now it is
# blocked in silence, and an agent that infers "I was blocked" from catching an
# exception would conclude the write succeeded.
#
# That is why the harness compares affected-row counts against expectation rather
# than catching errors, and why a stray GRANT is a real hazard rather than
# untidiness: it converts a loud failure into a silent one without changing a
# single policy.

run_as "$RF_CLUSTER_URL" "GRANT UPDATE ON TABLE memories TO alice;" >/dev/null

TRAP_OUT="$(run_as "$ALICE_URL" "UPDATE memories SET content='tampered' WHERE session_id='test_policies';")"
if [[ "$TRAP_OUT" == *"UPDATE 0"* ]]; then
  pass "with the privilege but no policy, UPDATE is denied SILENTLY (0 rows, no error)"
else
  fail "with the privilege but no policy, UPDATE is denied SILENTLY (0 rows, no error)" \
       "got: $(tr '\n' '|' <<<"$TRAP_OUT")"
fi

run_as "$RF_CLUSTER_URL" "REVOKE UPDATE ON TABLE memories FROM alice;" >/dev/null

expect_denied "grant revoked, alice's UPDATE is loud again" "$ALICE_URL" \
  "UPDATE memories SET content='tampered' WHERE session_id='test_policies';" "42501"

expect_count "nothing was tampered with in either case" "$ALICE_URL" \
  "SELECT count(*) FROM memories WHERE session_id='test_policies' AND content = 'tampered';" "0"

# ---------------------------------------------------------------------------
group "tenant role: the side channel (evidence tables hold every tenant's data in plaintext)"
# ---------------------------------------------------------------------------

for t in canaries probe_runs probe_results retrievals quarantined_memories receipts; do
  expect_denied "alice cannot read $t" "$ALICE_URL" \
    "SELECT count(*) FROM $t;" "42501"
done

# ---------------------------------------------------------------------------
group "rf_auditor: ground truth, read-only over evidence, append-only over receipts"
# ---------------------------------------------------------------------------

# The whole point of auditor_read. Without it, a tenant-visible "zero rows"
# cannot be distinguished from an emptied table.
expect_count "auditor sees all 7 rows across every tenant" "$AUDITOR_URL" \
  "SELECT count(*) FROM memories WHERE session_id LIKE 'test_policies%';" "7"

expect_ok "auditor can read canaries" "$AUDITOR_URL" "SELECT count(*) FROM canaries;" "count"
expect_ok "auditor can read retrievals" "$AUDITOR_URL" "SELECT count(*) FROM retrievals;" "count"

expect_denied "auditor cannot DELETE a memory" "$AUDITOR_URL" \
  "DELETE FROM memories WHERE session_id='test_policies';" "42501"

expect_denied "auditor cannot INSERT a memory" "$AUDITOR_URL" \
  "INSERT INTO memories (tenant, content, embedding_model) VALUES ('alice','x','test');" "42501"

# Append-only over receipts, asserted rather than claimed.
#
# This group was headed "append-only over receipts" for a while with nothing
# below it testing that, which is its own kind of failure: a heading is not a
# test. The property is the reason rf_auditor is the receipt writer at all, so
# the account that attests the breach must be able to add a receipt and unable to
# revise or remove one it already signed.
expect_ok "auditor can read receipts" "$AUDITOR_URL" \
  "SELECT count(*) FROM receipts;" "count"

# The INSERT is committed nowhere. It runs inside a transaction that rolls back,
# which still proves the privilege: a role without INSERT fails at the statement,
# not at COMMIT.
#
# The first version of this committed a sentinel receipt and deleted it
# afterwards, and that was wrong in a way worth recording. `receipts` feeds a
# changefeed into an append-only S3 sink, so the sink captured every sentinel and
# kept it after the row was gone, permanently. Chain verification against the
# sink then failed on junk this suite had written. Deleting from the database
# does not un-publish an audit record; that is the entire point of the sink.
expect_ok "auditor can APPEND a receipt (rolled back)" "$AUDITOR_URL" \
  "BEGIN;
   INSERT INTO receipts (passed, receipt_json, receipt_hash)
     VALUES (false, '{\"probe\":\"test_policies\"}'::JSONB, 'test_policies_rollback');
   ROLLBACK;" "ROLLBACK"

# Denials are asserted against the receipts that are really there. A privilege
# check fails before any row is touched, so these need no fixture of their own.
expect_denied "auditor cannot UPDATE a receipt it signed" "$AUDITOR_URL" \
  "UPDATE receipts SET passed = true WHERE receipt_hash IS NOT NULL;" "42501"

expect_denied "auditor cannot DELETE a receipt it signed" "$AUDITOR_URL" \
  "DELETE FROM receipts WHERE receipt_hash IS NOT NULL;" "42501"

# ---------------------------------------------------------------------------
group "rf_remediation: the only role that can remove a memory"
# ---------------------------------------------------------------------------

# Spike 2: a FOR DELETE policy alone deletes zero rows, because with no SELECT
# policy the role sees nothing and DELETE cannot evaluate its predicate. This
# case is what keeps someone from "simplifying" remediation_read away.
expect_count "remediation sees all rows (without this, quarantine moves nothing)" "$REMEDIATION_URL" \
  "SELECT count(*) FROM memories WHERE session_id LIKE 'test_policies%';" "7"

expect_ok "remediation can read retrievals (quarantine class 2 needs the join)" "$REMEDIATION_URL" \
  "SELECT count(*) FROM retrievals;" "count"

expect_ok "remediation can actually delete (rolled back)" "$REMEDIATION_URL" \
  "BEGIN; DELETE FROM memories WHERE session_id='test_policies'; ROLLBACK;" "DELETE 6"

expect_denied "remediation cannot INSERT a memory" "$REMEDIATION_URL" \
  "INSERT INTO memories (tenant, content, embedding_model) VALUES ('alice','x','test');" "42501"

# ---------------------------------------------------------------------------
group "rf_harness: writes the breach matrix, can never read a memory"
# ---------------------------------------------------------------------------

expect_denied "harness cannot read memories at all" "$HARNESS_URL" \
  "SELECT count(*) FROM memories;" "42501"

# The retrieval log moved to rf_agent. The harness never wrote it, and leaving it
# here meant the tenant-facing agent had to hold this credential to log a read.
expect_denied "harness can no longer write the retrieval log" "$HARNESS_URL" \
  "INSERT INTO retrievals (session_id, principal, tenant, returned_ids) VALUES ('test_policies','alice','alice',ARRAY[]::UUID[]);" \
  "42501"

# ---------------------------------------------------------------------------
group "rf_agent: the support agent's connection, and nothing more"
# ---------------------------------------------------------------------------

# Split out of rf_harness because the support agent runs tenant-facing code. It
# needs to append to the retrieval log, and rf_harness could also read canaries
# and probe_results, which hold every tenant's leaked rows in plaintext. Handing
# the agent that credential let tenant-facing code read around the RLS boundary.
AGENT_URL="$(url_for rf_agent service)"

expect_ok "agent can append to the retrieval log" "$AGENT_URL" \
  "INSERT INTO retrievals (session_id, principal, tenant, returned_ids) VALUES ('test_policies','alice','alice',ARRAY[]::UUID[]);" \
  "INSERT"

# Append-only: a compromised agent can add noise to its own audit trail but
# cannot read it back to learn what other sessions retrieved.
expect_denied "agent cannot read the retrieval log back" "$AGENT_URL" \
  "SELECT count(*) FROM retrievals;" "42501"

# The reason rf_agent exists. Each of these succeeds for rf_harness.
expect_denied "agent cannot read canaries" "$AGENT_URL" \
  "SELECT count(*) FROM canaries;" "42501"
expect_denied "agent cannot read probe_results" "$AGENT_URL" \
  "SELECT count(*) FROM probe_results;" "42501"
expect_denied "agent cannot read memories" "$AGENT_URL" \
  "SELECT count(*) FROM memories;" "42501"
expect_denied "agent cannot write the breach matrix" "$AGENT_URL" \
  "INSERT INTO probe_runs (phase) VALUES ('baseline');" "42501"

# ---------------------------------------------------------------------------

group "cleanup"
run_as "$RF_CLUSTER_URL" "
DELETE FROM memories WHERE session_id LIKE 'test_policies%';
DELETE FROM retrievals WHERE session_id = 'test_policies';
" >/dev/null && echo "  fixture rows removed"

summary
