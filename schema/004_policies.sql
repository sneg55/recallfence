-- RecallFence, step 4 of 4: the policy set, then the fence goes up.
--
-- Run this AFTER the fixture loader. Under FORCE ROW LEVEL SECURITY an
-- operation with no applicable policy is denied for every role including the
-- table owner, so a seeder that runs after this file would need a policy that
-- exists only to let it cheat.
--
-- Policies are created before RLS is enabled, so there is no window in which the
-- table is fenced with an empty policy set.
--
-- Every policy below is permissive, so they OR together. A role covered by both
-- a PUBLIC policy and a role-scoped one gets the union, which is why
-- rf_auditor and rf_remediation see everything while tenants covered only by the
-- PUBLIC policy see their own rows.
--
-- Idempotent. Safe to re-run.

DROP POLICY IF EXISTS tenant_isolation  ON memories;
DROP POLICY IF EXISTS tenant_write      ON memories;
DROP POLICY IF EXISTS auditor_read      ON memories;
DROP POLICY IF EXISTS remediation_read  ON memories;
DROP POLICY IF EXISTS quarantine_delete ON memories;

-- ---------------------------------------------------------------------------
-- The boundary itself.
--
-- `current_user` as a bare keyword is the spelling spike 1 executed. Note that
-- with this policy active the vector index on (tenant, embedding) is no longer
-- usable and reads become exact full scans. That is the intended trade and the
-- source of the demo's latency beat, not a regression.
-- ---------------------------------------------------------------------------

CREATE POLICY tenant_isolation ON memories
  FOR SELECT TO PUBLIC
  USING (tenant = current_user);

-- A buggy or compromised agent cannot write into another tenant's memory.
-- Spike 2: a cross-tenant INSERT is rejected during execution with SQLSTATE
-- 42501, loudly. This is a demo beat, not only a safety net, and it is also what
-- makes quarantine class 1 (origin_tenant <> tenant) unrepeatable going forward.
CREATE POLICY tenant_write ON memories
  FOR INSERT TO PUBLIC
  WITH CHECK (tenant = current_user);

-- Note what is absent: no UPDATE policy and no DELETE policy for tenant roles.
-- They cannot mutate or remove memories at all.
--
-- A caveat that changes how the agent must treat rejections. INSERT denial is
-- loud, but spike 2 confirmed that UPDATE and DELETE with no applicable policy
-- return zero rows affected and NO error. The fence holds either way, but only
-- INSERT signals the caller. Any harness or agent logic that infers "I was
-- blocked" from an exception will miss a blocked UPDATE or DELETE entirely, so
-- blocked mutations must be detected by comparing affected-row counts against
-- expectation, never by catching errors.

-- ---------------------------------------------------------------------------
-- auditor_read: ground truth.
--
-- Without this the auditor is covered only by tenant_isolation, which resolves
-- to `tenant = 'rf_auditor'` and matches nothing. Every probe result records
-- what the auditor sees for the same predicate at the same moment, because RLS
-- hiding a row and quarantine deleting a row both produce zero rows returned.
-- A tenant-visible "nothing" proves nothing on its own, and distinguishing a
-- working boundary from an emptied table is the first question a sharp judge
-- asks. rf_auditor holds no INSERT, UPDATE or DELETE policy on memories.
-- ---------------------------------------------------------------------------

CREATE POLICY auditor_read ON memories
  FOR SELECT TO rf_auditor
  USING (true);

-- ---------------------------------------------------------------------------
-- Remediation needs TWO policies, and this is a correctness requirement rather
-- than a nicety. Spike 2: a FOR DELETE policy alone deletes zero rows, because
-- with no SELECT policy the role sees no rows and `DELETE ... WHERE` cannot
-- evaluate its predicate against invisible rows. Quarantine would then report
-- success and move nothing, which is the worst possible outcome for a tool whose
-- entire output is a receipt saying the cleanup happened.
--
-- Both are scoped TO rf_remediation, so tenant isolation is unaffected: spike 2
-- verified alice still sees only her own rows afterwards.
-- ---------------------------------------------------------------------------

CREATE POLICY remediation_read ON memories
  FOR SELECT TO rf_remediation
  USING (true);

CREATE POLICY quarantine_delete ON memories
  FOR DELETE TO rf_remediation
  USING (true);

-- ---------------------------------------------------------------------------
-- The fence goes up. FORCE is what subjects the table owner too; without it an
-- application connected as the owner would sail straight past every policy
-- above and the proof would be vacuous.
--
-- FORCE does not subject superusers or roles with rolbypassrls. Nothing in SQL
-- can. That is what the startup refusal check and 005_assert_roles.sql are for.
-- ---------------------------------------------------------------------------

ALTER TABLE memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE memories FORCE ROW LEVEL SECURITY;
