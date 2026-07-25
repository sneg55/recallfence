-- RecallFence: re-arm the fence after a negative-control run.
--
-- Paired with 010_rls_off.sql. The policy set is untouched by that file, so this
-- restores the exact configuration 004_policies.sql left behind.

ALTER TABLE memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE memories FORCE ROW LEVEL SECURITY;
