-- RecallFence: drop the fence for the negative-control phase.
--
-- DISABLE, not DROP POLICY. The policy set stays defined and re-arming is one
-- statement, so the control run cannot accidentally become a permanent state
-- through a half-finished cleanup.
--
-- The negative control is what keeps the receipt honest in the other direction.
-- Every other phase asks "did the boundary hold"; this one asks "would we have
-- noticed if it hadn't", by running the identical probe matrix with nothing in
-- the way. It is recorded like any other phase and excluded from the receipt's
-- pass computation.
--
-- It is also the only phase in which the vector index is actually used, since
-- any active RLS policy structurally excludes it. Baseline-vs-control latency is
-- the honest measurement of what the boundary costs: 11ms indexed against 326ms
-- scanned at 48k rows in spike 1.

ALTER TABLE memories NO FORCE ROW LEVEL SECURITY;
ALTER TABLE memories DISABLE ROW LEVEL SECURITY;
