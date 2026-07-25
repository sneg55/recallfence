# schema/

Tables, roles, grants, the RLS policy set, and the changefeed. Everything that
makes the boundary a property of the database rather than of application code.

Applied and verified against the live CockroachDB Cloud Basic cluster
(v26.2.1, database `recallfence`). `tests/test_policies.sh` covers it: 33 cases,
per role per operation, all passing.

## Order, and why there is no `apply.sh all`

```
schema/apply.sh tables                  # 001
schema/apply.sh roles alice bob carol   # 002, 003, then 005 asserts
  <-- the fixture loader runs HERE
schema/apply.sh policies                # 004, then RLS on
schema/apply.sh changefeed              # 006 (needs the S3 sink secret)
```

The gap in the middle is deliberate. Under `FORCE ROW LEVEL SECURITY` an
operation with no applicable policy is denied for **every** role including the
table owner, so a seeder that ran after the fence went up would need a policy
that exists only to let it cheat. Seeding before means the fixture loader needs
no policy at all, and the policy set stays honest.

`apply.sh assert <roles...>` re-runs the non-privileged check alone. The service
runtime should call the same check at startup.

## Files

| File | What |
|---|---|
| `001_tables.sql` | 7 tables, the prefix vector index, CHECK constraints |
| `002_service_roles.sql.tmpl` | `rf_auditor`, `rf_remediation`, `rf_harness` + the full grant matrix |
| `003_tenant_role.sql.tmpl` | one tenant role, applied once per tenant |
| `004_policies.sql` | 5 policies, then `ENABLE` + `FORCE ROW LEVEL SECURITY` |
| `005_assert_roles.sql.tmpl` | the provisioning-time refusal |
| `006_changefeed.sql.tmpl` | `receipts` to S3 |
| `010_rls_off.sql` / `011_rls_on.sql` | negative-control toggle |
| `lib/crsql.sh` | resolves `cockroach sql`, native or via Apple `container` |

Templates are rendered in memory and piped to the cluster. They are never
written to disk, because the rendered output carries generated role passwords
and, for the changefeed, a live AWS secret key.

## Two additions to the design spec

Both surfaced while making the grant matrix total, and both close things the
original design left implicit.

**`auditor_read` is a sixth policy the spec's "full set" omits.** The spec lists
four (`tenant_isolation`, `tenant_write`, `remediation_read`,
`quarantine_delete`) and separately requires that every probe result record what
the auditor sees for the same predicate at the same moment. Those two cannot both
be true: under `FORCE` RLS, `rf_auditor` is covered only by `tenant_isolation`,
which resolves to `tenant = 'rf_auditor'` and matches nothing. Without an
explicit `FOR SELECT TO rf_auditor USING (true)`, `auditor_ground_truth` is
always empty and the receipt cannot tell a working boundary from an emptied
table. `rf_auditor` still holds no INSERT, UPDATE or DELETE policy on `memories`.

**`rf_harness` is a fifth role class.** The spec names four, and then twice
implies a fifth: the harness "writes `probe_runs` and `probe_results` under its
own account", and no tenant role may hold any privilege on the six evidence
tables. `retrievals` is one of those six and the support agent has to write it on
every retrieval, so the writer cannot be the tenant role without breaking the
access rule. Naming the account makes the matrix total.

`rf_harness` holds **no privilege on `memories` at all**, so it cannot read a
memory row under any query. It holds INSERT on `retrievals` **without** SELECT:
the agent runtime keeps this connection alongside its fenced tenant connection,
and append-only means a compromised agent can add noise to its own audit trail
but cannot read it back to learn what other sessions retrieved.

## One correction to the design spec

The spec says UPDATE and DELETE "with no applicable policy return zero rows
affected and no error", and warns that harness logic must not infer "blocked"
from an exception. That is true, but it is **conditional on holding the table
privilege**, and in the shipped grant matrix tenant roles do not.

Two layers answer, in order:

| Situation | Signal |
|---|---|
| no privilege | hard error, SQLSTATE 42501 |
| privilege, no policy | zero rows affected, **no error** |

Tenant roles hold only SELECT and INSERT, so their UPDATE and DELETE attempts hit
the privilege layer and fail loudly. The silent path is still real and still
matters: `tests/test_policies.sh` walks into it deliberately by granting alice
UPDATE and leaving the policy set alone, then confirms the write is blocked in
silence and that revoking the grant makes it loud again.

The consequence is sharper than the original warning. A stray `GRANT` does not
merely widen access, it **converts a loud failure into a silent one without
changing a single policy**. That is why the grant matrix is load-bearing rather
than belt-and-braces, and why the `side_channel` probe keeps testing privileges
that already hold by default.

## Findings this module bakes in

- **The vector index is retained but is not on the fenced read path.** With any
  RLS policy active, CockroachDB will not use it and falls back to an exact full
  scan; an index hint under RLS errors outright (spike 1). The index still serves
  the negative-control phase, which is where the honest cost-of-the-boundary
  measurement comes from.
- **Provisioning is the dangerous step.** `ccloud cluster user create` returns an
  admin superuser with `rolbypassrls` (spike 6), and the default Cloud SQL user
  is one too (spike 3). `005_assert_roles.sql.tmpl` refuses to continue if any
  managed role comes back privileged. Verified to bite: granting `admin` to a
  tenant makes `apply.sh assert` exit 1 with `FAIL_SUPERUSER`.
- **Remediation needs both SELECT and DELETE policies.** A `FOR DELETE` policy
  alone deletes zero rows, because with no SELECT policy the role sees nothing
  and `DELETE ... WHERE` cannot evaluate its predicate (spike 2). Quarantine
  would report success and move nothing.
- **Tenant roles are flat.** No group role, no memberships. That is what makes
  `SET ROLE bob` fail and `RESET ROLE` leave the connection still fenced
  (spike 5). A convenience group would have made the grants static at the cost of
  the property the whole thesis rests on.

## Environment

| Variable | Default | Notes |
|---|---|---|
| `RF_CLUSTER_URL` | required | admin connection URL |
| `RF_SECRETS_PREFIX` | `recallfence` | Secrets Manager path prefix |
| `RF_AWS_REGION` | `us-east-2` | |
| `RF_SKIP_SECRETS` | unset | `1` prints passwords instead of storing them |
| `RF_S3_BUCKET` | required for `changefeed` | |
| `RF_COCKROACH_IMAGE` | `cockroachdb/cockroach:v26.2.0` | container backend only |
| `RF_CONTAINER_DNS` | `1.1.1.1` | container backend only, see below |

Passwords are generated from `/dev/urandom` and go straight into Secrets Manager
without being echoed or written to a file. This is why role creation lives here
rather than being split across `schema/` and `infra/`: anywhere else and the
password would have to survive a hop.

`lib/crsql.sh` prefers a native `cockroach` binary and falls back to Apple's
`container` runtime. The fallback needs an explicit `--dns`, because containers
on that runtime do not inherit the host resolver and the failure mode is a
misleading `cannot dial server` timeout against a host the machine reaches fine.
