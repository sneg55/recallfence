# infra/

The AWS and Cloudflare side, and a preflight that tells the truth about it.

```bash
infra/doctor.sh                          check every external dependency
infra/provision.sh all <bucket>          bucket + scoped changefeed principal
infra/deploy-web.sh                       refresh the snapshot and deploy to Pages
```

Much of what "infra" usually means already lives in `schema/apply.sh`: role
creation with the non-privileged assertion, the changefeed, teardown, and secret
storage. This directory is the rest: the preflight, the correctly-created bucket,
and the deploy.

## doctor.sh is the important one

A preflight that only ever prints OK is theatre. This one is written around the
specific failures this project hit, so a fresh environment fails loudly here
rather than three commands into a demo. It is read-only and changes nothing.

It reports, honestly:

- **Cluster**: reachable, and no `rf_` role is superuser or bypasses RLS. That
  assertion is the whole thesis; the vendor CLI hands out `rolsuper` by default,
  so it is checked rather than assumed.
- **AWS**: reachable, and it *warns* when running as the account root rather than
  pretending that is fine.
- **Secrets**: the expected role and changefeed secrets are present in Secrets
  Manager.
- **S3 sink**: bucket reachable, versioning on, and Object Lock present or absent
  with the reason. Absent is a warning, not a failure, because tamper-evidence
  comes from the hash chain and not the bucket.
- **Models**: two checks, because "Bedrock" is two services that answer
  differently. Classic `bedrock-runtime` is probed with a real embedding call,
  since that is the endpoint the corpus needs, and the agent backend is resolved
  through `agent/lib/model.sh` itself so the report names the backend the agents
  will actually pick. Refusal on either is a warning: the build embeds with
  `local-hash-v1`, the agents print facts verbatim, and every receipt records its
  model so a fallback cannot masquerade as Titan.

Required checks failing exits non-zero. Warnings are honest fallbacks and do not.

## provision.sh, and the Object Lock trap

**Object Lock can only be enabled when a bucket is created.** A bucket made
without it can never have it added, which is exactly the state the spike-era
bucket is in, and why `provision.sh bucket` creates new buckets with
`--object-lock-enabled-for-bucket` from the start and can only *report* on an
existing one.

None of this is what makes receipts tamper-evident. The hash chain is, and it
survives an attacker with full write access to the bucket. Object Lock and a
delete-less IAM principal are defence in depth on top of that. `doctor.sh` says
so rather than implying the chain is only as strong as the bucket.

`provision.sh changefeed-iam` writes the changefeed principal's policy: scoped to
one prefix, and deliberately **without `s3:DeleteObject`**, so the account that
ships receipts to the sink cannot delete from it. Verified live: writes to any
other prefix are denied, and the policy carries no delete action. It does not
mint access keys if one already exists; rotation is a console action.

## deploy-web.sh, and the stale-snapshot guard

The dashboard is static and renders from `web/public/replay.json`, so deploy is a
file upload with one precondition: the snapshot must be current. A stale snapshot
is the one way a static demo silently lies, showing an old receipt while looking
live. So the script refreshes the snapshot from the cluster first, and if the
cluster is reachable it refuses to deploy a snapshot whose receipt is not the
newest one in the database.

## Why the harness stays a CLI

`harness/run.sh` is a CLI runner, not a deployed service. Iteration never goes
through a deploy, the demo renders from a committed snapshot, and the CLI prints
the same evidence the dashboard does. Putting it behind a Lambda would add a
packaging step to the critical path and buy nothing this project needs.

## Credential handling

Every credential these scripts touch is fetched from Secrets Manager at run time
and none is written to disk: `schema/apply.sh` renders SQL templates in memory
and pipes them to the cluster, because a rendered changefeed statement carries a
live access key.

`doctor.sh` warns when the AWS CLI is authenticated as the account root. The
scripts need only S3 write, Secrets Manager read, and changefeed setup, so a
scoped IAM user is the safer principal to run them under; the warning names root
because a wide credential is the opposite of what this project argues for.

The cluster and AWS account behind the recorded run are disposable demo
infrastructure. The receipt does not depend on either surviving: `audit/verify.sh
--from-file` re-verifies a delivered chain with nothing reachable at all.
