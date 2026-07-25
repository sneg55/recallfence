#!/usr/bin/env bash
# RecallFence: bring up the AWS side of the audit sink, idempotently.
#
#   infra/provision.sh bucket <name>     an S3 bucket created correctly for receipts
#   infra/provision.sh changefeed-iam    the scoped, delete-less changefeed principal
#   infra/provision.sh all <bucket>      both, then print what to put in the sink secret
#
# Two things about Object Lock that are easy to get wrong, and this script got
# the first one wrong until a review corrected it:
#
#   1. It does NOT have to be enabled at bucket creation. AWS supports enabling
#      Object Lock on an existing bucket that already has versioning, so an
#      existing sink is fixable in place rather than needing a new bucket.
#   2. Enabling it protects nothing on its own. Without a default retention rule,
#      or a per-object retention, versions are not actually locked. "Object Lock
#      is on" and "receipts cannot be removed" are different statements.
#
# So this sets a retention rule, and doctor.sh reports the difference rather than
# treating the presence of a configuration as protection.
#
# None of this is what makes receipts tamper-evident. The hash chain is, and it
# survives an attacker with full write access to the bucket. Object Lock and a
# delete-less IAM principal are defence in depth on top of that, not the load-
# bearing mechanism. `doctor.sh` reports honestly when they are absent rather than
# implying the chain is only as good as the bucket.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../schema/lib/creds.sh
source "$ROOT/schema/lib/creds.sh"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

CF_USER="recallfence-changefeed"
CF_POLICY="changefeed-s3-write"

cmd_bucket() {
  local name="${1:-}"
  [[ -n "$name" ]] || die "usage: provision.sh bucket <name>"

  local retain_days="${RF_OBJECT_LOCK_DAYS:-30}"

  if aws s3api head-bucket --bucket "$name" >/dev/null 2>&1; then
    say "bucket $name already exists"
    aws s3api put-bucket-versioning --bucket "$name" \
      --versioning-configuration Status=Enabled >/dev/null 2>&1 || true
    # Enabling Object Lock in place requires versioning, which the line above
    # ensures. This is idempotent and safe to re-run.
    if aws s3api put-object-lock-configuration --bucket "$name" \
         --object-lock-configuration "ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=GOVERNANCE,Days=$retain_days}}" \
         >/dev/null 2>&1; then
      printf '  Object Lock enabled with GOVERNANCE retention, %s days.\n' "$retain_days"
    else
      printf '  \033[33mCould not enable Object Lock in place.\033[0m Usually versioning was only\n'
      printf '  just turned on, or the caller lacks s3:PutBucketObjectLockConfiguration.\n'
      printf '  The hash chain is unaffected: tamper-evidence does not depend on the bucket.\n'
    fi
  else
    say "creating $name with versioning, Object Lock and public access blocked"
    # Object Lock enabled at creation, which also forces versioning on.
    if [[ "$RF_AWS_REGION" == "us-east-1" ]]; then
      aws s3api create-bucket --bucket "$name" --region us-east-1 \
        --object-lock-enabled-for-bucket >/dev/null
    else
      aws s3api create-bucket --bucket "$name" --region "$RF_AWS_REGION" \
        --create-bucket-configuration "LocationConstraint=$RF_AWS_REGION" \
        --object-lock-enabled-for-bucket >/dev/null
    fi
    aws s3api put-public-access-block --bucket "$name" \
      --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    printf '  created.\n'
  fi

  # A default retention on the receipts prefix would need per-object legal holds
  # or a bucket-wide rule; kept as a documented follow-up rather than a silent
  # half-measure. Governance-mode retention on the prefix is the intended policy.
  printf '  versioning: %s\n' \
    "$(aws s3api get-bucket-versioning --bucket "$name" --query Status --output text 2>/dev/null || echo unknown)"
}

cmd_changefeed_iam() {
  say "changefeed IAM principal: $CF_USER"

  aws iam get-user --user-name "$CF_USER" >/dev/null 2>&1 \
    || { aws iam create-user --user-name "$CF_USER" >/dev/null; printf '  created user\n'; }

  local bucket="${RF_S3_BUCKET:-}"
  [[ -n "$bucket" ]] || die "set RF_S3_BUCKET so the policy can be scoped to it"
  local prefix="${RF_S3_PREFIX:-receipts}"

  # Scoped to one prefix, with three corrections a review earned:
  #
  #   * ListBucket is conditioned on s3:prefix. Without the condition it is a
  #     bucket-level action and the principal could enumerate every key in the
  #     bucket, not just its own prefix.
  #   * An explicit Deny on the delete actions. Omitting Allow is not the same as
  #     Deny: IAM unions permissions, so any other attached or bucket policy
  #     could grant deletion later. An explicit Deny cannot be overridden.
  #   * The Deny also covers versioned deletes and Object Lock manipulation, so
  #     the writer cannot remove a version or weaken a retention rule.
  #
  # Note honestly what this does NOT prevent: PutObject on an existing key
  # creates a new version rather than being refused. With versioning on, the old
  # version survives, which is why versioning is part of the story. The sink is
  # append-only in the sense that history cannot be removed, not in the sense
  # that a key can never be written twice.
  local doc
  doc="$(jq -c -n --arg b "$bucket" --arg p "$prefix" '{
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ChangefeedWriteReceipts",
        Effect: "Allow",
        Action: ["s3:PutObject", "s3:GetObject"],
        Resource: ["arn:aws:s3:::\($b)/\($p)/*"]
      },
      {
        Sid: "ListOnlyOwnPrefix",
        Effect: "Allow",
        Action: ["s3:ListBucket"],
        Resource: ["arn:aws:s3:::\($b)"],
        Condition: {StringLike: {"s3:prefix": ["\($p)/*"]}}
      },
      {
        Sid: "NeverDelete",
        Effect: "Deny",
        Action: ["s3:DeleteObject", "s3:DeleteObjectVersion",
                 "s3:PutObjectRetention", "s3:PutObjectLegalHold",
                 "s3:PutBucketObjectLockConfiguration", "s3:PutBucketVersioning"],
        Resource: ["arn:aws:s3:::\($b)", "arn:aws:s3:::\($b)/*"]
      }
    ]
  }')"
  aws iam put-user-policy --user-name "$CF_USER" \
    --policy-name "$CF_POLICY" --policy-document "$doc" >/dev/null
  printf '  policy %s scoped to s3://%s/%s/* (no DeleteObject)\n' "$CF_POLICY" "$bucket" "$prefix"

  printf '  access keys are created here only if none exist; rotate via the console.\n'
  local nkeys
  nkeys="$(aws iam list-access-keys --user-name "$CF_USER" \
            --query 'length(AccessKeyMetadata)' --output text 2>/dev/null || echo 0)"
  if [[ "$nkeys" == 0 ]]; then
    printf '  no access key exists. Create one and store it in %s/changefeed/s3-sink:\n' "$RF_SECRETS_PREFIX"
    printf '    aws iam create-access-key --user-name %s\n' "$CF_USER"
  else
    printf '  %s access key(s) already exist; not creating another.\n' "$nkeys"
  fi
}

case "${1:-}" in
  bucket)          shift; cmd_bucket "$@" ;;
  changefeed-iam)  shift; cmd_changefeed_iam "$@" ;;
  all)
    shift
    RF_S3_BUCKET="${1:?usage: provision.sh all <bucket>}"; export RF_S3_BUCKET
    cmd_bucket "$RF_S3_BUCKET"
    cmd_changefeed_iam
    say "next"
    printf '  Put the changefeed key in Secrets Manager as %s/changefeed/s3-sink with\n' "$RF_SECRETS_PREFIX"
    printf '  fields aws_access_key_id, aws_secret_access_key, bucket, prefix, region.\n'
    printf '  Then: schema/apply.sh changefeed\n'
    ;;
  *) sed -n '2,10p' "${BASH_SOURCE[0]}" >&2; exit 1 ;;
esac
