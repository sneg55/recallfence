#!/usr/bin/env bash
# RecallFence: is the environment actually able to run this?
#
#   infra/doctor.sh
#
# Checks every external dependency and reports the real state of each, including
# the ones that are wrong. A preflight that only prints OK is theatre; this one
# is written to surface the specific failures this project hit, so a fresh
# environment fails loudly here rather than three commands into a demo.
#
# Read-only. It changes nothing. Exit is non-zero if any REQUIRED check failed;
# WARN checks (Bedrock access, Object Lock) do not fail the run, because the
# build has honest fallbacks for both and says so.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$ROOT/schema/lib/crsql.sh"
# shellcheck source=../schema/lib/creds.sh
source "$ROOT/schema/lib/creds.sh"

FAIL=0
ok()   { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; printf '        %s\n' "${2:-}"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; printf '        %s\n' "${2:-}"; FAIL=$((FAIL + 1)); }
grp()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
grp "tooling"

for t in jq aws python3 shasum base64; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t on PATH"; else bad "$t missing" "install $t"; fi
done

case "$(crsql_backend)" in
  native)    ok "cockroach binary on PATH" ;;
  container) ok "Apple container runtime (no native cockroach, no Docker)" ;;
  none)      bad "no way to reach the cluster" "need a cockroach binary or Apple's container runtime" ;;
esac

# ---------------------------------------------------------------------------
grp "cluster"

if [[ -z "${RF_CLUSTER_URL:-}" ]]; then
  bad "RF_CLUSTER_URL unset" "export the admin connection URL"
else
  if out="$(crsql_query "SELECT 1;" 2>&1)" && [[ "$out" == *1* ]]; then
    ok "cluster reachable"
    # The role assertion the whole thesis rests on: no managed role may be
    # superuser, bypass RLS, or belong to admin.
    # Tenant roles as well as rf_ ones, and admin MEMBERSHIP as well as the flags.
    # Checking only rf_% contradicted the point, because a privileged *tenant* is
    # the exact failure this project exists to prevent, and admin membership
    # grants bypass just as effectively as rolbypassrls does.
    #
    # Scoped to the roles this deployment manages, and no wider. A cluster-wide
    # sweep flags CockroachDB's own `admin` role and the human operator account
    # that RF_CLUSTER_URL connects as, both of which are supposed to be
    # privileged. Reporting those as failures would train whoever runs this to
    # ignore it. Tenants come from `canaries`, one row per seeded tenant, which is
    # the same ground truth the receipt's preflight uses.
    priv="$(crsql_query "SELECT coalesce(string_agg(rolname, ','), '') FROM pg_roles
      WHERE (rolname LIKE 'rf\_%' OR rolname IN (SELECT tenant FROM canaries))
        AND (rolsuper OR rolbypassrls OR pg_has_role(rolname, 'admin', 'MEMBER'));" \
      2>/dev/null | tail -n1)"
    if [[ -z "$priv" || "$priv" == "NULL" ]]; then
      ok "no managed role is superuser, bypasses RLS, or belongs to admin"
    else
      bad "privileged managed role(s): $priv" "REVOKE admin; the fence is off for those roles"
    fi
    # A hard failure, not a warning. Every other check can pass while the
    # boundary this whole project is about is switched off, and printing "ready"
    # in that state would be the single most misleading thing this script could do.
    rls="$(crsql_query "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='memories';" 2>/dev/null | tail -n1)"
    if [[ "$rls" == "t,t" ]]; then
      ok "memories has RLS enabled and forced"
    else
      bad "memories RLS state is '$rls', expected t,t" \
        "the isolation boundary is not active. Run schema/apply.sh policies"
    fi
  else
    bad "cluster unreachable" "$(tr '\n' '|' <<<"$out" | cut -c1-160)"
  fi
fi

# ---------------------------------------------------------------------------
grp "AWS identity and secrets"

if id="$(aws sts get-caller-identity --query Arn --output text 2>&1)"; then
  ok "AWS reachable as $id"
  case "$id" in
    *:root) warn "running as the account root" "a scoped IAM user is safer; see infra/README.md" ;;
  esac
else
  bad "AWS session unavailable" "$id"
fi

missing=""
for s in service/rf_auditor service/rf_remediation service/rf_harness \
         tenant/alice tenant/bob changefeed/s3-sink; do
  secret_field "$s" password >/dev/null 2>&1 || \
    aws secretsmanager describe-secret --region "$RF_AWS_REGION" \
      --secret-id "$RF_SECRETS_PREFIX/$s" >/dev/null 2>&1 || missing="$missing $s"
done
if [[ -z "$missing" ]]; then
  ok "expected secrets present in Secrets Manager"
else
  bad "missing secrets:$missing" "run infra/provision.sh or schema/apply.sh roles"
fi

# ---------------------------------------------------------------------------
grp "audit sink (S3)"

BKT=""
if json="$(aws secretsmanager get-secret-value --region "$RF_AWS_REGION" \
            --secret-id "$RF_SECRETS_PREFIX/changefeed/s3-sink" \
            --query SecretString --output text 2>/dev/null)"; then
  BKT="$(printf '%s' "$json" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("bucket",""))')"
fi
BKT="${RF_S3_BUCKET:-$BKT}"

if [[ -z "$BKT" ]]; then
  warn "no S3 bucket configured" "the changefeed is optional; set RF_S3_BUCKET or the sink secret"
elif ! aws s3api head-bucket --bucket "$BKT" >/dev/null 2>&1; then
  bad "bucket $BKT unreachable" "check the name and your credentials"
else
  ok "bucket $BKT reachable"
  if [[ "$(aws s3api get-bucket-versioning --bucket "$BKT" --query Status --output text 2>/dev/null)" == "Enabled" ]]; then
    ok "versioning enabled"
  else
    warn "versioning not enabled" "a deleted receipt object is unrecoverable without it"
  fi
  # Object Lock without a retention rule locks nothing, so the presence of a
  # configuration is not the same as protection and must not be reported as if
  # it were.
  if lock="$(aws s3api get-object-lock-configuration --bucket "$BKT" 2>/dev/null)"; then
    if printf '%s' "$lock" | grep -q '"Mode"'; then
      ok "Object Lock configured with a default retention rule"
    else
      warn "Object Lock enabled but no default retention rule" \
        "without a retention Mode and period, versions are not actually locked. Set one with infra/provision.sh."
    fi
  else
    warn "Object Lock not configured" \
      "AWS supports enabling it on an existing versioned bucket, so this is fixable in place. Tamper-evidence does not depend on it: it comes from the hash chain, not the bucket."
  fi
fi

# ---------------------------------------------------------------------------
grp "Models (optional, both paths have a fallback)"

# Two independent services, and they answer differently on this account, so they
# are checked separately. The embedding check invokes the embedding model rather
# than calling Converse on it: Converse against an embeddings model is rejected
# on its shape even where access is granted, so the old single check could never
# have reported ok.
if aws bedrock-runtime invoke-model --region "$RF_AWS_REGION" \
     --model-id amazon.titan-embed-text-v2:0 \
     --content-type application/json --accept application/json \
     --cli-binary-format raw-in-base64-out \
     --body '{"inputText":"x","dimensions":1024,"normalize":true}' \
     /dev/null >/dev/null 2>&1; then
  ok "classic Bedrock embeddings permitted (corpus can use Titan)"
else
  warn "classic Bedrock refuses the embedding model" \
    "account-level model access, not IAM (that would be AccessDeniedException). The console shows it as 0 TPM / 0 RPM on every model with quota increases unsupported. The corpus embeds with local-hash-v1 and every receipt records its model, so a fallback cannot masquerade as Titan. Note the mantle endpoint below does not help here: it publishes no embeddings route."
fi

# The agent's own resolution, so doctor reports the backend the agents will
# actually pick rather than a proxy for it.
# shellcheck source=../agent/lib/model.sh
source "$ROOT/agent/lib/model.sh"
case "$(model_backend)" in
  mantle)  ok "agent prose via bedrock-mantle ($(model_id))" ;;
  bedrock) ok "agent prose via classic Bedrock ($(model_id))" ;;
  *)       warn "no model backend reachable for agent prose" \
             "agents print facts verbatim as local-template-v1. For mantle, put a key in Secrets Manager as $RF_SECRETS_PREFIX/$RF_MANTLE_SECRET with field api_key, or export RF_MANTLE_API_KEY. Facts are unaffected either way: every number is computed in SQL." ;;
esac

# ---------------------------------------------------------------------------
printf '\n'
if [[ "$FAIL" -eq 0 ]]; then
  printf '\033[32mready.\033[0m Required checks passed. Warnings above are honest fallbacks, not blockers.\n'
else
  printf '\033[31m%d required check(s) failed.\033[0m Fix those before running the loop.\n' "$FAIL"
  exit 1
fi
