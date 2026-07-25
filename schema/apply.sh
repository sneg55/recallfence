#!/usr/bin/env bash
# RecallFence: schema and role provisioning.
#
#   ./schema/apply.sh tables                    tables, indexes
#   ./schema/apply.sh roles alice bob carol     service roles + tenant roles, asserted
#   ./schema/apply.sh assert alice bob          re-run the non-privileged assertion alone
#   ./schema/apply.sh policies                  policy set, then RLS on
#   ./schema/apply.sh rls off|on                negative-control toggle
#   ./schema/apply.sh changefeed                receipts -> S3
#   ./schema/apply.sh verify                    role flags, policy set, RLS state
#   ./schema/apply.sh teardown                  drop everything this created
#
# There is deliberately no single command that runs tables, roles and policies in
# one go. The fixture loader belongs between `roles` and `policies`: under FORCE
# ROW LEVEL SECURITY an operation with no applicable policy is denied for every
# role including the table owner, so seeding after the fence is up would need a
# policy that exists only to let the seeder cheat.
#
# Environment:
#   RF_CLUSTER_URL     required. Admin connection URL for the cluster.
#   RF_SECRETS_PREFIX  default "recallfence". Secrets Manager path prefix.
#   RF_AWS_REGION      default "us-east-2".
#   RF_SKIP_SECRETS    set to 1 to print passwords instead of storing them.
#   RF_S3_BUCKET       required for `changefeed`.
#   RF_S3_PREFIX       default "receipts".

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/crsql.sh
source "$HERE/lib/crsql.sh"
# Owns the RF_SECRETS_PREFIX and RF_AWS_REGION defaults, which used to be set
# here and in the test harness both.
# shellcheck source=lib/creds.sh
source "$HERE/lib/creds.sh"

RF_S3_PREFIX="${RF_S3_PREFIX:-receipts}"

SERVICE_ROLES=(rf_auditor rf_remediation rf_harness rf_agent)

say()  { printf '\n=== %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# Alphanumeric only. The password ends up inside a postgresql:// URL and inside a
# single-quoted SQL literal, and every class of quoting bug this avoids would
# show up as an authentication failure hours later rather than a syntax error now.
# `head -c` on /dev/urandom rather than piping an unbounded stream into it: with
# `set -o pipefail`, closing the pipe on an infinite producer makes the whole
# pipeline exit 141 (SIGPIPE) and takes the script down with it. Bounded read at
# the head, filters that consume everything after it.
genpw() { head -c 1024 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-32; }

# store_secret <path-suffix> <json>
# Passwords go straight from /dev/urandom into Secrets Manager without ever being
# echoed or written to a file. This is why role creation lives here rather than
# split across schema/ and infra/: anywhere else and the password would have to
# survive a hop.
store_secret() {
  local payload="$2" name="$RF_SECRETS_PREFIX/$1"
  if [[ "${RF_SKIP_SECRETS:-0}" == 1 ]]; then
    printf '  (RF_SKIP_SECRETS=1) would store %s\n' "$name"
    printf '  %s\n' "$payload"
    return 0
  fi
  if aws secretsmanager describe-secret --region "$RF_AWS_REGION" \
       --secret-id "$name" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value --region "$RF_AWS_REGION" \
      --secret-id "$name" --secret-string "$payload" >/dev/null
    printf '  rotated  %s\n' "$name"
  else
    aws secretsmanager create-secret --region "$RF_AWS_REGION" \
      --name "$name" --secret-string "$payload" >/dev/null
    printf '  created  %s\n' "$name"
  fi
}

# Pull host/port/database out of the admin URL so the per-role secrets are
# complete connection descriptors, which is what the harness and the agent
# runtime fetch. They never see the admin URL itself.
url_field() {
  RF_URL="$RF_CLUSTER_URL" python3 - "$1" <<'PY'
import os, sys
from urllib.parse import urlparse
u = urlparse(os.environ["RF_URL"])
print({"host": u.hostname or "", "port": str(u.port or 26257),
       "database": (u.path or "/").lstrip("/") or "defaultdb"}[sys.argv[1]])
PY
}

secret_json() {
  RF_U="$1" RF_P="$2" RF_H="$3" RF_PORT="$4" RF_DB="$5" python3 - <<'PY'
import json, os
print(json.dumps({k: os.environ[v] for k, v in {
    "user": "RF_U", "password": "RF_P", "host": "RF_H",
    "port": "RF_PORT", "database": "RF_DB"}.items()}))
PY
}

# ---------------------------------------------------------------------------

cmd_tables() {
  say "tables"
  crsql_file "$HERE/001_tables.sql"
}

cmd_roles() {
  [[ $# -ge 1 ]] || die "usage: apply.sh roles <tenant> [<tenant>...]"
  local tenants=("$@")

  local host port db
  host="$(url_field host)"; port="$(url_field port)"; db="$(url_field database)"

  say "service roles"
  local apw rpw hpw gpw
  apw="$(genpw)"; rpw="$(genpw)"; hpw="$(genpw)"; gpw="$(genpw)"
  crsql_render "$HERE/002_service_roles.sql.tmpl" \
    AUDITOR_PW "$apw" REMEDIATION_PW "$rpw" HARNESS_PW "$hpw" AGENT_PW "$gpw" | crsql_stdin
  store_secret "service/rf_auditor"     "$(secret_json rf_auditor     "$apw" "$host" "$port" "$db")"
  store_secret "service/rf_remediation" "$(secret_json rf_remediation "$rpw" "$host" "$port" "$db")"
  store_secret "service/rf_harness"     "$(secret_json rf_harness     "$hpw" "$host" "$port" "$db")"
  store_secret "service/rf_agent"       "$(secret_json rf_agent       "$gpw" "$host" "$port" "$db")"
  unset apw rpw hpw gpw

  local t tpw
  for t in "${tenants[@]}"; do
    say "tenant role: $t"
    [[ "$t" =~ ^[a-z][a-z0-9_]{0,62}$ ]] || die "tenant name '$t' must be lowercase [a-z][a-z0-9_]*"
    [[ "$t" == rf_* ]] && die "tenant name '$t' collides with the rf_ service-role prefix"
    tpw="$(genpw)"
    crsql_render "$HERE/003_tenant_role.sql.tmpl" TENANT "$t" TENANT_PW "$tpw" | crsql_stdin
    store_secret "tenant/$t" "$(secret_json "$t" "$tpw" "$host" "$port" "$db")"
    unset tpw
  done

  assert_roles "${SERVICE_ROLES[@]}" "${tenants[@]}"
}

# The gate. Nothing downstream may run until every managed role comes back
# non-privileged, because a privileged role makes the entire proof vacuous and
# reports no error while doing it.
assert_roles() {
  local roles=("$@") list="" r out bad expected
  for r in "${roles[@]}"; do list+="${list:+, }'$r'"; done
  expected="${#roles[@]}"

  say "asserting ${expected} managed roles are non-privileged"
  out="$(crsql_render "$HERE/005_assert_roles.sql.tmpl" ROLE_LIST "$list" \
         | crsql_stdin --format=csv)"
  printf '%s\n' "$out"

  local seen
  seen="$(printf '%s\n' "$out" | tail -n +2 | grep -c . || true)"
  if [[ "$seen" -ne "$expected" ]]; then
    die "expected $expected managed roles, found $seen. A role failed to create; refusing to continue."
  fi

  bad="$(printf '%s\n' "$out" | grep -E ',FAIL_[A-Z_]+$' || true)"
  if [[ -n "$bad" ]]; then
    printf '\n' >&2
    printf '%s\n' "$bad" >&2
    die "one or more managed roles can bypass row-level security. Refusing to continue.
       A superuser, a member of admin, or a role with rolbypassrls reads every
       tenant's rows and reports no error. Fix with:  REVOKE admin FROM <role>;"
  fi
  printf '  all %s roles clean\n' "$expected"
}

cmd_policies() {
  say "policy set, then RLS on"
  crsql_file "$HERE/004_policies.sql"
}

cmd_rls() {
  case "${1:-}" in
    off) say "RLS off (negative control)"; crsql_file "$HERE/010_rls_off.sql" ;;
    on)  say "RLS on";                     crsql_file "$HERE/011_rls_on.sql"  ;;
    *)   die "usage: apply.sh rls off|on" ;;
  esac
}

cmd_changefeed() {
  # The sink secret carries its own bucket, prefix and region, so the whole sink
  # is described in one place. RF_S3_BUCKET and RF_S3_PREFIX still override, for
  # pointing a run at a different bucket without rewriting the secret.
  #
  # Field names are read exactly as the secret stores them. This read them as
  # AWS_ACCESS_KEY_ID and the secret spells it aws_access_key_id, so the whole
  # subcommand died on a KeyError the first time it was run against the real
  # sink. Latent since the spike created the secret, because nothing had called
  # it since.
  local sink akid secret bucket prefix json
  json="$(aws secretsmanager get-secret-value --region "$RF_AWS_REGION" \
            --secret-id "$RF_SECRETS_PREFIX/changefeed/s3-sink" \
            --query SecretString --output text)" \
    || die "cannot read $RF_SECRETS_PREFIX/changefeed/s3-sink"

  akid="$(printf '%s' "$json"   | python3 -c 'import json,sys;print(json.load(sys.stdin)["aws_access_key_id"])')"
  secret="$(printf '%s' "$json" | python3 -c 'import json,sys,urllib.parse;print(urllib.parse.quote(json.load(sys.stdin)["aws_secret_access_key"], safe=""))')"
  bucket="${RF_S3_BUCKET:-$(printf '%s' "$json" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("bucket",""))')}"
  prefix="${RF_S3_PREFIX:-$(printf '%s' "$json" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("prefix","receipts"))')}"
  [[ -n "$bucket" ]] || die "no bucket in the sink secret and RF_S3_BUCKET is unset"

  say "changefeed: receipts -> s3://$bucket/$prefix"

  # Spike 4: implicit credentials are refused outright on Cloud
  # ("implicit credentials disallowed for s3"), so the key must be in the URI.
  # It comes from Secrets Manager and is never written to disk or echoed.
  sink="s3://$bucket/$prefix?AWS_ACCESS_KEY_ID=$akid&AWS_SECRET_ACCESS_KEY=$secret&AWS_REGION=$RF_AWS_REGION"

  crsql_render "$HERE/006_changefeed.sql.tmpl" SINK_URI "$sink" | crsql_stdin
  unset sink secret json
}

cmd_verify() {
  say "RLS state on memories"
  crsql_query "SELECT relname, relrowsecurity AS rls_enabled, relforcerowsecurity AS rls_forced
               FROM pg_class WHERE relname IN ('memories','quarantined_memories');"
  say "policy set"
  crsql_query "SELECT polname, polcmd, polroles::STRING AS roles, pg_get_expr(polqual, polrelid) AS using_expr,
                      pg_get_expr(polwithcheck, polrelid) AS with_check_expr
               FROM pg_policy ORDER BY polname;"
  say "grants on the six evidence tables (no tenant role may appear here)"
  crsql_query "SELECT grantee, table_name, privilege_type
               FROM information_schema.table_privileges
               WHERE table_name IN ('canaries','probe_runs','probe_results','retrievals','quarantined_memories','receipts')
                 AND grantee NOT IN ('admin','root','public')
               ORDER BY grantee, table_name, privilege_type;"
  say "managed role flags"
  crsql_query "SELECT rolname, rolsuper, rolbypassrls, rolcanlogin,
                      pg_has_role(rolname,'admin','MEMBER') AS member_of_admin
               FROM pg_roles WHERE rolcanlogin ORDER BY rolname;"
}

cmd_teardown() {
  say "teardown"
  crsql_stdin <<'SQL'
DROP TABLE IF EXISTS receipts CASCADE;
DROP TABLE IF EXISTS probe_results CASCADE;
DROP TABLE IF EXISTS probe_runs CASCADE;
DROP TABLE IF EXISTS retrievals CASCADE;
DROP TABLE IF EXISTS canaries CASCADE;
DROP TABLE IF EXISTS quarantined_memories CASCADE;
DROP TABLE IF EXISTS memories CASCADE;
SQL
  printf '\nRoles are left in place on purpose. Dropping a SQL role that still owns\n'
  printf 'objects fails halfway and leaves the cluster in a worse state than it\n'
  printf 'started. Drop them explicitly once the tables are gone.\n'
}

crsql_require

case "${1:-}" in
  tables)     shift; cmd_tables "$@" ;;
  roles)      shift; cmd_roles "$@" ;;
  assert)     shift; [[ $# -ge 1 ]] || die "usage: apply.sh assert <role> [<role>...]"
              assert_roles "${SERVICE_ROLES[@]}" "$@" ;;
  policies)   shift; cmd_policies "$@" ;;
  rls)        shift; cmd_rls "$@" ;;
  changefeed) shift; cmd_changefeed "$@" ;;
  verify)     shift; cmd_verify "$@" ;;
  teardown)   shift; cmd_teardown "$@" ;;
  *)          sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
