#!/usr/bin/env bash
# RecallFence: reach the cluster as a named role.
#
# Sourced by schema/apply.sh, tests/lib/assert.sh and harness/. Extracted from
# the test harness once a second caller appeared: the tests and the probe runner
# have to build connections the same way, or a probe and the test that is
# supposed to guard it would be exercising different things.
#
# Connections are built by swapping the userinfo on the admin URL, keeping host,
# port, database and every TLS parameter identical. The role is the only thing
# that differs between them, which is what makes comparisons across roles mean
# anything.
#
# This file owns the RF_SECRETS_PREFIX and RF_AWS_REGION defaults. They used to
# be set in two places, and a default in two places will eventually disagree
# with itself.
#
# No `set -e`. This file is sourced and options leak into the caller.

RF_SECRETS_PREFIX="${RF_SECRETS_PREFIX:-recallfence}"
RF_AWS_REGION="${RF_AWS_REGION:-us-east-2}"

# secret_field <path-suffix> <json field>
secret_field() {
  aws secretsmanager get-secret-value --region "$RF_AWS_REGION" \
    --secret-id "$RF_SECRETS_PREFIX/$1" --query SecretString --output text \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['$2'])"
}

# role_url <user> <password> -> the admin URL with the userinfo swapped.
# Percent-encoding matters: generated passwords are alphanumeric today, but a
# URL builder that only works for alphanumerics is a trap for whoever changes
# genpw later.
role_url() {
  RF_URL="$RF_CLUSTER_URL" RF_U="$1" RF_P="$2" python3 - <<'PY'
import os
from urllib.parse import urlparse, quote
u = urlparse(os.environ["RF_URL"])
netloc = "%s:%s@%s:%d" % (quote(os.environ["RF_U"], safe=""),
                          quote(os.environ["RF_P"], safe=""),
                          u.hostname, u.port or 26257)
print(u._replace(netloc=netloc).geturl())
PY
}

# url_for <role> <tenant|service>
url_for() { role_url "$1" "$(secret_field "$2/$1" password)"; }

# run_as <url> <sql> -> combined output on stdout, exit status preserved.
# Status matters as much as output: it is what separates an expected permission
# denial from a query that was simply written wrong.
run_as() {
  local out status
  out="$(RF_SQL_URL="$1" crsql_stdin --format=csv <<<"$2" 2>&1)"
  status=$?
  printf '%s' "$out"
  return $status
}
