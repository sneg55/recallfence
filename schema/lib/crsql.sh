#!/usr/bin/env bash
# RecallFence: resolve a way to run SQL against the cluster.
#
# Sourced by apply.sh. Defines crsql_stdin, crsql_query and crsql_file.
#
# Prefers a native `cockroach` binary. Falls back to Apple's `container` runtime,
# which is how this project was developed: no native binary on the machine and no
# Docker daemon. The fallback needs an explicit --dns, because containers on that
# runtime do not inherit the host resolver and the failure mode is a misleading
# "cannot dial server" timeout against a host the machine can reach fine.
#
# Everything goes in over stdin rather than --file or --execute, for two reasons.
# Rendered templates carry generated passwords and a live S3 secret key, so they
# must never touch disk. And `--file` halts the whole batch on the first error,
# which is wrong for the statements we expect to fail.

# No `set -e` here, on purpose. This file is sourced, so shell options it sets
# leak into the caller. tests/test_policies.sh runs statements that are SUPPOSED
# to fail, and inheriting errexit from a library killed the suite on its first
# expected permission denial. Callers choose their own options.

RF_COCKROACH_IMAGE="${RF_COCKROACH_IMAGE:-cockroachdb/cockroach:v26.2.0}"
RF_CONTAINER_DNS="${RF_CONTAINER_DNS:-1.1.1.1}"
RF_CERT_DIR="${RF_CERT_DIR:-$HOME/.postgresql}"

crsql_backend() {
  if command -v cockroach >/dev/null 2>&1; then
    echo native
  elif command -v container >/dev/null 2>&1; then
    echo container
  else
    echo none
  fi
}

crsql_require() {
  local backend
  backend="$(crsql_backend)"
  if [[ "$backend" == none ]]; then
    echo "error: need either a \`cockroach\` binary on PATH or Apple's \`container\` runtime." >&2
    echo "       https://www.cockroachlabs.com/docs/stable/install-cockroachdb" >&2
    return 1
  fi
  if [[ -z "${RF_CLUSTER_URL:-}" ]]; then
    echo "error: RF_CLUSTER_URL is unset. It must be an admin connection URL for the cluster." >&2
    return 1
  fi
}

# The container backend cannot see the host's CA cert at the host's path, so the
# cert directory is bind-mounted at /certs and the URL is rewritten to match.
# Doing this here, rather than asking the operator to keep two URLs around,
# removes a class of confusing TLS failures.
crsql_url() {
  local url="${RF_SQL_URL:-$RF_CLUSTER_URL}"
  if [[ "$(crsql_backend)" == container ]]; then
    url="$(printf '%s' "$url" | sed -E 's#sslrootcert=[^&]*#sslrootcert=/certs/root.crt#')"
  fi
  printf '%s' "$url"
}

# crsql_stdin [extra cockroach sql flags...] < statements.sql
# Reads SQL from stdin. Never writes it anywhere.
crsql_stdin() {
  local url
  url="$(crsql_url)"
  case "$(crsql_backend)" in
    native)
      cockroach sql --url "$url" "$@"
      ;;
    container)
      # --volume mounts the CA cert the URL's sslrootcert path points at; the
      # rendered URL uses /certs/root.crt inside the container.
      #
      # The runtime's "[4/6] Fetching kernel" progress lines go to stderr, so
      # they are filtered there rather than by piping the whole invocation
      # through grep. That matters: a filter pipeline would make grep's exit
      # status the function's, and a failed statement would return 0 while the
      # error text scrolled past. Callers here branch on exit status to tell an
      # expected permission denial from a broken query.
      container run --rm --interactive \
        --dns "$RF_CONTAINER_DNS" \
        --volume "$RF_CERT_DIR:/certs" \
        --entrypoint /cockroach/cockroach \
        "$RF_COCKROACH_IMAGE" \
        sql --url "$url" "$@" \
        2> >(grep -v '^\[[0-9]/[0-9]\] ' >&2)
      ;;
  esac
}

# crsql_query "SELECT ..." -> CSV on stdout, header included
crsql_query() {
  printf '%s\n' "$1" | crsql_stdin --format=csv
}

# crsql_file path/to.sql [extra flags...]
crsql_file() {
  local f="$1"; shift
  crsql_stdin "$@" < "$f"
}

# crsql_render path/to.sql.tmpl VAR VALUE [VAR VALUE...] -> rendered SQL on stdout
# Substitution is literal, on @@VAR@@. Values containing & or / are safe because
# this uses bash string replacement rather than sed.
crsql_render() {
  local tmpl="$1"; shift
  local body
  body="$(cat "$tmpl")"
  while [[ $# -gt 0 ]]; do
    body="${body//@@$1@@/$2}"
    shift 2
  done
  printf '%s\n' "$body"
}
