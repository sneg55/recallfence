#!/usr/bin/env bash
# RecallFence: the policy generator and its approval gate.
#
#   ./repair/policy.sh propose            show the current set, the proposed set, the diff
#   ./repair/policy.sh apply --approve    apply it
#
# The generator emits the exact SQL for review and applies nothing without the
# operator saying so in the same command. `apply` on its own is refused, on
# purpose: a human-in-the-loop gate that can be satisfied by pressing return is
# not a gate.
#
# The proposed set is read from schema/004_policies.sql rather than assembled
# here. One source of truth: a generator that composed its own version of the
# policies could emit SQL the schema does not contain, which is the one thing an
# operator reviewing a security change must be able to rule out.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$HERE/../schema/lib/crsql.sh"

PROPOSED="$HERE/../schema/004_policies.sql"

say() { printf '\n=== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# The live set, read from the catalog rather than from a file, because what is
# installed is the only thing that matters when deciding what to change.
current_policies() {
  crsql_stdin --format=table <<'SQL'
SELECT p.polname AS policy, p.polcmd AS command,
       CASE p.polpermissive WHEN true THEN 'permissive' ELSE 'restrictive' END AS kind,
       coalesce(array_to_string(ARRAY(
         SELECT rolname FROM pg_roles WHERE oid = ANY (p.polroles)), ', '), 'PUBLIC') AS applies_to
  FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
 WHERE c.relname = 'memories' ORDER BY p.polname;
SQL
  crsql_stdin --format=table <<'SQL'
SELECT relname AS table, relrowsecurity AS rls_enabled, relforcerowsecurity AS rls_forced
  FROM pg_class WHERE relname = 'memories';
SQL
}

cmd_propose() {
  crsql_require
  say "currently installed on memories"
  current_policies

  say "proposed ($PROPOSED)"
  grep -vE '^\s*--|^\s*$' "$PROPOSED"

  say "what changes"
  # Compare policy names only. The bodies are in the file above verbatim, and a
  # textual diff of USING clauses against a catalog rendering would mostly show
  # formatting, which trains an operator to skim exactly the review that matters.
  local live want
  live="$(crsql_stdin --format=csv <<'SQL' | tail -n +2 | sort
SELECT p.polname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
 WHERE c.relname = 'memories';
SQL
)"
  want="$(grep -oE '^CREATE POLICY [a-z_]+' "$PROPOSED" | awk '{print $3}' | sort)"
  diff <(printf '%s\n' "$live") <(printf '%s\n' "$want") \
    && printf '  policy set already matches. Applying is a no-op re-run.\n' \
    || printf '  (< installed, > proposed)\n'

  printf '\nNothing has been changed. To apply:\n  %s apply --approve\n' "$0"
}

cmd_apply() {
  [[ "${1:-}" == "--approve" ]] || die \
"refusing to apply without --approve.

       This is the human-in-the-loop gate. Run
         $0 propose
       first, read the SQL, then
         $0 apply --approve"

  crsql_require
  say "applying $PROPOSED"
  crsql_file "$PROPOSED"

  say "installed"
  current_policies
}

case "${1:-}" in
  propose) cmd_propose ;;
  apply)   shift; cmd_apply "$@" ;;
  *)       sed -n '2,6p' "${BASH_SOURCE[0]}" >&2; exit 1 ;;
esac
