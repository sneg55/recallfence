#!/usr/bin/env bash
# RecallFence: values crossing the bash/SQL boundary.
#
# Sourced by receipt.sh and verify.sh. Extracted once the verifier needed the
# same base64 read-back the writer already had: a JSON blob returned through CSV
# framing is a quoting bug waiting to happen, and having that logic written twice
# means fixing it twice.
#
# No `set -e`. This file is sourced and options leak into the caller.

# SQL string literal, apostrophes doubled. For short controlled values: UUIDs,
# timestamps, hex digests.
#
# The quote character goes through a variable rather than a backslash escape.
# `${1//\'/\'\'}` looks equivalent and is not: on bash 3.2 it substitutes a
# literal \'\' and the statement dies at the backslash. That construct was in
# three files here, latent in two and live in the third the moment a receipt
# embedded policy SQL containing an apostrophe.
lit() { local q="'" s="$1"; s="${s//$q/$q$q}"; printf '%s%s%s' "$q" "$s" "$q"; }

# SQL text expression for arbitrary content, sent base64 and decoded in the
# database. Large, multi-line, quote-bearing values (policy SQL, a receipt body)
# take this path instead: nothing between here and the cluster should have an
# opinion about quoting.
sqltext() {
  printf "convert_from(decode('%s', 'base64'), 'UTF8')" \
    "$(printf '%s' "$1" | base64 | tr -d '\n')"
}

# CockroachDB renders booleans as t/f in CSV; JSON and SQL boolean literals both
# want true/false. One conversion, so a `t` never reaches jq --argjson or a VALUES
# list, where it is a silent "invalid JSON" or a syntax error rather than a bool.
jbool() {
  case "$1" in
    t) printf 'true' ;;
    f) printf 'false' ;;
    *) printf 'not a boolean: %q\n' "$1" >&2; return 1 ;;
  esac
}

# sql_b64 <url> <scalar sql expression> -> the decoded text
#
# Reads one text-valued expression back through base64, so newlines, commas and
# quotes inside a JSON blob never collide with CSV framing. The argument is an
# expression or a parenthesized single-row single-column subquery, and must carry
# no trailing semicolon: it is wrapped, not executed on its own.
sql_b64() {
  local url="$1" expr="$2" out
  out="$(run_as "$url" "SELECT encode(convert_to(($expr)::STRING, 'UTF8'), 'base64');")" \
    || { printf '%s' "$out" >&2; return 1; }
  printf '%s' "$out" | tail -n +2 | tr -d '\r\n" ' | base64 -d 2>/dev/null
}

# sql_scalar <url> <sql> -> the single value, trimmed, empty if no rows.
#
# The header is dropped first, deliberately. On an empty result CSV is one header
# line, so taking the last line returns the column name: that is how the receipt
# writer's genesis lookup first reported a predecessor hash of "coalesce".
sql_scalar() { run_as "$1" "$2" | tail -n +2 | tail -n1 | tr -d '[:space:]'; }
