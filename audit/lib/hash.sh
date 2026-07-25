#!/usr/bin/env bash
# RecallFence: the chain link.
#
# Sourced by receipt.sh and verify.sh. One definition of "canonical form" and one
# definition of "the digest", used by both the writer and the verifier, because a
# chain whose two halves serialize differently is a chain that fails to verify a
# receipt nobody tampered with.
#
# The property this buys: `receipt_hash` digests the canonical receipt body plus
# the predecessor's hash, so altering any earlier receipt breaks every later one,
# and verification needs nothing but the receipts themselves. That survives an
# attacker with full write access to the S3 sink. The bucket is not what makes the
# record tamper-evident; this file is.
#
# No `set -e`. This file is sourced and options leak into the caller.

# Canonical form: sorted object keys, compact, one line, no insignificant
# whitespace. Read on stdin, written on stdout.
#
# Load-bearing that this is applied on BOTH write and verify. The body is stored
# as JSONB, and CockroachDB is free to reorder object keys and renormalize
# whitespace on the way in and out. Re-canonicalizing on read makes the digest a
# function of the JSON's *content*, not of a byte layout the database never
# promised to preserve. Arrays are left in place, so any array whose order
# matters (the matrix, the quarantined IDs) must already be sorted by its builder.
rf_canon() { jq -S -c '.'; }

# Lowercase hex SHA-256 of stdin. shasum ships on macOS; sha256sum on most Linux.
rf_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | cut -d' ' -f1
  else
    sha256sum | cut -d' ' -f1
  fi
}

# rf_link <prev_hash> < body.json  -> receipt_hash (hex) on stdout
#
# The canonical body and the predecessor hash are joined with a newline before
# digesting. The separator is not decoration: without a delimiter, a body ending
# in "…abc" chained onto prev "def" and a body ending "…ab" onto prev "cdef" would
# digest identically. A byte that cannot appear inside compact JSON removes that
# ambiguity. Genesis passes an empty prev, so the genesis digest is over
# "<body>\n".
rf_link() {
  local prev="${1:-}" body
  body="$(rf_canon)"
  printf '%s\n%s' "$body" "$prev" | rf_sha256
}
