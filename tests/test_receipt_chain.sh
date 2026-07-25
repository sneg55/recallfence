#!/usr/bin/env bash
# RecallFence: does the receipt chain actually detect tampering?
#
#   ./tests/test_receipt_chain.sh
#
# Needs no cluster and no credentials. It builds a synthetic three-receipt chain
# with the same rf_link the receipt writer uses, shapes it exactly like a
# changefeed export, and drives the real verifier over it.
#
# This file exists because "tamper-evident" is the project's strongest claim and
# the easiest one to ship untested. A chain that is never handed a tampered
# receipt is indistinguishable from a chain that always prints "verified", which
# is the same defect as a test that asserts only "it errored".
#
# The case that matters is TAMPER B. An attacker who edits a receipt and then
# recomputes its hash defeats any per-record checksum. Only the linkage catches
# it, and only because the next receipt committed to the old hash.

set -uo pipefail  # not -e: most cases here expect a non-zero exit

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../audit/lib/hash.sh
source "$HERE/../audit/lib/hash.sh"
# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"

VERIFY="$HERE/../audit/verify.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Assertions, in terms of what the verifier concluded.
# ---------------------------------------------------------------------------

# expect_chain_ok <label> <file> [extra verify args...]
expect_chain_ok() {
  local label="$1" file="$2"; shift 2
  local out status=0
  out="$("$VERIFY" --from-file "$file" "$@" 2>&1)" || status=$?
  if [[ "$status" -eq 0 && "$out" == *"no breaks"* ]]; then
    pass "$label"
  else
    fail "$label" "expected a clean chain, got: $(tr '\n' '|' <<<"$out")"
  fi
}

# expect_chain_broken <label> <file> <what must be reported> [extra args...]
# Matches the reason, not just the failure. A truncated chain and a rewritten
# body both exit non-zero, and a test that cannot tell them apart is not testing
# tamper detection, only that something went wrong.
expect_chain_broken() {
  local label="$1" file="$2" want="$3"; shift 3
  local out status=0
  out="$("$VERIFY" --from-file "$file" "$@" 2>&1)" || status=$?
  if [[ "$status" -eq 0 ]]; then
    fail "$label" "chain VERIFIED but should have been rejected: $(tr '\n' '|' <<<"$out")"
  elif [[ "$out" != *"$want"* ]]; then
    fail "$label" "rejected, but not for the stated reason. Wanted '$want', got: $(tr '\n' '|' <<<"$out")"
  else
    pass "$label"
  fi
}

# ---------------------------------------------------------------------------
# A synthetic chain, shaped like a changefeed export (envelope = wrapped).
# ---------------------------------------------------------------------------

# body <seq> -> a receipt body on stdout
body() {
  jq -c -n --argjson seq "$1" \
    '{version: "rf-receipt-1", emitted_at: ("2026-01-0" + ($seq + 1 | tostring) + "T00:00:00Z"),
      seq: $seq, passed: true, note: "synthetic",
      baseline_run: "00000000-0000-0000-0000-0000000000b1",
      post_rls_run: "00000000-0000-0000-0000-0000000000r1",
      post_quarantine_run: "00000000-0000-0000-0000-0000000000q1"}'
}

# line <receipt_id> <prev|null> <hash> <body> -> one NDJSON changefeed row
#
# The outer columns mirror the body, exactly as the writer stores them. They are
# NOT covered by the hash, which is the whole reason the verifier cross-checks
# them and the reason TAMPER D below exists.
line() {
  jq -c -n --arg id "$1" --arg prev "$2" --arg hash "$3" --argjson body "$4" \
    '{after: {receipt_id: $id, prev_receipt_hash: (if $prev == "" then null else $prev end),
              receipt_hash: $hash, receipt_json: $body, emitted_at: $body.emitted_at,
              baseline_run: $body.baseline_run, post_rls_run: $body.post_rls_run,
              post_quarantine_run: $body.post_quarantine_run, passed: $body.passed}}'
}

CHAIN="$WORK/chain.ndjson"; : >"$CHAIN"
HASHES=() BODIES=()
prev=""
for seq in 0 1 2; do
  b="$(body "$seq")"
  h="$(printf '%s' "$b" | rf_link "$prev")"
  line "0000000$seq-0000-0000-0000-00000000000$seq" "$prev" "$h" "$b" >>"$CHAIN"
  HASHES+=("$h"); BODIES+=("$b")
  prev="$h"
done
HEAD="${HASHES[2]}"

group "a chain nobody touched"
expect_chain_ok "three linked receipts verify" "$CHAIN"
expect_chain_ok "head matches the external anchor" "$CHAIN" --head "$HEAD"

group "canonicalization: the digest is over content, not bytes"
# Same content, different key order and whitespace. JSONB is free to do exactly
# this to a stored body, so if the digest were byte-sensitive the chain would
# break on receipts nobody touched.
jq -c '.after.receipt_json |= (to_entries | sort_by(.key) | reverse | from_entries)' \
  "$CHAIN" >"$WORK/reordered.ndjson"
expect_chain_ok "reordered keys still verify" "$WORK/reordered.ndjson"

group "changefeed redelivery"
# A feed that restarts can emit a row twice. Dedup is not a nicety: without it the
# duplicate looks like a second receipt whose prev points at its own predecessor.
{ cat "$CHAIN"; head -n 2 "$CHAIN"; } >"$WORK/dupes.ndjson"
expect_chain_ok "duplicate rows are deduplicated" "$WORK/dupes.ndjson"
# Resolved-timestamp markers are interleaved with rows in a real export.
{ cat "$CHAIN"; echo '{"resolved":"1750000000.0000000000"}'; } >"$WORK/resolved.ndjson"
expect_chain_ok "resolved markers are skipped" "$WORK/resolved.ndjson"

group "TAMPER A: a body is edited, hashes left alone"
jq -c 'if .after.receipt_json.seq == 0 then .after.receipt_json.passed = false else . end' \
  "$CHAIN" >"$WORK/tamper_a.ndjson"
expect_chain_broken "edited body breaks its own link" "$WORK/tamper_a.ndjson" "BROKEN"

group "TAMPER B: a body is edited AND its hash recomputed"
# The attack a per-record checksum cannot survive. The forged receipt is
# internally consistent; what convicts it is that receipt 1 committed to the hash
# the original had.
forged_body="$(jq -c '.passed = false' <<<"${BODIES[0]}")"
forged_hash="$(printf '%s' "$forged_body" | rf_link "")"
jq -c --argjson fb "$forged_body" --arg fh "$forged_hash" \
  'if .after.receipt_json.seq == 0
     then .after.receipt_json = $fb | .after.receipt_hash = $fh
     else . end' "$CHAIN" >"$WORK/tamper_b.ndjson"
expect_chain_broken "consistent forgery still breaks the next linkage" \
  "$WORK/tamper_b.ndjson" "BROKEN"

group "TAMPER D: the columns beside the body are edited, body untouched"
# The hash covers the body, not the columns next to it, and several of those
# columns restate what the body already says. Flipping the verdict column while
# leaving the body and its hash alone produces a receipt that verifies as a valid
# link and reports the opposite result to anything reading the columns: SQL
# queries, the changefeed consumer, a dashboard.
jq -c 'if .after.receipt_json.seq == 1 then .after.passed = false else . end' \
  "$CHAIN" >"$WORK/tamper_d.ndjson"
expect_chain_broken "a flipped verdict column is caught by the body" \
  "$WORK/tamper_d.ndjson" "BROKEN:passed"

jq -c 'if .after.receipt_json.seq == 1
         then .after.post_rls_run = "00000000-0000-0000-0000-00000000dead" else . end' \
  "$CHAIN" >"$WORK/tamper_d2.ndjson"
expect_chain_broken "a repointed run ID column is caught by the body" \
  "$WORK/tamper_d2.ndjson" "BROKEN:post_rls_run"

group "TAMPER C: the suffix is rewritten wholesale"
# If the attacker rewrites every receipt from the forgery forward, the chain is
# internally consistent again and only an external anchor catches it. This is why
# `--head` exists and why the head belongs somewhere the attacker cannot reach.
prev="" ; : >"$WORK/tamper_c.ndjson"
for seq in 0 1 2; do
  b="$(body "$seq")"
  [[ "$seq" == 0 ]] && b="$(jq -c '.passed = false' <<<"$b")"
  h="$(printf '%s' "$b" | rf_link "$prev")"
  line "0000000$seq-0000-0000-0000-00000000000$seq" "$prev" "$h" "$b" >>"$WORK/tamper_c.ndjson"
  prev="$h"
done
expect_chain_ok "a fully rewritten chain is self-consistent" "$WORK/tamper_c.ndjson"
expect_chain_broken "but the anchored head convicts it" \
  "$WORK/tamper_c.ndjson" "HEAD MISMATCH" --head "$HEAD"

group "two independent chains sharing one export prefix"
# An audit sink is a prefix that accumulates. This bucket really did end up with
# a spike's chain and this build's chain side by side, and ordering by timestamp
# merged them into one bogus chain that failed to verify for a reason unrelated
# to tampering. Following the links instead keeps them separate.
{
  cat "$CHAIN"
  p2=""
  for seq in 0 1; do
    b="$(jq -c '.note = "other-chain"' <<<"$(body "$seq")")"
    h="$(printf '%s' "$b" | rf_link "$p2")"
    line "aaaaaaa$seq-0000-0000-0000-00000000000$seq" "$p2" "$h" "$b"
    p2="$h"
  done
} >"$WORK/two_chains.ndjson"
expect_chain_ok "both chains verify, neither contaminates the other" "$WORK/two_chains.ndjson"

group "a receipt deleted from the middle of a chain"
# This verified clean before, even with --head. Following links split the
# survivors into two internally valid chains and the anchored head was
# untouched, so nothing objected. A root whose prev names an absent hash is a
# missing predecessor, which is exactly what a deletion leaves behind.
grep -v '"receipt_id":"00000001-0000-0000-0000-000000000001"' "$CHAIN" >"$WORK/hole.ndjson"
expect_chain_broken "an orphaned successor is reported" "$WORK/hole.ndjson" "ORPHAN"
expect_chain_broken "and it stays broken even when the anchor still matches" \
  "$WORK/hole.ndjson" "ORPHAN" --head "$HEAD"

group "two distinct receipts carrying the same hash"
# The walk uses a hash as node identity, so a collision makes it ambiguous: the
# lookup returns whichever came first and the other body is never inspected.
{
  cat "$CHAIN"
  jq -c --arg h "${HASHES[0]}" \
    '.after.receipt_id = "dddddddd-0000-0000-0000-00000000000d" | .after.receipt_hash = $h' \
    <(head -n 1 "$CHAIN")
} >"$WORK/dup_hash.ndjson"
expect_chain_broken "a duplicate hash is refused" "$WORK/dup_hash.ndjson" "DUPLICATE HASH"

group "a fork: two receipts claim the same predecessor"
{
  cat "$CHAIN"
  fb="$(jq -c '.note = "fork"' <<<"$(body 1)")"
  fh="$(printf '%s' "$fb" | rf_link "${HASHES[0]}")"
  line "ffffffff-0000-0000-0000-000000000001" "${HASHES[0]}" "$fh" "$fb"
} >"$WORK/fork.ndjson"
expect_chain_broken "a fork is refused, no linear order can verify it" \
  "$WORK/fork.ndjson" "FORK"

group "truncation"
head -n 2 "$CHAIN" >"$WORK/truncated.ndjson"
expect_chain_ok "a truncated chain verifies on its own" "$WORK/truncated.ndjson"
expect_chain_broken "but the anchored head catches the missing tail" \
  "$WORK/truncated.ndjson" "HEAD MISMATCH" --head "$HEAD"

summary
