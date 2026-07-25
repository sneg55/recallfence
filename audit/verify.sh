#!/usr/bin/env bash
# RecallFence: verify the receipt hash chain.
#
#   ./audit/verify.sh                       # recompute the chain from the DB (rf_auditor)
#   ./audit/verify.sh --from-file f.ndjson  # from a changefeed export, no DB needed
#   ./audit/verify.sh --from-s3             # sync the S3 sink and verify the delivered objects
#   ./audit/verify.sh --head <hash>         # also assert the chain head equals an external anchor
#
# The point of the exercise: verification needs nothing but the receipts. It
# recomputes every link from the stored body and checks two things per receipt,
# the integrity of the link (does the stored hash match a fresh digest of the
# body) and the linkage (does this receipt's prev point at the previous receipt's
# hash). Tampering with any receipt breaks its own link and every later linkage,
# and no attacker with write access to the S3 bucket can repair that without the
# entire suffix. `--head` closes the last gap: pin the newest hash to something an
# attacker cannot reach (a value a judge wrote down, an Object-Locked manifest)
# and even a full-suffix rewrite is caught.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../schema/lib/crsql.sh
source "$HERE/../schema/lib/crsql.sh"
# shellcheck source=../schema/lib/creds.sh
source "$HERE/../schema/lib/creds.sh"
# shellcheck source=lib/hash.sh
source "$HERE/lib/hash.sh"
# shellcheck source=lib/sqlio.sh
source "$HERE/lib/sqlio.sh"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n=== %s\n' "$*"; }

SOURCE="db" FILE="" EXPECT_HEAD=""

# `shift 2` with only one positional left FAILS and shifts nothing, so a flag
# given without its operand would spin this loop forever on the same argument.
# A typo has to produce a usage error, not a hang.
need() { [[ $# -ge 2 ]] || die "$1 needs a value"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-file) need "$@"; SOURCE="file"; FILE="$2"; shift 2 ;;
    --from-s3)   SOURCE="s3"; shift ;;
    --head)      need "$@"; EXPECT_HEAD="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Normalize any source to a JSON array of {receipt_id, prev, hash, body}, ordered
# by emitted_at then receipt_id, deduplicated by receipt_id. A changefeed may
# redeliver a row on restart, so dedup is not optional.
normalize() {
  jq -s '
    map(.after // .)
    | map(select(.receipt_id != null))
    | map({receipt_id, prev: (.prev_receipt_hash // ""),
           hash: .receipt_hash, body: .receipt_json, emitted: .emitted_at,
           cols: {baseline_run, post_rls_run, post_quarantine_run, passed,
                  policy_sql, quarantined_ids}})
    | unique_by(.receipt_id)
    | sort_by(.emitted, .receipt_id)'
}

# The hash covers the body. It does not cover the columns beside it, and several
# of those columns restate facts the body already carries: the three run IDs and
# the verdict. Two copies where only one is authenticated is an invitation to
# edit the other, so the unauthenticated copy is checked against the authenticated
# one. A receipt whose `passed` column disagrees with its own body is not a
# receipt.
#
# Columns absent from the source (an older export) are skipped rather than failed,
# so this tightens verification without rejecting artifacts it predates.
cols_agree() {
  jq -r --argjson i "$1" '
    .[$i] as $r
    | [ ["baseline_run", $r.cols.baseline_run, $r.body.baseline_run],
        ["post_rls_run", $r.cols.post_rls_run, $r.body.post_rls_run],
        ["post_quarantine_run", $r.cols.post_quarantine_run, $r.body.post_quarantine_run],
        ["passed", $r.cols.passed, $r.body.passed] ]
      | map(select(.[1] != null and .[1] != .[2]) | .[0])
      | join(",")' <<<"$2"
}

load_db() {
  local url
  url="${RF_AUDITOR_URL:-$(url_for rf_auditor service)}"
  sql_b64 "$url" "(
      SELECT coalesce(jsonb_agg(jsonb_build_object(
               'receipt_id', receipt_id, 'prev_receipt_hash', prev_receipt_hash,
               'receipt_hash', receipt_hash, 'receipt_json', receipt_json,
               'emitted_at', emitted_at,
               'baseline_run', baseline_run, 'post_rls_run', post_rls_run,
               'post_quarantine_run', post_quarantine_run, 'passed', passed)),
             '[]'::JSONB)
        FROM receipts)" | jq -c '.[]' | normalize
}

load_file() {
  [[ -f "$FILE" ]] || die "no such file: $FILE"
  # Skip resolved-timestamp markers; keep only rows carrying a receipt.
  grep -v '"resolved"' "$FILE" | normalize
}

load_s3() {
  [[ -n "${RF_S3_BUCKET:-}" ]] || die "RF_S3_BUCKET is unset"
  local prefix="${RF_S3_PREFIX:-receipts}" dir
  dir="$(mktemp -d)"
  # To stderr: this function's stdout is captured as the chain JSON, so a progress
  # line on stdout becomes line 1 of the document and jq aborts on it.
  say "sync s3://$RF_S3_BUCKET/$prefix -> $dir" >&2
  aws s3 sync "s3://$RF_S3_BUCKET/$prefix" "$dir" --region "$RF_AWS_REGION" --quiet \
    || die "s3 sync failed"
  # Every delivered object concatenated: the chain spans objects, so verifying
  # only the newest would miss the predecessors it links back to.
  #
  # `awk 1` rather than `cat`, because the RESOLVED marker objects are written
  # without a trailing newline. Concatenating them with cat glues the closing
  # brace of one object to the opening brace of the next, and the whole stream
  # fails to parse as NDJSON. awk 1 prints each record with a newline, so the
  # boundary between objects is always a line boundary.
  find "$dir" -type f -print0 | xargs -0 awk 1 2>/dev/null | grep -v '"resolved"' | normalize
}

# Only the db source needs a database. Requiring a Cockroach client and
# RF_CLUSTER_URL to verify an S3 export defeated the point of offline sink
# verification: the whole claim is that the receipts verify on their own.
case "$SOURCE" in
  db)   crsql_require || exit 1; CHAIN="$(load_db)" ;;
  file) CHAIN="$(load_file)" ;;
  s3)   CHAIN="$(load_s3)" ;;
esac

N="$(jq 'length' <<<"$CHAIN")"
[[ "$N" -gt 0 ]] || die "no receipts to verify"
say "verifying $N receipt(s) from source: $SOURCE"

# Order by following the links, not by sorting on emitted_at.
#
# A chain is defined by its pointers, so reconstructing it from timestamps was
# wrong twice over. Two receipts can share a timestamp and then order by random
# UUID against the order they were actually written. And an audit sink is a
# prefix that accumulates: this bucket really does hold two unrelated chains,
# one from a spike using a "GENESIS" sentinel and one from this build, and
# sorting them together produced a single bogus chain that failed to verify for
# a reason that had nothing to do with tampering.
#
# A root is a receipt whose prev is empty, or whose prev names a hash that is not
# in this set (its predecessor lives elsewhere, or was truncated away).
roots() {
  jq -r '. as $all
    | (reduce .[] as $r ({}; .[$r.hash] = 1)) as $known
    | .[] | select(.prev == "" or ($known[.prev] // null) == null) | .hash' <<<"$CHAIN"
}
at_hash()   { jq -c --arg h "$1" 'map(select(.hash == $h)) | .[0]' <<<"$CHAIN"; }
succs_of()  { jq -r --arg h "$1" '.[] | select(.prev == $h) | .hash' <<<"$CHAIN"; }

# A hash is used as a node identity while walking, so two receipts sharing one
# would make the walk ambiguous: the lookup returns whichever came first and the
# other body is never inspected. Distinct receipts must have distinct hashes, and
# if they do not, that is itself the finding.
dupes="$(jq -r 'group_by(.hash) | map(select(length > 1)) | .[] | .[0].hash' <<<"$CHAIN")"
broken=0 seen=0 chains=0 head_hash="" anchored=0
if [[ -n "$dupes" ]]; then
  while IFS= read -r d; do
    [[ -n "$d" ]] && { printf '  DUPLICATE HASH shared by distinct receipts: %s\n' "${d:0:13}" >&2
                       broken=$((broken + 1)); }
  done <<<"$dupes"
fi

while IFS= read -r root; do
  [[ -n "$root" ]] || continue
  chains=$((chains + 1))
  printf '\n  chain %d\n' "$chains"
  printf '  %-4s %-14s %-8s %-14s %-8s %-8s %-8s\n' idx receipt passed hash link linkage columns

  cur="$root" idx=0
  while [[ -n "$cur" ]]; do
    r="$(at_hash "$cur")"
    rid="$(jq -r '.receipt_id' <<<"$r")"
    prev="$(jq -r '.prev' <<<"$r")"
    body="$(jq -c '.body' <<<"$r")"
    passed="$(jq -r '.body.passed' <<<"$r")"

    recomputed="$(printf '%s' "$body" | rf_link "$prev")"
    link=ok; [[ "$recomputed" == "$cur" ]] || { link=BROKEN; broken=$((broken + 1)); }

    # Reached by following prev pointers, so linkage holds by construction for
    # every step after the root. The root itself must genuinely be a genesis.
    #
    # A root whose prev names a hash absent from this source is an ORPHAN, and it
    # is a break, not a note. It was only printed before, which meant deleting a
    # receipt from the middle of a chain split it into two "valid" chains and
    # still verified clean even with --head, because the anchored head was
    # untouched. A missing predecessor is exactly what a deletion looks like.
    linkage=ok
    if [[ "$idx" -eq 0 && -n "$prev" ]]; then
      linkage="ORPHAN:${prev:0:8}"
      broken=$((broken + 1))
    fi

    # Each column is gated on its OWN presence, not on baseline_run's. Gating the
    # whole comparison behind one field meant nulling that field switched off
    # every other check, so a tamperer could null baseline_run and then rewrite
    # `passed` freely. quarantined_ids is compared as a sorted set; emitted_at is
    # deliberately not compared, because the DB and changefeed renderings differ
    # in precision and a format difference is not tampering.
    bad_cols="$(jq -r '
      [ ["baseline_run",        .cols.baseline_run,        .body.baseline_run],
        ["post_rls_run",        .cols.post_rls_run,        .body.post_rls_run],
        ["post_quarantine_run", .cols.post_quarantine_run, .body.post_quarantine_run],
        ["passed",              .cols.passed,              .body.passed],
        ["policy_sql",          .cols.policy_sql,          .body.policy_sql],
        ["quarantined_ids",
           (if .cols.quarantined_ids == null then null else (.cols.quarantined_ids | sort) end),
           ((.body.quarantine.ids // []) | sort)] ]
      | map(select(.[1] != null and .[1] != .[2]) | .[0]) | join(",")' <<<"$r")"
    columns=ok
    [[ -z "$bad_cols" ]] || { columns="BROKEN:$bad_cols"; broken=$((broken + 1)); }

    printf '  %-4s %-14s %-8s %-14s %-8s %-8s %-8s\n' \
      "$idx" "${rid:0:13}" "$passed" "${cur:0:13}" "$link" "$linkage" "$columns"

    seen=$((seen + 1)); idx=$((idx + 1)); head_hash="$cur"
    [[ -n "$EXPECT_HEAD" && "$cur" == "$EXPECT_HEAD" ]] && anchored="$chains"

    # More than one receipt claiming the same predecessor is a fork, which no
    # linear ordering can verify. Two concurrent emitters selecting the same
    # parent would produce exactly this.
    nsucc="$(succs_of "$cur" | grep -c . || true)"
    if [[ "$nsucc" -gt 1 ]]; then
      printf '  FORK: %s successors claim %s\n' "$nsucc" "${cur:0:13}" >&2
      broken=$((broken + 1)); break
    fi
    cur="$(succs_of "$cur" | head -n1)"
    [[ "$idx" -gt "$N" ]] && { printf '  CYCLE detected\n' >&2; broken=$((broken + 1)); break; }
  done
done < <(roots)

# Anything not reachable from a root is an orphan, and silently ignoring it would
# let a receipt be dropped from the middle of a chain without comment.
if [[ "$seen" -ne "$N" ]]; then
  printf '\nUNREACHABLE: %d of %d receipt(s) are not on any chain\n' "$((N - seen))" "$N" >&2
  broken=$((broken + 1))
fi

if [[ -n "$EXPECT_HEAD" ]]; then
  # The anchor has to match SOME chain's head, not merely the last one walked.
  # With several chains present the walk order is incidental, and checking only
  # the final head meant a forged chain could sit alongside the anchored one and
  # be reported verified because the legitimate chain happened to be walked last.
  if [[ "$anchored" != 0 ]]; then
    printf '\nhead matches anchor on chain %s: %s\n' "$anchored" "$EXPECT_HEAD"
    if [[ "$chains" -gt 1 ]]; then
      printf 'note: %d chains present. The anchor attests chain %s only; the others\n' "$chains" "$anchored"
      printf '      are internally consistent but unanchored, which is not the same thing.\n'
    fi
  else
    printf '\nHEAD MISMATCH: no chain in this source ends at %s\n' "$EXPECT_HEAD" >&2
    broken=$((broken + 1))
  fi
else
  printf '\nchain head: %s\n' "$head_hash"
fi

if [[ "$broken" -eq 0 ]]; then
  printf 'verified: %d receipt(s) across %d chain(s), no breaks.\n' "$seen" "$chains"
else
  printf 'chain FAILED: %d break(s).\n' "$broken" >&2
  exit 1
fi
