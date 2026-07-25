#!/usr/bin/env bash
# RecallFence: rendering the evidence bundle.
#
# Sourced by cli/rf. Every function here takes the bundle on stdin and prints one
# panel. Nothing in this file talks to a database, which is the property that lets
# the same code render a live cluster and a committed replay snapshot.
#
# Every jq program is assigned from a quoted heredoc at file scope rather than
# written as a multi-line single-quoted string inside a function body. That is not
# a style preference. Bash 3.2, which is what macOS ships and what this project
# runs on, mis-parses certain multi-line quoted programs in that position: the
# file passes `bash -n` and then fails to source with "unexpected EOF while
# looking for matching `''" pointing at the opening quote. A quoted heredoc is
# read literally and sidesteps the whole class, and it keeps the programs
# readable as jq rather than as escaped shell.
#
# No `set -e`. This file is sourced and options leak into the caller.

# Padding, and one definition of how a probe result is scored. Shared so the
# matrix, the summary and the evidence panel cannot disagree about what is a hit.
JQ_LIB=$(cat <<'JQ'
def pad($n): (. // "" | tostring) as $s
  | $s + (if $n > ($s | length) then " " * ($n - ($s | length)) else "" end);
def cell: if . == null then "-"
          elif .status != "ok" then "ERR"
          elif .breach then "HIT"
          else "ok" end;
JQ
)

JQ_STATUS=$(cat <<'JQ'
  "corpus        \(.corpus.rows) rows, \(.corpus.tenants | length) tenants, model \(.corpus.model)",
  "rls           enabled=\(.rls.enabled)  forced=\(.rls.forced)  policies=\(.rls.policies | length)",
  "policies      \(.rls.policies | join(", "))",
  "receipt       \(.receipt_meta.receipt_id) emitted \(.receipt_meta.emitted_at)",
  "verdict       passed=\(.receipt.passed)",
  "chain head    \(.receipt_meta.receipt_hash)",
  "runs          baseline=\(.receipt.baseline_run)",
  "              post_rls=\(.receipt.post_rls_run)",
  "              post_quarantine=\(.receipt.post_quarantine_run)"
JQ
)

# The panel the whole project is about: principal by probe, across phases, with
# the side_channel row shown alongside the semantic and direct-ID ones.
JQ_MATRIX=$(cat <<'JQ'
  (.evidence | group_by(.principal + " " + .probe_type)
    | map({
        principal: .[0].principal, probe_type: .[0].probe_type,
        baseline:        (map(select(.phase == "baseline"))        | first),
        post_rls:        (map(select(.phase == "post_rls"))        | first),
        post_quarantine: (map(select(.phase == "post_quarantine")) | first)
      })) as $rows
  | ("  " + ("principal" | pad(11)) + ("probe" | pad(21))
          + ("baseline" | pad(10)) + ("post_rls" | pad(10)) + "post_quarantine"),
    ("  " + ("-" * 62)),
    ($rows[] | "  " + (.principal | pad(11)) + (.probe_type | pad(21))
             + (.baseline | cell | pad(10)) + (.post_rls | cell | pad(10))
             + (.post_quarantine | cell)),
    "",
    "  HIT = this principal received a row belonging to another tenant",
    "        (or, for side_channel, read an evidence table).",
    "  ok = clean.  ERR = the probe failed, and the phase does not pass.",
    "  \(.receipt.phases.baseline.foreign_rows) foreign rows at baseline, "
      + "\(.receipt.phases.post_rls.foreign_rows) after RLS, "
      + "\(.receipt.phases.post_quarantine.foreign_rows) after quarantine.",
    "  canary phrase corroborates on \(.receipt.phases.baseline.canary_hits) baseline probe(s)."
JQ
)

# The exact foreign rows that leaked, with the provenance that makes a breach a
# lineage record rather than a pass/fail bit.
JQ_EVIDENCE=$(cat <<'JQ'
  (.provenance | map({key: .id, value: .}) | from_entries) as $prov
  | [.evidence[] | select(.phase == "baseline" and .breach and .probe_type != "side_channel")] as $hits
  | if ($hits | length) == 0 then "  no baseline canary hits in this bundle"
    else ($hits[] as $h
      | "  \($h.principal) via \($h.probe_type), foreign rows returned:",
        ($h.returned[]
          | select(.tenant != $h.principal)
          | ($prov[.id] // {}) as $p
          | "    row \(.id[0:8])  tenant=\(.tenant)"
              + (if $p.origin_tenant then "  origin=\($p.origin_tenant)" else "" end)
              + (if $p.session_id   then "  session=\($p.session_id)"   else "" end)
              + (if $p.source       then "  source=\($p.source)"        else "" end)
              + (if $p.trust        then "  trust=\($p.trust)"          else "" end)
              + (if $p.quarantined  then "  [QUARANTINED]"              else "" end),
            "      \(.content[0:150])"),
        "")
    end
JQ
)

JQ_POLICY=$(cat <<'JQ'
  "  installed on the cluster right now:",
  (.rls.policies[] | "    \(.)"),
  "",
  "  enabled=\(.rls.enabled)  forced=\(.rls.forced)",
  "",
  "  the policy SQL this receipt attests (sha256 \(.receipt.policy_sql_sha256[0:16])):",
  "",
  (.receipt.policy_sql | split("\n")[] | "    \(.)")
JQ
)

JQ_QUARANTINE=$(cat <<'JQ'
  "  \(.receipt.quarantine.count) row(s) moved out of memories",
  "    misattributed_write        \(.receipt.quarantine.misattributed_write)",
  "    derived_from_foreign_read  \(.receipt.quarantine.derived_from_foreign_read)",
  "",
  (if (.quarantine | length) == 0 then "  (no lineage rows in this bundle)"
   else
    ("  " + ("id" | pad(10)) + ("tenant" | pad(9)) + ("origin" | pad(9))
          + ("session" | pad(22)) + "reason"),
    ("  " + ("-" * 74)),
    (.quarantine[] | "  " + (.id[0:8] | pad(10)) + (.tenant | pad(9))
                   + ((.origin_tenant // "-") | pad(9))
                   + ((.session_id // "-") | pad(22)) + .reason)
   end)
JQ
)

JQ_RECEIPT=$(cat <<'JQ'
  "  receipt_id    \(.receipt_meta.receipt_id)",
  "  emitted_at    \(.receipt_meta.emitted_at)",
  "  passed        \(.receipt.passed)",
  "",
  "  clauses:",
  (.receipt.clauses | to_entries[]
    | "    " + (if .value then "PASS" else "FAIL" end) + "  \(.key)"),
  "",
  "  phases:",
  (.receipt.phases | to_entries[]
    | "    " + (.key | pad(18))
      + "probes=\(.value.probes)  breaches=\(.value.breaches)"
      + "  foreign_rows=\(.value.foreign_rows)  canary=\(.value.canary_hits)"
      + "  errors=\(.value.errors)"),
  "",
  "  prev_receipt_hash  \(.receipt_meta.prev_receipt_hash // "<genesis>")",
  "  receipt_hash       \(.receipt_meta.receipt_hash)"
JQ
)

# ---------------------------------------------------------------------------

# Red for a hit, amber for a failed probe. Applied here rather than inside jq so
# the bundle stays plain data, and skipped when stdout is not a terminal so a
# redirected run stays greppable.
colorize() {
  if [[ -t 1 ]]; then
    local red=$'\033[31;1m' amber=$'\033[33;1m' off=$'\033[0m'
    sed -e "s/HIT/${red}HIT${off}/g" -e "s/ERR/${amber}ERR${off}/g"
  else
    cat
  fi
}

hdr() { printf '\n\033[1m%s\033[0m\n' "$*"; }

render_status()     { jq -r "$JQ_LIB $JQ_STATUS"; }
render_matrix()     { jq -r "$JQ_LIB $JQ_MATRIX" | colorize; }
render_evidence()   { jq -r "$JQ_EVIDENCE"; }
render_policy()     { jq -r "$JQ_POLICY"; }
render_quarantine() { jq -r "$JQ_LIB $JQ_QUARANTINE"; }
render_receipt()    { jq -r "$JQ_LIB $JQ_RECEIPT"; }
