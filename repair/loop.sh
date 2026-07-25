#!/usr/bin/env bash
# RecallFence: the repair loop, end to end.
#
#   ./repair/loop.sh <baseline-run-id> --approve
#
# Applies the policy set, reruns the probe matrix, quarantines the contaminated
# rows, and reruns the matrix again. One command for the demo and the CLI, and
# the same four steps an operator would run by hand.
#
# `--approve` is required and is passed down rather than re-asked at each step.
# The operator approves the repair once, having read the policy SQL; being
# prompted four times would train them to stop reading, which is the failure mode
# an approval gate is supposed to prevent.
#
# Step order is deliberate and is the reason there are two reruns rather than
# one. Probing after RLS but before quarantine is what makes the two effects
# separable: if cleanup ran first, "no rows returned" would prove nothing,
# because an emptied table returns nothing either.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_RUN="${1:-}"

[[ -n "$BASELINE_RUN" && "${2:-}" == "--approve" ]] || {
  sed -n '2,6p' "${BASH_SOURCE[0]}" >&2; exit 1
}

step() { printf '\n\n########## %s\n' "$*"; }

step "1/4  policy set (human-in-the-loop gate, approved on the command line)"
"$HERE/policy.sh" apply --approve

step "2/4  rerun: post_rls"
"$HERE/../harness/run.sh" post_rls

step "3/4  quarantine, keyed to $BASELINE_RUN"
"$HERE/quarantine.sh" "$BASELINE_RUN" --apply

step "4/4  rerun: post_quarantine"
"$HERE/../harness/run.sh" post_quarantine

printf '\n\nrepair loop complete. The receipt is built from the three runs.\n'
