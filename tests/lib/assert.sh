#!/usr/bin/env bash
# RecallFence: the assertion harness the policy tests are written against.
#
# Sourced, never executed. Sets no shell options of its own, because half the
# cases in a policy suite are supposed to fail and inheriting errexit from a
# library would abort the run on the first expected permission denial.
#
# Credentials and connection building moved to schema/lib/creds.sh once harness/
# needed them too. The probe runner and the tests that guard it have to build
# connections the same way or they are not exercising the same thing.
# shellcheck source=../../schema/lib/creds.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../schema/lib" && pwd)/creds.sh"

PASSED=0
FAILED=0

pass()  { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASSED=$((PASSED + 1)); }
fail()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; printf '        %s\n' "${2:-}" >&2; FAILED=$((FAILED + 1)); }
group() { printf '\n%s\n' "$1"; }

summary() {
  printf '\n%s\n' "-------------------------------------------"
  printf 'passed: %d   failed: %d\n' "$PASSED" "$FAILED"
  [[ "$FAILED" -eq 0 ]]
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

# `run_as` lives in schema/lib/creds.sh, sourced above. Every assertion below is
# written against it.

# expect_count <label> <url> <sql returning one count> <exact expected value>
# Exact rather than substring, because "3" matches almost any output and a
# permissive assertion in a security test is worse than no assertion at all.
expect_count() {
  local label="$1" url="$2" sql="$3" want="$4" out got
  if ! out="$(run_as "$url" "$sql")"; then
    fail "$label" "statement failed but should have succeeded: $(tr '\n' '|' <<<"$out")"
    return
  fi
  got="$(printf '%s' "$out" | tail -n 1 | tr -d '[:space:]')"
  if [[ "$got" == "$want" ]]; then
    pass "$label"
  else
    fail "$label" "expected exactly '$want', got '$got'"
  fi
}

# expect_ok <label> <url> <sql> <substring the output must contain>
expect_ok() {
  local label="$1" url="$2" sql="$3" want="$4" out
  if ! out="$(run_as "$url" "$sql")"; then
    fail "$label" "statement failed but should have succeeded: $(tr '\n' '|' <<<"$out")"
  elif [[ "$out" != *"$want"* ]]; then
    fail "$label" "expected output containing '$want', got: $(tr '\n' '|' <<<"$out")"
  else
    pass "$label"
  fi
}

# expect_denied <label> <url> <sql> <substring the error must contain>
# The statement must fail AND fail for the stated reason. Matching the reason is
# not pedantry: a case that only checks "it errored" passes just as happily when
# the table name is misspelled, which is how a security suite ends up green while
# testing nothing.
expect_denied() {
  local label="$1" url="$2" sql="$3" want="$4" out
  if out="$(run_as "$url" "$sql")"; then
    fail "$label" "statement SUCCEEDED but should have been denied: $(tr '\n' '|' <<<"$out")"
  elif [[ "$out" != *"$want"* ]]; then
    fail "$label" "denied, but not for the expected reason. Wanted '$want', got: $(tr '\n' '|' <<<"$out")"
  else
    pass "$label"
  fi
}
