#!/usr/bin/env bash
# RecallFence: freeze the probe-query embeddings.
#
#   ./harness/freeze.sh          write harness/queries.json from fixtures/config.json
#
# Determinism has a precondition. A harness that called Bedrock at run time would
# not be deterministic: a model version change between the baseline and
# post-repair phases silently moves the query point, and the phases stop being
# comparable without anything appearing to go wrong. So the query vector is
# computed once, here, and committed. run.sh reads it from disk and never calls a
# model.
#
# Scope that precisely. Bedrock is a build-time dependency of the *harness*. It
# stays a run-time dependency of the support agent, which has to embed new
# content whenever it writes a memory. Two paths, two failure modes, and this
# file covers only the first.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$HERE/../fixtures"
OUT="$HERE/queries.json"

query="$(jq -r .leak.query "$FIXTURES/config.json")"
model="$("$FIXTURES/embed.sh" backend | cut -f2)"
vec="$("$FIXTURES/embed.sh" one "$query")"

jq -n --arg m "$model" \
      --argjson d "$(jq -r .embedding_dim "$FIXTURES/config.json")" \
      --arg t "$query" \
      --argjson v "$vec" \
      '{embedding_model: $m, embedding_dim: $d, queries: {leak: {text: $t, vector: $v}}}' \
  >"$OUT"

printf 'wrote %s\n  model %s, %s dimensions\n  query: %s\n' \
  "$OUT" "$model" "$(jq '.queries.leak.vector | length' "$OUT")" "$query"

# The model that embedded the query has to be the model that embedded the
# corpus, or the query point is in a different coordinate system from the rows
# and every distance is meaningless. Nothing about that failure is visible in a
# result set, so it is checked here rather than discovered on camera.
corpus_model="$(jq -r .embedding_model "$FIXTURES/manifest.json" 2>/dev/null || echo unknown)"
if [[ "$corpus_model" != "$model" && "$corpus_model" != unknown ]]; then
  printf '\nerror: corpus was embedded with %s, this query with %s.\n' "$corpus_model" "$model" >&2
  printf '       Reseed the fixtures or re-freeze, but do not run the harness across both.\n' >&2
  exit 1
fi
