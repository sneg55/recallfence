#!/usr/bin/env bash
# RecallFence: build-time embeddings, with a cache and an honest fallback.
#
#   ./fixtures/embed.sh one "some text"     print the vector literal for one text
#   ./fixtures/embed.sh fill < texts.txt    embed every line, in parallel, into the cache
#   ./fixtures/embed.sh key "some text"     print the cache key
#   ./fixtures/embed.sh backend             print which backend would be used, and why
#
# Two backends:
#
#   bedrock  amazon.titan-embed-text-v2:0 (or RF_EMBED_MODEL). The real one.
#   local    a deterministic keystream expanded from SHA-256 of the text.
#
# The fallback is not a stand-in that pretends to be the model. It writes its own
# identifier into `memories.embedding_model` on every row it produces, so a
# receipt can never quietly present fallback vectors as Titan vectors, and a
# table holding both is visibly holding both. That column exists precisely
# because mixing embedding versions inside one vector index degrades retrieval
# with no error and no visible symptom.
#
# What the fallback does and does not buy: it preserves determinism, row count,
# vector width and index behaviour, so every structural property of the demo
# holds under it. It carries no semantics at all, so the leak's semantic ranking
# beat does not survive it. That is survivable by design, because the money shot
# is the direct-ID probe and the rejected write, neither of which depends on an
# embedding model cooperating on the day.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RF_AWS_REGION="${RF_AWS_REGION:-us-east-2}"
RF_EMBED_MODEL="${RF_EMBED_MODEL:-$(jq -r .embedding_model "$HERE/config.json")}"
RF_EMBED_DIM="${RF_EMBED_DIM:-$(jq -r .embedding_dim "$HERE/config.json")}"
RF_EMBED_BACKEND="${RF_EMBED_BACKEND:-auto}"
RF_EMBED_JOBS="${RF_EMBED_JOBS:-8}"
RF_CACHE_DIR="${RF_CACHE_DIR:-$HERE/cache}"

RF_LOCAL_MODEL_ID="local-hash-v1"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Backend selection.
#
# Probed once against the live account rather than assumed, because Bedrock
# model access is an account-level flip that is invisible from the model catalog:
# the model lists as ACTIVE and ON_DEMAND in-region and still refuses InvokeModel
# with "Operation not allowed" until access is granted.
# ---------------------------------------------------------------------------

embed_probe_bedrock() {
  local out; out="$(mktemp)"
  if aws bedrock-runtime invoke-model \
       --region "$RF_AWS_REGION" --model-id "$RF_EMBED_MODEL" \
       --content-type application/json --accept application/json \
       --cli-binary-format raw-in-base64-out \
       --body "{\"inputText\":\"probe\",\"dimensions\":$RF_EMBED_DIM,\"normalize\":true}" \
       "$out" >/dev/null 2>&1; then
    rm -f "$out"; return 0
  fi
  rm -f "$out"; return 1
}

_RF_BACKEND_RESOLVED=""

embed_backend() {
  case "$RF_EMBED_BACKEND" in
    bedrock|local) printf '%s' "$RF_EMBED_BACKEND"; return ;;
  esac
  # Memoised: the probe is a live InvokeModel call, and embed_one asks per text.
  if [[ -z "$_RF_BACKEND_RESOLVED" ]]; then
    if embed_probe_bedrock; then _RF_BACKEND_RESOLVED=bedrock; else _RF_BACKEND_RESOLVED=local; fi
  fi
  printf '%s' "$_RF_BACKEND_RESOLVED"
}

# The model ID that goes into memories.embedding_model for rows this run writes.
embed_model_id() {
  case "$(embed_backend)" in
    bedrock) printf '%s' "$RF_EMBED_MODEL" ;;
    local)   printf '%s' "$RF_LOCAL_MODEL_ID" ;;
  esac
}

# ---------------------------------------------------------------------------
# Cache. One file per text, sharded two levels, keyed by model so switching
# backends can never serve a Titan vector for a local-hash row or the reverse.
# ---------------------------------------------------------------------------

embed_key() { printf '%s' "$1" | shasum -a 256 | cut -c1-64; }

embed_cache_path() {
  local model="$1" key="$2"
  printf '%s/%s/%s/%s.vec' "$RF_CACHE_DIR" "${model//[^A-Za-z0-9._-]/_}" "${key:0:2}" "$key"
}

# ---------------------------------------------------------------------------
# The two producers. Both print a CockroachDB vector literal: [f1,f2,...].
# ---------------------------------------------------------------------------

embed_via_bedrock() {
  local text="$1" out attempt=0 body
  out="$(mktemp)"
  body="$(jq -nc --arg t "$text" --argjson d "$RF_EMBED_DIM" \
            '{inputText:$t, dimensions:$d, normalize:true}')"
  # Titan throttles per account, and a fixture run is thousands of calls back to
  # back. Retry with backoff rather than losing the run to a burst limit.
  while (( attempt < 5 )); do
    if aws bedrock-runtime invoke-model \
         --region "$RF_AWS_REGION" --model-id "$RF_EMBED_MODEL" \
         --content-type application/json --accept application/json \
         --cli-binary-format raw-in-base64-out \
         --body "$body" "$out" >/dev/null 2>&1; then
      jq -c '.embedding' <"$out" | tr -d ' '
      rm -f "$out"; return 0
    fi
    attempt=$(( attempt + 1 ))
    sleep "$attempt"
  done
  rm -f "$out"
  die "bedrock: invoke-model failed 5 times for a text of ${#text} chars"
}

# Deterministic, uniformly distributed, unit-normalised. AES-CTR over zeros with
# the text's own digest as the key is a stable keystream: same text, same vector,
# on any machine, with no model call and no state.
embed_via_local() {
  local text="$1" seed
  seed="$(printf '%s' "$text" | shasum -a 256 | cut -c1-64)"
  head -c "$(( RF_EMBED_DIM * 2 ))" /dev/zero \
    | openssl enc -aes-256-ctr -K "$seed" -iv 00000000000000000000000000000000 -nosalt 2>/dev/null \
    | od -An -tu2 -v \
    | awk '
        { for (i = 1; i <= NF; i++) { v[++n] = $i / 32767.5 - 1.0 } }
        END {
          for (i = 1; i <= n; i++) s += v[i] * v[i]
          s = sqrt(s); if (s == 0) s = 1
          printf "["
          for (i = 1; i <= n; i++) printf "%s%.6f", (i > 1 ? "," : ""), v[i] / s
          printf "]"
        }'
}

# ---------------------------------------------------------------------------
# Public entry points.
# ---------------------------------------------------------------------------

embed_one() {
  local text="$1" backend model key path
  backend="$(embed_backend)"
  model="$(embed_model_id)"
  key="$(embed_key "$text")"
  path="$(embed_cache_path "$model" "$key")"
  if [[ -s "$path" ]]; then cat "$path"; return 0; fi
  mkdir -p "$(dirname "$path")"
  case "$backend" in
    bedrock) embed_via_bedrock "$text" >"$path.tmp" ;;
    local)   embed_via_local   "$text" >"$path.tmp" ;;
    *)       die "unknown backend: $backend" ;;
  esac
  mv "$path.tmp" "$path"
  cat "$path"
}

# Reads one text per line. Content is generated without tabs or newlines, so a
# line is a whole text and no quoting layer is needed between here and the corpus.
embed_fill() {
  local backend model total
  backend="$(embed_backend)"
  model="$(embed_model_id)"
  printf 'embedding via %s (%s), %s jobs\n' "$backend" "$model" "$RF_EMBED_JOBS" >&2
  # The children get the resolved backend, model and dimension in the
  # environment so that sourcing this file costs them nothing: left to their own
  # defaults they would each re-run the jq config reads and, on `auto`, a live
  # Bedrock probe, once per text.
  #
  # NUL-delimited, and a batch of texts per worker rather than one. `-I{}` would
  # be simpler but starts a shell per text, and at corpus scale sourcing this
  # file thousands of times costs more than the embedding does. `-n` needs `-0`,
  # because without it xargs splits on whitespace and every text here is a
  # sentence.
  #
  # shellcheck disable=SC2016  # $1 and $@ belong to the child shell, not to this one
  total=$(tr '\n' '\0' \
          | RF_EMBED_BACKEND="$backend" RF_EMBED_MODEL="$RF_EMBED_MODEL" \
            RF_EMBED_DIM="$RF_EMBED_DIM" RF_CACHE_DIR="$RF_CACHE_DIR" \
            xargs -0 -P "$RF_EMBED_JOBS" -n 64 \
              bash -c 'source "$1"; shift; for t in "$@"; do embed_one "$t" >/dev/null; echo .; done' \
              embed-worker "$HERE/embed.sh" \
          | wc -l | tr -d ' ')
  printf 'cached %s texts (%s)\n' "$total" "$model" >&2
}

# Sourcing this file gets the functions without running anything. The worker in
# embed_fill is deliberately given a $0 of its own rather than the script path:
# `bash -c '...' "$HERE/embed.sh"` would make $0 equal BASH_SOURCE, this guard
# would read as "run directly", and every worker would print usage and exit
# instead of embedding anything.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-}" in
    one)     embed_one "${2:?text required}" ;;
    fill)    embed_fill ;;
    key)     embed_key "${2:?text required}" ;;
    backend) printf '%s\t%s\n' "$(embed_backend)" "$(embed_model_id)" ;;
    *)       sed -n '2,26p' "${BASH_SOURCE[0]}" >&2; exit 1 ;;
  esac
fi
