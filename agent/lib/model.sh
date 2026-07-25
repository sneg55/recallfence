#!/usr/bin/env bash
# RecallFence: the language model, kept off the access-control path.
#
# Sourced by support.sh and auditor.sh.
#
# The rule this file exists to enforce: every fact an agent states is computed by
# SQL first, and the model is only ever asked to render those facts as prose. It
# is never asked what a tenant may see, never asked whether a row leaked, and
# never asked to decide anything. If the model is unavailable the facts are
# printed verbatim and nothing about the result changes except how it reads.
#
# That is why `model_polish` takes the finished text and returns text. There is
# deliberately no function here that takes a question and returns an answer.
#
# The same honesty rule as the embedder: the backend actually used is reported,
# so a transcript cannot present template output as model output.
#
# Three backends, tried in that order:
#
#   mantle    the bedrock-mantle endpoint, authenticated with an API key rather
#             than SigV4. This is the one that currently works on this account.
#   bedrock   classic bedrock-runtime Converse. Still probed, because the
#             account restriction that blocks it is expected to clear.
#   template  facts printed verbatim.
#
# Why mantle exists as a separate backend rather than a different model id: the
# account's classic `bedrock-runtime` is restricted to zero on-demand throughput
# for every model, while the mantle endpoint serves inference on the same
# account. They are different services reached different ways, so a caller that
# knows only "Bedrock" cannot express which one answered, and the receipt has to
# say which one answered.
#
# Note that mantle is text generation only. It publishes no embeddings route, so
# `fixtures/embed.sh` is unaffected by any of this and the corpus stays on
# local-hash-v1 until classic Bedrock clears.
#
# No `set -e`. This file is sourced and options leak into the caller.

RF_BEDROCK_TEXT_MODEL="${RF_BEDROCK_TEXT_MODEL:-us.amazon.nova-lite-v1:0}"
RF_AWS_REGION="${RF_AWS_REGION:-us-east-2}"

# The mantle endpoint is its own region. us-east-1 rather than the project's
# us-east-2 because that is where the endpoint is served; keeping it as its own
# variable means changing the cluster region can never silently point the model
# somewhere that does not answer.
RF_MANTLE_REGION="${RF_MANTLE_REGION:-us-east-1}"
RF_MANTLE_TEXT_MODEL="${RF_MANTLE_TEXT_MODEL:-google.gemma-4-31b}"
RF_MANTLE_URL="${RF_MANTLE_URL:-https://bedrock-mantle.$RF_MANTLE_REGION.api.aws/openai/v1/chat/completions}"

# Why the OpenAI-compatible route and an open-weight model, when the endpoint
# also speaks the Anthropic Messages API. Both were measured on this account:
#
#   /anthropic/v1/messages   authenticates, but every Anthropic model answers
#                            `permission_error: not available for this account`.
#                            Those are gated behind the same use-case form the
#                            account cannot submit, so they are out of reach.
#   /openai/v1/chat/completions   serves the open-weight catalogue. Confirmed
#                            answering with google.gemma-4-31b and
#                            google.gemma-4-e2b.
#
# Two traps worth leaving written down. Sending an `OpenAI-Project` header makes
# otherwise valid requests fail, so it is deliberately absent. And the
# `openai.gpt-oss-*` ids are recognised but rejected with "isn't supported on
# this route", so a model id existing in the catalogue does not mean this route
# will serve it. Probe before switching RF_MANTLE_TEXT_MODEL.

# Where the API key comes from. Never a literal, never a file in the repo:
# RF_MANTLE_API_KEY for a throwaway short-term key, otherwise Secrets Manager
# under the same prefix as every other credential this project holds.
RF_MANTLE_SECRET="${RF_MANTLE_SECRET:-service/bedrock-mantle}"

# `secret_field` and the RF_SECRETS_PREFIX default live in schema/lib/creds.sh,
# which both agents already source before this file. Sourced here too when it is
# absent, rather than re-declaring the prefix, because a default in two places
# will eventually disagree with itself.
if ! declare -F secret_field >/dev/null 2>&1; then
  # shellcheck source=../../schema/lib/creds.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../schema/lib" && pwd)/creds.sh"
fi

RF_MODEL_BACKEND=""
_RF_MANTLE_KEY=""
_RF_MANTLE_KEY_TRIED=""

# The key, memoised, including a memoised failure: without the second flag an
# account with no key configured would call Secrets Manager once per polish.
mantle_key() {
  [[ -n "$_RF_MANTLE_KEY" ]] && { printf '%s' "$_RF_MANTLE_KEY"; return 0; }
  [[ -n "$_RF_MANTLE_KEY_TRIED" ]] && return 1
  _RF_MANTLE_KEY_TRIED=1

  if [[ -n "${RF_MANTLE_API_KEY:-}" ]]; then
    _RF_MANTLE_KEY="$RF_MANTLE_API_KEY"
  else
    _RF_MANTLE_KEY="$(secret_field "$RF_MANTLE_SECRET" api_key 2>/dev/null)" || _RF_MANTLE_KEY=""
  fi
  [[ -n "$_RF_MANTLE_KEY" ]] || return 1
  printf '%s' "$_RF_MANTLE_KEY"
}

# mantle_post <body-file> -> response body on stdout.
#
# The key goes in a curl config on stdin, not in an argument. Arguments are
# world-readable in `ps` for the life of the call, and this project's whole
# posture is that nothing credential-shaped is ever observable outside the
# process that needs it. The body is a temp file because stdin is taken.
mantle_post() {
  local body_file="$1" key
  key="$(mantle_key)" || return 1
  curl -sS --max-time 30 -X POST --data-binary "@$body_file" --config - <<CFG
url = "$RF_MANTLE_URL"
header = "content-type: application/json"
header = "x-api-key: $key"
CFG
}

# mantle_text <prompt> <max-tokens> -> generated text, or non-zero.
mantle_text() {
  local prompt="$1" max="$2" body out text
  body="$(mktemp)" || return 1
  jq -nc --arg m "$RF_MANTLE_TEXT_MODEL" --arg p "$prompt" --argjson n "$max" \
     '{model:$m, max_tokens:$n, temperature:0,
       messages:[{role:"user", content:$p}]}' >"$body" || { rm -f "$body"; return 1; }
  out="$(mantle_post "$body" 2>/dev/null)"; local status=$?
  rm -f "$body"
  (( status == 0 )) || return 1
  # An error response is still HTTP-shaped JSON, so absence of the text is the
  # check that matters, not the exit status of curl.
  text="$(printf '%s' "$out" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
  [[ -n "$text" ]] || return 1
  printf '%s' "$text"
}

# Probed once, then memoized. Reading a model catalogue is not enough: a model
# can list as ACTIVE and ON_DEMAND and still refuse InvokeModel until access is
# granted on the account, which is exactly the state classic Bedrock is in here.
# So each probe is a real call.
model_backend() {
  [[ -n "$RF_MODEL_BACKEND" ]] && { printf '%s' "$RF_MODEL_BACKEND"; return 0; }

  case "${RF_TEXT_BACKEND:-auto}" in
    mantle|bedrock|template) RF_MODEL_BACKEND="$RF_TEXT_BACKEND"
                             printf '%s' "$RF_MODEL_BACKEND"; return 0 ;;
  esac

  if mantle_text "ok" 8 >/dev/null 2>&1; then
    RF_MODEL_BACKEND=mantle
  elif aws bedrock-runtime converse \
         --region "$RF_AWS_REGION" --model-id "$RF_BEDROCK_TEXT_MODEL" \
         --messages '[{"role":"user","content":[{"text":"ok"}]}]' \
         --inference-config '{"maxTokens":8}' >/dev/null 2>&1; then
    RF_MODEL_BACKEND=bedrock
  else
    RF_MODEL_BACKEND=template
  fi
  printf '%s' "$RF_MODEL_BACKEND"
}

# model_id -> what to record alongside anything this produced.
model_id() {
  case "$(model_backend)" in
    mantle)  printf '%s' "$RF_MANTLE_TEXT_MODEL" ;;
    bedrock) printf '%s' "$RF_BEDROCK_TEXT_MODEL" ;;
    *)       printf 'local-template-v1' ;;
  esac
}

# model_polish <facts> [style]
#
# Facts in, prose out. With no backend, the facts come back unchanged, which is a
# perfectly good answer and is why the fallback is not a degraded mode so much as
# a plainer voice.
#
# The prompt says "do not add any fact that is not present". It is worth being
# clear-eyed that this is an instruction, not a guarantee, which is the whole
# reason the model never touches the boundary and every number in the receipt is
# computed in SQL.
model_polish() {
  local facts="$1" style="${2:-Rewrite as two or three plain sentences.}"
  local backend prompt out
  backend="$(model_backend)"
  [[ "$backend" == template ]] && { printf '%s' "$facts"; return 0; }

  prompt="$style
Do not add any fact that is not present below. Do not speculate. Keep every
identifier, tenant name and number exactly as written.

$facts"

  case "$backend" in
    mantle)
      out="$(mantle_text "$prompt" 400)" || { printf '%s' "$facts"; return 0; }
      ;;
    bedrock)
      out="$(aws bedrock-runtime converse \
              --region "$RF_AWS_REGION" --model-id "$RF_BEDROCK_TEXT_MODEL" \
              --messages "$(jq -c -n --arg p "$prompt" \
                            '[{role:"user",content:[{text:$p}]}]')" \
              --inference-config '{"maxTokens":400,"temperature":0}' \
              --query 'output.message.content[0].text' --output text 2>/dev/null)" \
        || { printf '%s' "$facts"; return 0; }
      ;;
  esac

  [[ -n "$out" && "$out" != "None" ]] && printf '%s' "$out" || printf '%s' "$facts"
}

# A one-line banner so a transcript always says which voice produced it.
model_banner() {
  case "$(model_backend)" in
    mantle)
      printf '[model: %s via bedrock-mantle]\n' "$RF_MANTLE_TEXT_MODEL" ;;
    bedrock)
      printf '[model: %s]\n' "$RF_BEDROCK_TEXT_MODEL" ;;
    *)
      printf '[model: local-template-v1, no model backend reachable. Facts are unaffected:\n'
      printf ' every number below is computed in SQL, the model only ever rephrases them.]\n' ;;
  esac
}
