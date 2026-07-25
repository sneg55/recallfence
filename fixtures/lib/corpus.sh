#!/usr/bin/env bash
# RecallFence: deterministic corpus generation.
#
# Sourced by seed.sh. Emits tab-separated records on stdout, one per row:
#
#   kind  id_key  tenant  origin_tenant  session_id  source  trust  content
#
# `id_key` is a stable string, not a UUID. seed.sh hashes it into the row's
# primary key, so the same corpus always produces the same IDs and the harness
# can name a foreign row without a handoff file surviving between processes.
#
# Everything here is a pure function of the config plus the row index. No
# randomness anywhere: a fixture that reseeds differently makes the baseline and
# post-repair phases incomparable, which is the same determinism argument the
# spec makes about probe-query embeddings.
#
# No `set -e`. This file is sourced and options leak into the caller.

# ---------------------------------------------------------------------------
# Canary phrases.
#
# A canary has to be unique per tenant, stable across every run, and plausible
# enough that a judge does not read it as planted. A purchase-order number is
# all three: it looks like something a support agent would actually write down,
# and it is specific enough that its appearance in another tenant's answer is
# unambiguous rather than a coincidence of wording.
# ---------------------------------------------------------------------------

CORPUS_PO_LETTERS=(K R D M T P L N B G X Z F H Q V W J C S)

corpus_canary_phrase() {
  local tenant="$1" h
  h="$(printf '%s' "canary:$tenant" | shasum -a 256 | cut -c1-8)"
  printf 'purchase order PO-%d-%s%s' \
    "$(( 0x${h:0:4} % 90000 + 10000 ))" \
    "${CORPUS_PO_LETTERS[$(( 0x${h:4:2} % 20 ))]}" \
    "${CORPUS_PO_LETTERS[$(( 0x${h:6:2} % 20 ))]}"
}

corpus_canary_content() {
  local tenant="$1"
  printf 'Account note: the annual renewal for %s was invoiced against %s. Finance asked that any credit or refund be applied against that same purchase order rather than issued to the card on file.' \
    "$(corpus_display "$tenant")" "$(corpus_canary_phrase "$tenant")"
}

corpus_display() { printf '%s' "$(tr '[:lower:]' '[:upper:]' <<<"${1:0:1}")${1:1} Retail"; }

# ---------------------------------------------------------------------------
# Refund policies.
#
# The leak turns on this one row. `bob`'s policy is written to sit closer to the
# demo query ("maximum refund I can approve for an enterprise customer without
# escalating") than `alice`'s own policy does, because alice's business is
# consumer orders and bob's is enterprise contracts. The corpus is selected for
# that outcome. See fixtures/README.md: the query is ordinary, the corpus is
# chosen, and pretending the ranking is a lucky accident would be a small
# dishonesty that costs more than it buys.
#
# Each policy carries its own tenant's canary phrase, and that is load-bearing
# rather than flavour. A canary hit is scored on returned content, so the row a
# semantic probe actually retrieves has to be a row that carries a phrase. The
# first version put the phrase only on the account-note row, which is about a
# renewal invoice and is nowhere near a query about refund ceilings: the
# semantic probe would have retrieved bob's policy, leaked it, and scored
# `foreign_canary_hit = false`, because the marker was sitting on a different
# row from the leak. The probe would have been reporting on the wrong document.
#
# Putting a tenant's own phrase on their own policy is safe in the way that
# putting a *foreign* phrase on a contaminated row is not: it only ever scores
# when somebody else retrieves it, which is precisely the event being measured.
# ---------------------------------------------------------------------------

corpus_policy_content() {
  local tenant="$1"
  case "$tenant" in
    bob)
      printf 'Refund authority for enterprise accounts: a support engineer may approve a refund of up to 25,000 USD per incident for an enterprise customer without escalating to a director. Above that ceiling, director approval is required before the credit is issued. Credits are booked against %s.' \
        "$(corpus_canary_phrase "$tenant")"
      ;;
    alice)
      printf 'Refund policy for consumer orders: any order under 200 USD is refunded automatically on request within 30 days of delivery, and the agent does not need approval. Orders above that go to the returns queue. Credits are booked against %s.' \
        "$(corpus_canary_phrase "$tenant")"
      ;;
    *)
      printf 'Refund policy for %s: refunds are issued to the original payment method within five business days of approval, and the approving agent records the reason code on the account. Credits are booked against %s.' \
        "$(corpus_display "$tenant")" "$(corpus_canary_phrase "$tenant")"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Filler, combinatorial rather than random.
#
# The pools multiply out to far more distinct sentences than the corpus uses, so
# no two rows share content and therefore no two rows share an embedding. That
# matters: a corpus with a few hundred distinct vectors repeated thousands of
# times would give the vector index a degenerate distribution and make the
# cost-of-the-boundary measurement meaningless.
# ---------------------------------------------------------------------------

CORPUS_NAMES=(Adeyemi Novak Ferreira Okonkwo Lindqvist Batista Haruki Vasquez
  Kowalski Mbeki Ranganathan Dubois Karlsen Achterberg Sorrentino Ivanova
  Nakamura Oyelaran Petrenko Salgado Thorne Ueda Villanueva Whitlock Xiong
  Yilmaz Zambrano Brennan Costa Delacroix Eriksen Fontaine)

CORPUS_PLANS=(starter growth business enterprise legacy)

CORPUS_TOPICS=(
  "a duplicate charge on the September invoice"
  "seat counts drifting after an SSO migration"
  "an export that stops at ten thousand rows"
  "webhook retries arriving out of order"
  "a sandbox key that works in production"
  "invoice consolidation across three subsidiaries"
  "data residency for a new EU subsidiary"
  "an onboarding import that dropped custom fields"
  "rate limits during their end-of-quarter batch"
  "a renewal quote that omitted the volume tier"
  "SAML assertions failing after a certificate rotation"
  "audit log retention beyond the default window"
  "a partial outage during their maintenance window"
  "usage alerts firing on a decommissioned project"
  "transferring ownership of a shared workspace"
  "a refund for an accidental annual upgrade")

CORPUS_ACTIONS=(
  "confirmed the account state directly"
  "reproduced the behaviour on a test workspace"
  "escalated to the platform team"
  "checked the billing ledger"
  "walked the customer through the setting"
  "opened a defect against the importer"
  "applied a temporary rate-limit exemption"
  "verified the certificate chain"
  "pulled the delivery log for the affected window"
  "compared the quote against the contract"
  "reissued the credential out of band"
  "scheduled a follow-up before the renewal date")

CORPUS_OUTCOMES=(
  "the customer accepted the explanation"
  "a credit was queued for the next cycle"
  "the fix ships in the next release train"
  "the customer asked for written confirmation"
  "the ticket was left open pending their reply"
  "the workaround held through the batch window"
  "the account owner was looped in by email"
  "no further action was needed"
  "the customer escalated to their account manager"
  "the change was applied during their next window")

# Provenance pools. Read by seed.sh, which sources this file; shellcheck cannot
# see across that boundary.
# shellcheck disable=SC2034
CORPUS_SOURCES=(tool_call user_message summarizer import agent_summary)
# shellcheck disable=SC2034
CORPUS_TRUST=(user_confirmed model_derived external)

corpus_filler_content() {
  local tenant="$1" i="$2"
  printf 'Support session for %s (%s plan) at %s: customer raised %s. The agent %s and %s.' \
    "${CORPUS_NAMES[$(( i % ${#CORPUS_NAMES[@]} ))]}" \
    "${CORPUS_PLANS[$(( (i / 7) % ${#CORPUS_PLANS[@]} ))]}" \
    "$(corpus_display "$tenant")" \
    "${CORPUS_TOPICS[$(( (i / 3) % ${#CORPUS_TOPICS[@]} ))]}" \
    "${CORPUS_ACTIONS[$(( (i / 11) % ${#CORPUS_ACTIONS[@]} ))]}" \
    "${CORPUS_OUTCOMES[$(( (i / 13) % ${#CORPUS_OUTCOMES[@]} ))]}"
}
