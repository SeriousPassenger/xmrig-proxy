#include "base/net/stratum/DaemonReconciliation.h"

#include "3rdparty/rapidjson/document.h"


#include <cassert>
#include <initializer_list>
#include <string>


using xmrig::DaemonReconciliation;


namespace {


static const char *kBlockId =
    "ac13a10457b15f81f06da3c21a5db03fcacf137805185ffb948d345a1d45fb66";
static const char *kFormerWrongRawHash =
    "89d66b5f187e371890cf9103cdf66d8e3abc213d32bba29bc2b3f313b3d10108";


void parse(rapidjson::Document &doc, const char *json)
{
    doc.Parse(json);
    assert(!doc.HasParseError());
}


uint32_t attemptsFor(std::initializer_list<DaemonReconciliation::SubmitDecision::Outcome> outcomes)
{
    uint32_t attempts = 0;
    for (const auto outcome : outcomes) {
        attempts++;
        if (!DaemonReconciliation::shouldRetrySubmit(outcome, attempts)) {
            break;
        }
    }

    return attempts;
}


} // namespace


int main()
{
    static_assert(DaemonReconciliation::kMaxSubmitAttempts == 4,
                  "failed submissions require at most four total attempts");
    static_assert(DaemonReconciliation::kRetryDelayMs == 2000,
                  "submit retries must be spaced by two seconds");
    assert(DaemonReconciliation::hasRemainingSubmitAttempts(1));
    assert(DaemonReconciliation::hasRemainingSubmitAttempts(3));
    assert(!DaemonReconciliation::hasRemainingSubmitAttempts(4));
    assert(DaemonReconciliation::nextSubmitAttemptAt(1000) == 3000);
    assert(!DaemonReconciliation::isSubmitRetryDue(3000, 2999));
    assert(DaemonReconciliation::isSubmitRetryDue(3000, 3000));
    assert(!DaemonReconciliation::isSubmitRetryDue(0, 3000));

    using SubmitOutcome = DaemonReconciliation::SubmitDecision::Outcome;
    for (uint32_t attempt = 1; attempt <= 4; ++attempt) {
        assert(!DaemonReconciliation::shouldRetrySubmit(
            SubmitOutcome::Accepted, attempt));
    }
    for (uint32_t attempt = 1; attempt < 4; ++attempt) {
        assert(DaemonReconciliation::shouldRetrySubmit(
            SubmitOutcome::Rejected, attempt));
        assert(DaemonReconciliation::shouldRetrySubmit(
            SubmitOutcome::Indeterminate, attempt));
    }
    assert(!DaemonReconciliation::shouldRetrySubmit(
        SubmitOutcome::Rejected, 4));
    assert(!DaemonReconciliation::shouldRetrySubmit(
        SubmitOutcome::Indeterminate, 4));
    assert(DaemonReconciliation::terminalSubmitOutcome(
        SubmitOutcome::Rejected, false) == SubmitOutcome::Rejected);
    assert(DaemonReconciliation::terminalSubmitOutcome(
        SubmitOutcome::Rejected, true) == SubmitOutcome::Indeterminate);
    assert(DaemonReconciliation::terminalSubmitOutcome(
        SubmitOutcome::Indeterminate, true) == SubmitOutcome::Indeterminate);
    assert(DaemonReconciliation::terminalSubmitOutcome(
        SubmitOutcome::Accepted, true) == SubmitOutcome::Accepted);

    // The first OK stops submission immediately; otherwise a later OK stops
    // the bounded sequence without sending any remaining retries.
    assert(attemptsFor({SubmitOutcome::Accepted, SubmitOutcome::Rejected}) == 1);
    assert(attemptsFor({SubmitOutcome::Rejected, SubmitOutcome::Indeterminate,
                        SubmitOutcome::Accepted, SubmitOutcome::Rejected}) == 3);
    assert(attemptsFor({SubmitOutcome::Rejected, SubmitOutcome::Rejected,
                        SubmitOutcome::Rejected, SubmitOutcome::Rejected}) == 4);
    assert(attemptsFor({SubmitOutcome::Indeterminate, SubmitOutcome::Indeterminate,
                        SubmitOutcome::Indeterminate, SubmitOutcome::Indeterminate}) == 4);

    rapidjson::Document doc;

    // status OK is authoritative, and a daemon-returned ID is canonical. No
    // locally calculated candidate ID participates in this decision.
    parse(doc,
        "{\"status\":\"OK\","
        "\"block_id\":\"AC13A10457B15F81F06DA3C21A5DB03FCACF137805185FFB948D345A1D45FB66\"}");
    DaemonReconciliation::SubmitDecision decision =
        DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Accepted);
    assert(decision.blockId == kBlockId);
    assert(decision.blockId != kFormerWrongRawHash);

    // Legacy/malformed optional ID metadata cannot delay or reverse status OK.
    parse(doc, "{\"status\":\"OK\"}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Accepted);
    assert(decision.blockId.empty());
    assert(!DaemonReconciliation::shouldRetrySubmit(decision.outcome, 1));

    parse(doc, "{\"status\":\"OK\",\"block_id\":\"not-a-block-id\"}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Accepted);
    assert(decision.blockId.empty());
    assert(!DaemonReconciliation::shouldRetrySubmit(decision.outcome, 1));

    parse(doc, "{\"status\":\"BUSY\"}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Rejected);
    assert(DaemonReconciliation::shouldRetrySubmit(decision.outcome, 1));

    parse(doc, "{}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Indeterminate);

    parse(doc, "{\"status\":\"\"}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Indeterminate);

    parse(doc, "{\"status\":\"O\\u0000K\"}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Indeterminate);

    return 0;
}
