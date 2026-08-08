#include "base/net/stratum/DaemonReconciliation.h"

#include "3rdparty/rapidjson/document.h"


#include <cassert>
#include <cstring>
#include <string>


using xmrig::DaemonReconciliation;


namespace {


static const char *kBlockId =
    "ac13a10457b15f81f06da3c21a5db03fcacf137805185ffb948d345a1d45fb66";
static const char *kFormerWrongRawHash =
    "89d66b5f187e371890cf9103cdf66d8e3abc213d32bba29bc2b3f313b3d10108";
static const char *kMinerTxHash =
    "6770a7051757bdd06e2656457ed9cde01bbd5914103fde93f277b613676bdbd1";
static const char *kBlockBlob =
    "101093daded306ab16f908b7f6f53b3f6f35d2a54e72cac93d64c7985a508a"
    "1d3f44d43bf7594dfa10008902b783e40101fffb82e40101c09897e6be11034b"
    "2c7cf7f470b15c19049f75e6e192bad6a3bbbb04d65212a58939f2d4b3d1646"
    "73301be41136497b6e8d10b826a1492e635c4239b63f98f66ba0d699bc146488"
    "45b0a0210e3360a8e954e1cc51b0dd0cf85c0037c0003de4efd4363e4429421"
    "ada2726935b71db63ea532dd189c2099dd35fbc3b269fdf1246dc9908dc14ce3"
    "835722086129cd17f991c31cfd82bad3710177d3bff6ec3f56170978c2650353"
    "4cbe71bbb1ff19a7b7216f0fa1a7239ea99b725cad98d3";


void parse(rapidjson::Document &doc, const char *json)
{
    doc.Parse(json);
    assert(!doc.HasParseError());
}


void parseCanonicalBlock(rapidjson::Document &doc)
{
    parse(doc,
        "{"
        "\"blob\":\"101093daded306ab16f908b7f6f53b3f6f35d2a54e72cac93d64c7985a508a1d3f44d43bf7594dfa10008902b783e40101fffb82e40101c09897e6be11034b2c7cf7f470b15c19049f75e6e192bad6a3bbbb04d65212a58939f2d4b3d164673301be41136497b6e8d10b826a1492e635c4239b63f98f66ba0d699bc14648845b0a0210e3360a8e954e1cc51b0dd0cf85c0037c0003de4efd4363e4429421ada2726935b71db63ea532dd189c2099dd35fbc3b269fdf1246dc9908dc14ce3835722086129cd17f991c31cfd82bad3710177d3bff6ec3f56170978c26503534cbe71bbb1ff19a7b7216f0fa1a7239ea99b725cad98d3\","
        "\"block_header\":{"
        "\"hash\":\"ac13a10457b15f81f06da3c21a5db03fcacf137805185ffb948d345a1d45fb66\","
        "\"height\":3735931,"
        "\"miner_tx_hash\":\"6770a7051757bdd06e2656457ed9cde01bbd5914103fde93f277b613676bdbd1\","
        "\"orphan_status\":false"
        "},"
        "\"miner_tx_hash\":\"6770a7051757bdd06e2656457ed9cde01bbd5914103fde93f277b613676bdbd1\","
        "\"status\":\"OK\","
        "\"untrusted\":false"
        "}");
}


} // namespace


int main()
{
    static_assert(DaemonReconciliation::kMaxAttempts == 4,
                  "indeterminate submissions require exactly four lookups");
    static_assert(DaemonReconciliation::kRetryDelayMs == 2000,
                  "canonical lookups must be spaced by two seconds");
    assert(DaemonReconciliation::hasRemainingAttempts(0));
    assert(DaemonReconciliation::hasRemainingAttempts(3));
    assert(!DaemonReconciliation::hasRemainingAttempts(4));
    assert(DaemonReconciliation::nextAttemptAt(1000) == 3000);
    assert(strlen(kBlockBlob) == 490);

    using SubmitOutcome = DaemonReconciliation::SubmitDecision::Outcome;
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

    parse(doc, "{\"status\":\"OK\",\"block_id\":\"not-a-block-id\"}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Accepted);
    assert(decision.blockId.empty());

    parse(doc, "{\"status\":\"BUSY\"}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Rejected);

    parse(doc, "{}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Indeterminate);

    parse(doc, "{\"status\":\"\"}");
    decision = DaemonReconciliation::classifySubmitResult(doc);
    assert(decision.outcome == SubmitOutcome::Indeterminate);

    // Height 3735931 is the production regression. Monero calculate_block_hash
    // hashes the serialized blobdata object: its 76-byte hashing blob is
    // prefixed by the canonical one-byte length 0x4c. The former proxy hashed
    // those 76 bytes raw and obtained kFormerWrongRawHash instead. Exact full
    // blob and miner transaction matches recover the daemon's canonical ID.
    parseCanonicalBlock(doc);
    DaemonReconciliation::Match match =
        DaemonReconciliation::matchCanonicalBlock(
            doc, 3735931, kMinerTxHash, kBlockBlob);
    assert(match.accepted);
    assert(match.blockId == kBlockId);
    assert(match.blockId != kFormerWrongRawHash);

    parseCanonicalBlock(doc);
    doc["block_header"]["miner_tx_hash"].SetString(
        "7770a7051757bdd06e2656457ed9cde01bbd5914103fde93f277b613676bdbd1",
        doc.GetAllocator());
    match = DaemonReconciliation::matchCanonicalBlock(
        doc, 3735931, kMinerTxHash, kBlockBlob);
    assert(!match.accepted);

    parseCanonicalBlock(doc);
    std::string differentBlob(kBlockBlob);
    differentBlob[0] = '2';
    doc["blob"].SetString(differentBlob.c_str(),
                          static_cast<rapidjson::SizeType>(differentBlob.size()),
                          doc.GetAllocator());
    match = DaemonReconciliation::matchCanonicalBlock(
        doc, 3735931, kMinerTxHash, kBlockBlob);
    assert(!match.accepted);

    parseCanonicalBlock(doc);
    doc["block_header"]["orphan_status"].SetBool(true);
    match = DaemonReconciliation::matchCanonicalBlock(
        doc, 3735931, kMinerTxHash, kBlockBlob);
    assert(!match.accepted);

    parseCanonicalBlock(doc);
    match = DaemonReconciliation::matchCanonicalBlock(
        doc, 3735932, kMinerTxHash, kBlockBlob);
    assert(!match.accepted);

    return 0;
}
