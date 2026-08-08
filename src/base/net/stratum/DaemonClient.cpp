/* XMRig
 * Copyright (c) 2019      Howard Chu  <https://github.com/hyc>
 * Copyright (c) 2018-2026 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2026 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */


#include "base/net/stratum/DaemonClient.h"

#include "3rdparty/rapidjson/document.h"
#include "3rdparty/rapidjson/error/en.h"
#include "base/io/json/Json.h"
#include "base/io/json/JsonRequest.h"
#include "base/io/log/Log.h"
#include "base/kernel/interfaces/IClientListener.h"
#include "base/net/http/Fetch.h"
#include "base/net/http/HttpData.h"
#include "base/net/http/HttpListener.h"
#include "base/net/stratum/DaemonReconciliation.h"
#include "base/net/stratum/SubmitResult.h"
#include "base/tools/Chrono.h"
#include "base/tools/cryptonote/BlockTemplate.h"
#include "base/tools/cryptonote/Signatures.h"
#include "base/tools/Cvt.h"
#include "base/tools/SecureRandom.h"
#include "net/JobResult.h"
#include "proxy/live/LiveEventStream.h"
#include "proxy/RandomXVerifier.h"


#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
#include <uv.h>


namespace xmrig {


namespace {


static const char *kJsonRpc = "/json_rpc";
static const char *kSubmitTag = "daemon-submit";
static constexpr size_t kEntropySize = 16;
static constexpr size_t kJobHistorySize = 6;
static constexpr uint64_t kJobHistoryMs = 120000;
static const int kHttpSubmit    = 0x445403;
static const int kHttpReconcile = 0x445404;


bool jsonString(const rapidjson::Value &object, const char *key, std::string &out)
{
    out.clear();
    if (!object.IsObject() || !key) {
        return false;
    }

    const auto member = object.FindMember(key);
    if (member == object.MemberEnd() || !member->value.IsString()) {
        return false;
    }

    out.assign(member->value.GetString(), member->value.GetStringLength());
    return out.find('\0') == std::string::npos;
}


} // namespace


DaemonClient::DaemonClient(int id, IClientListener *listener) :
    BaseClient(id, listener),
    m_httpListener(std::make_shared<HttpListener>(this))
{
}


DaemonClient::~DaemonClient()
{
    m_destroying = true;
    disconnect();
}


void DaemonClient::deleteLater()
{
    delete this;
}


bool DaemonClient::disconnect()
{
    // A live strategy disconnect (for example failover) must complete every
    // accepted downstream request exactly once. Object destruction is the one
    // exception: its listener graph may already be tearing down, so only
    // telemetry is safe there.
    if (!m_destroying) {
        while (!m_pendingSubmissions.empty()) {
            finalizeSubmission(m_pendingSubmissions.begin()->first,
                               SubmitResult::Outcome::Ambiguous,
                               "daemon client disconnected before submitblock outcome was known");
        }
    }
    else {
        for (const auto &entry : m_pendingSubmissions) {
            publishSubmissionRow("submit_block_result", entry.second, entry.first,
                                 "ambiguous",
                                 "daemon client destroyed before submitblock outcome was known",
                                 0, nullptr, true);
        }
    }

    if (m_source) {
        m_source->unsubscribe(this);
        m_source.reset();
    }

    m_contexts.clear();
    m_pendingSnapshot.reset();
    m_pendingSubmissions.clear();
    m_results.clear();
    m_httpListener.reset();
    m_job.reset();
    setState(UnconnectedState);

    return true;
}


bool DaemonClient::isTLS() const
{
#   ifdef XMRIG_FEATURE_TLS
    return m_pool.isTLS();
#   else
    return false;
#   endif
}


void DaemonClient::connect()
{
    if (m_state == ConnectedState || m_state == ConnectingState) {
        return;
    }

    setState(ConnectingState);

    if (!m_httpListener) {
        m_httpListener = std::make_shared<HttpListener>(this);
    }

    if (!m_coin.isValid() && !m_pool.algorithm().isValid()) {
        LOG_ERR("%s " RED("connect error: ") RED_BOLD("\"Invalid algorithm.\""), tag());
        m_listener->onClose(this, 1);
        return;
    }

    if (!m_pool.algorithm().isValid()) {
        m_pool.setAlgo(m_coin.algorithm());
    }

    if (!m_walletAddress.isValid()) {
        LOG_ERR("%s " RED("connect error: ") RED_BOLD("\"Invalid wallet address.\""), tag());
        m_listener->onClose(this, 1);
        return;
    }

    m_source = DaemonTemplateSource::acquire(m_pool, m_user);
    if (!m_source) {
        LOG_ERR("%s " RED("connect error: ") RED_BOLD("\"Failed to create daemon template source.\""), tag());
        m_listener->onClose(this, 1);
        return;
    }

    m_source->subscribe(this, true);
}


void DaemonClient::connect(const Pool &pool)
{
    setPool(pool);
    connect();
}


void DaemonClient::setPool(const Pool &pool)
{
    BaseClient::setPool(pool);

    m_walletAddress.decode(m_user);
    m_coin = pool.coin().isValid() ? pool.coin() : m_walletAddress.coin();

    if (!m_coin.isValid() && pool.algorithm() == Algorithm::RX_WOW) {
        m_coin = Coin::WOWNERO;
    }
}


void DaemonClient::onDaemonTemplate(const std::shared_ptr<const DaemonTemplateSource::Snapshot> &snapshot)
{
    if (m_state == UnconnectedState || !snapshot) {
        return;
    }

    if (RandomXVerifier::instance()) {
        RandomXVerifier::instance()->setSeedRoles(
            snapshot->sourceId,
            snapshot->previousSeedHash.data() ? snapshot->previousSeedHash.data() : "",
            snapshot->seedHash.data() ? snapshot->seedHash.data() : "",
            snapshot->nextSeedHash.data() ? snapshot->nextSeedHash.data() : "");
        RandomXVerifier::instance()->prepareSeed(snapshot->seedHash.data() ? snapshot->seedHash.data() : "");
        RandomXVerifier::instance()->prepareSeed(snapshot->nextSeedHash.data() ? snapshot->nextSeedHash.data() : "");

        if (!RandomXVerifier::instance()->isSeedReady(snapshot->seedHash.data() ? snapshot->seedHash.data() : "")) {
            // Do not advertise work that the configured fail-closed verifier
            // cannot yet check. Keep only the newest daemon snapshot while
            // the current full-memory dataset is prepared.
            m_pendingSnapshot = snapshot;
            return;
        }
    }

    m_pendingSnapshot.reset();
    if (!installTemplate(snapshot) && !isQuiet()) {
        LOG_ERR("%s " RED("job error: ") RED_BOLD("\"Unable to derive private 16-byte template job.\""), tag());
    }
}


void DaemonClient::tick(uint64_t now)
{
    if (m_pendingSnapshot && RandomXVerifier::instance()) {
        const char *seedHash = m_pendingSnapshot->seedHash.data() ? m_pendingSnapshot->seedHash.data() : "";
        if (RandomXVerifier::instance()->isSeedReady(seedHash)) {
            const std::shared_ptr<const DaemonTemplateSource::Snapshot> snapshot = m_pendingSnapshot;
            m_pendingSnapshot.reset();
            if (!installTemplate(snapshot) && !isQuiet()) {
                LOG_ERR("%s " RED("job error: ") RED_BOLD("\"Unable to derive private 16-byte template job.\""), tag());
            }
        }
    }

    std::vector<int64_t> due;
    due.reserve(m_pendingSubmissions.size());
    for (const auto &entry : m_pendingSubmissions) {
        if (entry.second.reconcileDueMs && now >= entry.second.reconcileDueMs) {
            due.push_back(entry.first);
        }
    }

    for (const int64_t id : due) {
        beginReconciliationAttempt(id);
    }
}


bool DaemonClient::prepareSpendKey(Job &job, const BlockTemplate &blocktemplate, const char **error)
{
    if (!blocktemplate.hasMinerSignature()) {
        return true;
    }

    if (m_pool.spendSecretKey().isEmpty()) {
        *error = "Secret spend key is not set.";
        return false;
    }

    if (m_pool.spendSecretKey().size() != 64) {
        *error = "Secret spend key must be exactly 64 hex characters.";
        return false;
    }

    uint8_t secretSpendKey[32];
    if (!Cvt::fromHex(secretSpendKey, sizeof(secretSpendKey), m_pool.spendSecretKey(), 64)) {
        *error = "Secret spend key is not valid hexadecimal data.";
        return false;
    }

    uint8_t publicSpendKey[32];
    if (!secret_key_to_public_key(secretSpendKey, publicSpendKey)) {
        *error = "Secret spend key is invalid.";
        return false;
    }

    job.setSpendSecretKey(secretSpendKey);
    return true;
}


bool DaemonClient::installTemplate(const std::shared_ptr<const DaemonTemplateSource::Snapshot> &snapshot)
{
    auto fail = [this](const char *message) {
        if (!isQuiet()) {
            LOG_ERR("%s " RED("job error: ") RED_BOLD("\"%s\""), tag(), message);
        }
        return false;
    };

    if (snapshot->reserveSize != kEntropySize || snapshot->blocktemplateBlob.isEmpty()) {
        return fail("Daemon template does not contain the required 16-byte reserve.");
    }

    BlockTemplate original;
    if (!original.parse(snapshot->blocktemplateBlob, m_coin)) {
        return fail("Invalid block template received from daemon.");
    }

    if (m_coin == Coin::MONERO && Cvt::toHex(original.generateHashingBlob()) != snapshot->blockhashingBlob) {
        return fail("Daemon blockhashing_blob does not match the parsed block template.");
    }

    const size_t extraNonceOffset = original.offset(BlockTemplate::TX_EXTRA_NONCE_OFFSET);
    if (original.txExtraNonce().size() != kEntropySize ||
        snapshot->reservedOffset != extraNonceOffset ||
        extraNonceOffset + kEntropySize > original.size()) {
        return fail("Daemon reserved_offset does not identify an exact 16-byte tx extra nonce.");
    }

    Buffer entropy;
    if (!SecureRandom::bytes(kEntropySize, entropy)) {
        return fail("OS CSPRNG failed while generating template entropy.");
    }

    const String entropyHex = Cvt::toHex(entropy);
    String blocktemplate(snapshot->blocktemplateBlob);
    memcpy(blocktemplate.data() + extraNonceOffset * 2, entropyHex.data(), entropyHex.size());

    // Parse the mutated full block so its coinbase hash and Merkle root are
    // recalculated from the exact 16 bytes that this downstream will mine.
    BlockTemplate mutated;
    if (!mutated.parse(blocktemplate, m_coin) ||
        mutated.txExtraNonce().size() != kEntropySize ||
        mutated.offset(BlockTemplate::TX_EXTRA_NONCE_OFFSET) != extraNonceOffset) {
        return fail("Mutated block template failed validation.");
    }

    const String hashingBlob = Cvt::toHex(mutated.generateHashingBlob());
    const std::string clientIdText = std::to_string(m_id);
    Job job(false, m_pool.algorithm(), String(clientIdText.c_str()));

    const size_t prefix = mutated.offset(BlockTemplate::MINER_TX_PREFIX_OFFSET);
    job.setMinerTx(
        mutated.blob() + prefix,
        mutated.blob() + mutated.offset(BlockTemplate::MINER_TX_PREFIX_END_OFFSET),
        mutated.offset(BlockTemplate::EPH_PUBLIC_KEY_OFFSET) - prefix,
        mutated.offset(BlockTemplate::TX_PUBKEY_OFFSET) - prefix,
        mutated.offset(BlockTemplate::TX_EXTRA_NONCE_OFFSET) - prefix,
        mutated.txExtraNonce().size(),
        mutated.minerTxMerkleTreeBranch(),
        mutated.minerTxMerkleTreePath(),
        mutated.outputType() == 3
    );

    const char *spendKeyError = nullptr;
    if (!prepareSpendKey(job, mutated, &spendKeyError)) {
        return fail(spendKeyError);
    }

    if (m_coin.isValid()) {
        job.setAlgorithm(m_coin.algorithm(mutated.majorVersion()));
    }

    if (!job.setBlob(hashingBlob)) {
        return fail("Generated hashing blob is invalid.");
    }

    if (!job.setSeedHash(snapshot->seedHash)) {
        return fail("Daemon template has an invalid seed hash.");
    }

    job.setHeight(snapshot->height);
    job.setDiff(snapshot->difficulty);

    String jobId;
    for (size_t attempt = 0; attempt < 4; ++attempt) {
        Buffer id;
        if (!SecureRandom::bytes(kEntropySize, id)) {
            return fail("OS CSPRNG failed while generating a private job id.");
        }

        jobId = Cvt::toHex(id);
        if (!findContext(jobId)) {
            break;
        }
        jobId = nullptr;
    }

    if (jobId.isEmpty() || !job.setId(jobId)) {
        return fail("Unable to allocate a collision-free private job id.");
    }

    job.setTemplateMetadata(snapshot->sourceId, snapshot->generation, snapshot->fetchedSteadyMs,
                            entropyHex, snapshot->prevHash);

    JobContext context;
    context.blocktemplate      = blocktemplate;
    context.entropy            = entropyHex;
    context.hashingBlob        = hashingBlob;
    context.jobId              = jobId;
    context.prevHash           = snapshot->prevHash;
    context.seedHash           = snapshot->seedHash;
    context.hasMinerSignature  = mutated.hasMinerSignature();
    context.hasViewTag         = mutated.outputType() == 3;
    context.ephPublicKeyOffset = mutated.offset(BlockTemplate::EPH_PUBLIC_KEY_OFFSET);
    context.extraNonceOffset   = extraNonceOffset;
    context.nonceOffset        = job.nonceOffset();
    context.nonceSize          = job.nonceSize();
    context.signatureOffset    = job.nonceOffset() + job.nonceSize();
    context.txPublicKeyOffset  = mutated.offset(BlockTemplate::TX_PUBKEY_OFFSET);
    context.createdSteadyMs    = Chrono::steadyMSecs();
    context.difficulty         = snapshot->difficulty;
    context.generation         = snapshot->generation;
    context.height             = snapshot->height;
    context.sourceId           = snapshot->sourceId;

    LiveEventStream::Row telemetry("template_derived");
    telemetry.sourceId          = snapshot->sourceId;
    telemetry.templateId        = std::to_string(snapshot->generation);
    telemetry.height            = snapshot->height;
    telemetry.prevHash          = snapshot->prevHash.data() ? snapshot->prevHash.data() : "";
    telemetry.seedHash          = snapshot->seedHash.data() ? snapshot->seedHash.data() : "";
    telemetry.previousSeedHash  = snapshot->previousSeedHash.data() ? snapshot->previousSeedHash.data() : "";
    telemetry.nextSeedHash      = snapshot->nextSeedHash.data() ? snapshot->nextSeedHash.data() : "";
    telemetry.algorithm         = job.algorithm().name();
    telemetry.jobId             = jobId.data() ? jobId.data() : "";
    telemetry.entropyHex        = entropyHex.data() ? entropyHex.data() : "";
    telemetry.networkTargetDiff = snapshot->difficulty;
    telemetry.hashingBlob       = hashingBlob.data() ? hashingBlob.data() : "";
    // The shared template_cached row already carries the original full
    // template. reserved_offset + this job's entropy reconstruct the private
    // template without repeating a potentially large blob for every miner.
    telemetry.nonceOffset       = job.nonceOffset();
    telemetry.nonceSize         = job.nonceSize();
    telemetry.reservedOffset    = snapshot->reservedOffset;
    telemetry.reservedSize      = snapshot->reserveSize;
    telemetry.extraNonceOffset  = extraNonceOffset;
    telemetry.status            = "derived";
    LiveEventStream::publish(telemetry);

    m_contexts.push_front(std::move(context));
    trimContexts();
    m_job = std::move(job);
    m_ip  = snapshot->ip;

#   ifdef XMRIG_FEATURE_TLS
    m_tlsFingerprint = snapshot->tlsFingerprint;
    m_tlsVersion     = snapshot->tlsVersion;
#   endif

    if (m_state == ConnectingState) {
        setState(ConnectedState);
    }

    rapidjson::Value params(rapidjson::kNullType);
    m_listener->onJobReceived(this, m_job, params);
    return true;
}


const DaemonClient::JobContext *DaemonClient::findContext(const String &jobId) const
{
    for (const JobContext &context : m_contexts) {
        if (context.jobId == jobId) {
            return &context;
        }
    }

    return nullptr;
}


void DaemonClient::trimContexts()
{
    const uint64_t now = Chrono::steadyMSecs();
    while (m_contexts.size() > kJobHistorySize) {
        m_contexts.pop_back();
    }

    while (m_contexts.size() > 1 && now >= m_contexts.back().createdSteadyMs + kJobHistoryMs) {
        m_contexts.pop_back();
    }
}


int64_t DaemonClient::submit(const JobResult &result)
{
    trimContexts();
    const JobContext *context = findContext(result.jobId);
    if (!context || !result.nonce || strlen(result.nonce) != 8) {
        return -1;
    }

    String blocktemplate(context->blocktemplate);
    char *data = blocktemplate.data();
    memcpy(data + context->nonceOffset * 2, result.nonce, 8);

    if (context->hasMinerSignature) {
        if (!result.sig || strlen(result.sig) != BlockTemplate::kSignatureSize * 2 ||
            !result.sig_data || strlen(result.sig_data) < BlockTemplate::kKeySize * 4) {
            return -1;
        }

        memcpy(data + context->signatureOffset * 2, result.sig, BlockTemplate::kSignatureSize * 2);
        memcpy(data + context->txPublicKeyOffset * 2, result.sig_data, BlockTemplate::kKeySize * 2);
        memcpy(data + context->ephPublicKeyOffset * 2,
               result.sig_data + BlockTemplate::kKeySize * 2,
               BlockTemplate::kKeySize * 2);

        if (context->hasViewTag) {
            Cvt::toHex(data + context->ephPublicKeyOffset * 2 + BlockTemplate::kKeySize * 2,
                       2, &result.view_tag, 1);
        }
    }

    if (result.extra_nonce >= 0) {
        Cvt::toHex(data + context->extraNonceOffset * 2, 8,
                   reinterpret_cast<const uint8_t *>(&result.extra_nonce), 4);
    }

    // Parse the exact finalized full block once more so its locally known
    // coinbase transaction hash can identify it during read-only daemon
    // reconciliation. The daemon's successful submit response or canonical
    // get_block response remains authoritative for the consensus block ID.
    BlockTemplate submitted;
    if (!submitted.parse(blocktemplate, m_coin)) {
        return -1;
    }

    using namespace rapidjson;
    Document doc(kObjectType);
    Value params(kArrayType);
    params.PushBack(blocktemplate.toJSON(), doc.GetAllocator());

    const int64_t requestId = m_sequence;
    JsonRequest::create(doc, requestId, "submitblock", params);

    PendingSubmission submission;
    submission.result = SubmitResult(
        requestId,
        context->difficulty,
        result.actualDiff(),
        result.id,
        0,
        result.shareId,
        result.jobId,
        context->generation,
        context->height,
        context->entropy,
        context->sourceId,
        result.minerDiff
    );
    submission.blockBlob        = blocktemplate;
    submission.attemptStartedMs = Chrono::steadyMSecs();
    m_pendingSubmissions[requestId] = std::move(submission);

    LiveEventStream::Row row("submit_block");
    row.sourceId         = context->sourceId;
    row.templateId       = std::to_string(context->generation);
    row.height           = context->height;
    row.prevHash         = context->prevHash.data() ? context->prevHash.data() : "";
    row.seedHash         = context->seedHash.data() ? context->seedHash.data() : "";
    row.jobId            = context->jobId.data() ? context->jobId.data() : "";
    row.entropyHex       = context->entropy.data() ? context->entropy.data() : "";
    row.minerTargetDiff  = result.minerDiff;
    row.networkTargetDiff = context->difficulty;
    row.shareDiff        = result.actualDiff();
    row.shareId          = result.shareId;
    row.minerRequestId   = result.id;
    row.daemonRequestId  = requestId;
    row.nonce            = result.nonce;
    row.resultHash       = result.result ? result.result : "";
    row.submittedBlockBlob = blocktemplate.data() ? blocktemplate.data() : "";
    row.nonceOffset      = context->nonceOffset;
    row.nonceSize        = context->nonceSize;
    row.extraNonceOffset = context->extraNonceOffset;
    if (result.extra_nonce >= 0) {
        row.extraNonce = result.extra_nonce;
    }
    row.signatureHex     = result.sig ? result.sig : "";
    if (context->hasViewTag) {
        row.viewTag = result.view_tag;
    }
    uint8_t minerTxHash[BlockTemplate::kHashSize];
    BlockTemplate::calculateMinerTxHash(
        submitted.blob(BlockTemplate::MINER_TX_PREFIX_OFFSET),
        submitted.blob(BlockTemplate::MINER_TX_PREFIX_END_OFFSET),
        minerTxHash);
    const String minerTxHashHex = Cvt::toHex(minerTxHash, sizeof(minerTxHash));
    row.minerTxHash = minerTxHashHex.data() ? minerTxHashHex.data() : "";
    m_pendingSubmissions[requestId].minerTxHash = minerTxHashHex;
    row.status           = "requested";
    LiveEventStream::publish(row);

    std::map<std::string, std::string> headers;
    headers.insert({"X-Hash-Difficulty", std::to_string(result.actualDiff())});

    return rpcSend(doc, headers, kHttpSubmit);
}


int64_t DaemonClient::rpcSend(const rapidjson::Document &doc,
                              const std::map<std::string, std::string> &headers,
                              int userType)
{
    const int64_t requestId = m_sequence++;
    FetchRequest req(HTTP_POST, m_pool.host(), m_pool.port(), kJsonRpc, doc, m_pool.isTLS(), isQuiet());
    req.fingerprint = m_pool.fingerprint();
    req.timeout = std::max<uint64_t>(5000, std::min<uint64_t>(m_pool.jobTimeout(), 60000));
    for (const auto &header : headers) {
        req.headers.insert(header);
    }

    // HttpClient stores the tag pointer for the life of the asynchronous
    // request, so it must not point into this DaemonClient's mutable string.
    fetch(kSubmitTag, std::move(req), m_httpListener, userType, static_cast<uint64_t>(requestId));
    return requestId;
}


void DaemonClient::onHttpData(const HttpData &data)
{
    if (data.userType != kHttpSubmit && data.userType != kHttpReconcile) {
        return;
    }

    if (data.status > 0) {
        m_ip = data.ip().c_str();
    }

#   ifdef XMRIG_FEATURE_TLS
    m_tlsVersion     = data.tlsVersion();
    m_tlsFingerprint = data.tlsFingerprint();
#   endif

    if (data.status != 200) {
        const std::string error = data.status < 0
            ? std::string("transport error: ") + uv_strerror(data.status)
            : std::string("HTTP ") + std::to_string(data.status);

        if (data.userType == kHttpSubmit) {
            onIndeterminateSubmit(static_cast<int64_t>(data.rpcId), error.c_str());
        }
        else {
            const std::string message = std::string("submitblock reconciliation unavailable: ") + error;
            retryOrFinalizeReconciliation(static_cast<int64_t>(data.rpcId),
                                           message.c_str());
        }
        return;
    }

    rapidjson::Document doc;
    if (doc.Parse(data.body.c_str()).HasParseError()) {
        const std::string error = std::string("JSON decode failed: ") + rapidjson::GetParseError_En(doc.GetParseError());
        if (data.userType == kHttpSubmit) {
            onIndeterminateSubmit(static_cast<int64_t>(data.rpcId), error.c_str());
        }
        else {
            const std::string message = std::string("submitblock reconciliation unavailable: ") + error;
            retryOrFinalizeReconciliation(static_cast<int64_t>(data.rpcId),
                                           message.c_str());
        }
        return;
    }

    const int64_t responseId = Json::getInt64(doc, "id", -1);
    if (responseId != static_cast<int64_t>(data.rpcId)) {
        const char *message = data.userType == kHttpSubmit
            ? "Mismatched submitblock response id"
            : "submitblock reconciliation returned a mismatched response id";
        if (data.userType == kHttpSubmit) {
            onIndeterminateSubmit(static_cast<int64_t>(data.rpcId), message);
        }
        else {
            retryOrFinalizeReconciliation(static_cast<int64_t>(data.rpcId), message);
        }
        return;
    }

    if (data.userType == kHttpSubmit) {
        parseSubmitResponse(static_cast<int64_t>(data.rpcId),
                            Json::getObject(doc, "result"), Json::getObject(doc, "error"));
    }
    else {
        parseReconcileResponse(static_cast<int64_t>(data.rpcId),
                               Json::getObject(doc, "result"), Json::getObject(doc, "error"));
    }
}


bool DaemonClient::parseSubmitResponse(int64_t id, const rapidjson::Value &result, const rapidjson::Value &error)
{
    auto it = m_pendingSubmissions.find(id);
    if (it == m_pendingSubmissions.end()) {
        return false;
    }

    // JSON-RPC defines result and error as mutually exclusive. If a malformed
    // response contains both, never let an embedded status=OK override the
    // daemon's explicit error object.
    if (error.IsObject()) {
        std::string errorMessage;
        if (!jsonString(error, "message", errorMessage)) {
            return onIndeterminateSubmit(id, "Missing, invalid, or embedded-NUL submitblock error message");
        }
        return finalizeSubmission(id, SubmitResult::Outcome::Rejected,
                                  errorMessage.c_str(), Json::getInt64(error, "code", 0));
    }

    const DaemonReconciliation::SubmitDecision decision =
        DaemonReconciliation::classifySubmitResult(result);

    // status=OK is the daemon's authoritative acceptance decision. A valid
    // returned block_id is canonical even if any local diagnostic disagrees.
    // Older daemons may omit it; that still completes immediately as accepted,
    // with the locally calculated miner transaction hash retained as evidence.
    if (decision.outcome == DaemonReconciliation::SubmitDecision::Outcome::Accepted) {
        return finalizeSubmission(id, SubmitResult::Outcome::Accepted,
                                  decision.reason.empty() ? nullptr : decision.reason.c_str(),
                                  0,
                                  decision.blockId.empty() ? nullptr : decision.blockId.c_str());
    }

    if (decision.outcome == DaemonReconciliation::SubmitDecision::Outcome::Rejected) {
        return finalizeSubmission(id, SubmitResult::Outcome::Rejected,
                                  decision.reason.c_str());
    }

    return onIndeterminateSubmit(id, decision.reason.c_str());
}


bool DaemonClient::onIndeterminateSubmit(int64_t id, const char *message)
{
    auto it = m_pendingSubmissions.find(id);
    if (it == m_pendingSubmissions.end()) {
        return false;
    }

    return startReconciliation(id,
        message ? message : "indeterminate submitblock response") >= 0;
}


int64_t DaemonClient::startReconciliation(int64_t id, const char *reason)
{
    auto it = m_pendingSubmissions.find(id);
    if (it == m_pendingSubmissions.end()) {
        return -1;
    }

    if (it->second.lastIndeterminateError.empty()) {
        it->second.lastIndeterminateError = reason
            ? reason
            : "indeterminate submitblock response";
    }

    return beginReconciliationAttempt(id);
}


int64_t DaemonClient::beginReconciliationAttempt(int64_t id)
{
    auto it = m_pendingSubmissions.find(id);
    if (it == m_pendingSubmissions.end() ||
        !DaemonReconciliation::hasRemainingAttempts(it->second.reconcileAttempts)) {
        return -1;
    }

    PendingSubmission submission(std::move(it->second));
    m_pendingSubmissions.erase(it);

    using namespace rapidjson;
    Document doc(kObjectType);
    Value params(kObjectType);
    params.AddMember("height", Value().SetUint64(submission.result.height),
                     doc.GetAllocator());
    params.AddMember("hash", Value("", doc.GetAllocator()), doc.GetAllocator());

    const int64_t requestId = m_sequence;
    JsonRequest::create(doc, requestId, "get_block", params);
    submission.reconcileAttempts++;
    submission.reconcileDueMs = 0;
    submission.attemptStartedMs = Chrono::steadyMSecs();
    m_pendingSubmissions[requestId] = std::move(submission);

    PendingSubmission &pending = m_pendingSubmissions[requestId];
    std::string message = "canonical get_block attempt ";
    message += std::to_string(pending.reconcileAttempts);
    message += " of ";
    message += std::to_string(DaemonReconciliation::kMaxAttempts);
    message += " at submitted height ";
    message += std::to_string(pending.result.height);
    message += " using miner_tx_hash ";
    message += pending.minerTxHash.data() ? pending.minerTxHash.data() : "";
    message += "; original submit outcome: ";
    message += pending.lastIndeterminateError;
    publishSubmissionRow("submit_block_reconcile", pending, requestId, "requested",
                         message.c_str());

    return rpcSend(doc, {}, kHttpReconcile);
}


bool DaemonClient::retryOrFinalizeReconciliation(int64_t id, const char *reason)
{
    auto it = m_pendingSubmissions.find(id);
    if (it == m_pendingSubmissions.end()) {
        return false;
    }

    PendingSubmission &pending = it->second;
    pending.lastReconcileError = reason ? reason : "canonical block lookup failed";
    if (DaemonReconciliation::hasRemainingAttempts(pending.reconcileAttempts)) {
        pending.reconcileDueMs = DaemonReconciliation::nextAttemptAt(
            Chrono::steadyMSecs());

        std::string message = "canonical get_block attempt ";
        message += std::to_string(pending.reconcileAttempts);
        message += " did not identify the submitted block; attempt ";
        message += std::to_string(pending.reconcileAttempts + 1);
        message += " is scheduled in ";
        message += std::to_string(DaemonReconciliation::kRetryDelayMs);
        message += " ms: ";
        message += pending.lastReconcileError;
        publishSubmissionRow("submit_block_reconcile", pending, id,
                             "retry_scheduled", message.c_str());
        return true;
    }

    std::string message = "submitblock outcome remains ambiguous after ";
    message += std::to_string(DaemonReconciliation::kMaxAttempts);
    message += " canonical get_block attempts; last lookup: ";
    message += pending.lastReconcileError;

    return finalizeSubmission(id, SubmitResult::Outcome::Ambiguous,
                              message.c_str(), 0, nullptr, true);
}


bool DaemonClient::parseReconcileResponse(int64_t id, const rapidjson::Value &result,
                                          const rapidjson::Value &error)
{
    auto it = m_pendingSubmissions.find(id);
    if (it == m_pendingSubmissions.end()) {
        return false;
    }

    if (error.IsObject()) {
        std::string rpcMessage;
        if (!jsonString(error, "message", rpcMessage)) {
            return retryOrFinalizeReconciliation(id,
                "malformed get_block JSON-RPC error");
        }

        std::string message = "get_block JSON-RPC error: ";
        message += rpcMessage;
        return retryOrFinalizeReconciliation(id, message.c_str());
    }

    const DaemonReconciliation::Match match =
        DaemonReconciliation::matchCanonicalBlock(
            result,
            it->second.result.height,
            it->second.minerTxHash.data(),
            it->second.blockBlob.data());
    if (match.accepted) {
        std::string message = "accepted after exact canonical get_block reconciliation; earlier response: ";
        message += it->second.lastIndeterminateError;
        return finalizeSubmission(id, SubmitResult::Outcome::Accepted, message.c_str(),
                                  0, match.blockId.c_str(), true);
    }

    return retryOrFinalizeReconciliation(id, match.reason.c_str());
}


void DaemonClient::publishSubmissionRow(const char *event, const PendingSubmission &submission,
                                        int64_t requestId, const char *status, const char *message,
                                        int64_t errorCode, const char *blockId,
                                        bool includeBlockBlob) const
{
    LiveEventStream::Row row(event);
    if (submission.result.templateSourceId) {
        row.sourceId = submission.result.templateSourceId;
    }
    if (submission.result.templateGeneration) {
        row.templateId = std::to_string(submission.result.templateGeneration);
    }
    if (submission.result.height) {
        row.height = submission.result.height;
    }
    row.jobId             = submission.result.jobId.data() ? submission.result.jobId.data() : "";
    row.entropyHex        = submission.result.entropy.data() ? submission.result.entropy.data() : "";
    row.minerTargetDiff   = submission.result.minerDiff;
    row.networkTargetDiff = submission.result.diff;
    row.shareDiff         = submission.result.actualDiff;
    if (submission.result.shareId) {
        row.shareId = submission.result.shareId;
    }
    row.minerRequestId  = submission.result.reqId;
    row.daemonRequestId = requestId;
    const uint64_t now = Chrono::steadyMSecs();
    const bool final = event && strcmp(event, "submit_block_result") == 0;
    const uint64_t started = final ? submission.result.startTime() : submission.attemptStartedMs;
    row.latencyMs = now >= started ? now - started : 0;
    row.status    = status ? status : "";
    if (errorCode) {
        row.errorCode = errorCode;
    }
    row.errorMessage = message ? message : "";
    row.blockId = blockId ? blockId : "";
    row.minerTxHash = submission.minerTxHash.data() ? submission.minerTxHash.data() : "";
    if (includeBlockBlob) {
        row.submittedBlockBlob = submission.blockBlob.data() ? submission.blockBlob.data() : "";
    }
    LiveEventStream::publish(row);
}


bool DaemonClient::finalizeSubmission(int64_t id, SubmitResult::Outcome outcome,
                                      const char *message, int64_t errorCode,
                                      const char *blockId, bool reconciled)
{
    auto it = m_pendingSubmissions.find(id);
    if (it == m_pendingSubmissions.end()) {
        return false;
    }

    PendingSubmission submission(std::move(it->second));
    m_pendingSubmissions.erase(it);
    submission.result.outcome = outcome;

    std::string telemetryMessage;
    if (message) {
        telemetryMessage = message;
    }
    if (reconciled && outcome == SubmitResult::Outcome::Rejected && telemetryMessage.empty()) {
        telemetryMessage = "reconciled as rejected";
    }

    const char *status = "ambiguous";
    if (outcome == SubmitResult::Outcome::Accepted) {
        status = "accepted";
    }
    else if (outcome == SubmitResult::Outcome::Rejected) {
        status = "rejected";
    }

    publishSubmissionRow("submit_block_result", submission, id, status,
                         telemetryMessage.empty() ? nullptr : telemetryMessage.c_str(),
                         errorCode, blockId, true);

    m_results[id] = std::move(submission.result);
    const char *minerError = outcome == SubmitResult::Outcome::Accepted
        ? nullptr
        : (message ? message : "submitblock outcome ambiguous");

    return handleSubmitResponse(id, minerError);
}


void DaemonClient::setState(SocketState state)
{
    if (m_state == state) {
        return;
    }

    m_state = state;
    if (state == ConnectedState) {
        m_failures = 0;
        m_listener->onLoginSuccess(this);
    }
    else if (state == UnconnectedState) {
        m_failures = -1;
    }
}


} /* namespace xmrig */
