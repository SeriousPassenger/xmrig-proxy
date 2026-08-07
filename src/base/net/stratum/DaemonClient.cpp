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
#include "base/net/stratum/SubmitResult.h"
#include "base/tools/Chrono.h"
#include "base/tools/cryptonote/BlockTemplate.h"
#include "base/tools/cryptonote/Signatures.h"
#include "base/tools/Cvt.h"
#include "base/tools/SecureRandom.h"
#include "net/JobResult.h"
#include "proxy/live/LiveEventStream.h"


#include <algorithm>
#include <cstring>
#include <string>


namespace xmrig {


namespace {


static const char *kJsonRpc = "/json_rpc";
static const char *kSubmitTag = "daemon-submit";
static constexpr size_t kEntropySize = 16;
static constexpr size_t kJobHistorySize = 6;
static constexpr uint64_t kJobHistoryMs = 120000;
static const int kHttpSubmit = 0x445403;


} // namespace


DaemonClient::DaemonClient(int id, IClientListener *listener) :
    BaseClient(id, listener),
    m_httpListener(std::make_shared<HttpListener>(this))
{
}


DaemonClient::~DaemonClient()
{
    disconnect();
}


void DaemonClient::deleteLater()
{
    delete this;
}


bool DaemonClient::disconnect()
{
    if (m_source) {
        m_source->unsubscribe(this);
        m_source.reset();
    }

    m_contexts.clear();
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

    if (!installTemplate(snapshot) && !isQuiet()) {
        LOG_ERR("%s " RED("job error: ") RED_BOLD("\"Unable to derive private 16-byte template job.\""), tag());
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

    job.setTemplateMetadata(snapshot->sourceId, snapshot->generation, snapshot->fetchedSteadyMs, entropyHex);

    JobContext context;
    context.blocktemplate      = blocktemplate;
    context.entropy            = entropyHex;
    context.jobId              = jobId;
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

    using namespace rapidjson;
    Document doc(kObjectType);
    Value params(kArrayType);
    params.PushBack(blocktemplate.toJSON(), doc.GetAllocator());

    const int64_t requestId = m_sequence;
    JsonRequest::create(doc, requestId, "submitblock", params);

    m_results[requestId] = SubmitResult(
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
        context->sourceId
    );

    LiveEventStream::Row row("submit_block");
    row.sourceId         = context->sourceId;
    row.templateId       = std::to_string(context->generation);
    row.height           = context->height;
    row.jobId            = context->jobId.data() ? context->jobId.data() : "";
    row.entropyHex       = context->entropy.data() ? context->entropy.data() : "";
    row.networkTargetDiff = context->difficulty;
    row.shareDiff        = result.actualDiff();
    row.shareId          = result.shareId;
    row.minerRequestId   = result.id;
    row.daemonRequestId  = requestId;
    row.nonce            = result.nonce;
    row.resultHash       = result.result ? result.result : "";
    row.status           = "requested";
    LiveEventStream::publish(row);

    std::map<std::string, std::string> headers;
    headers.insert({"X-Hash-Difficulty", std::to_string(result.actualDiff())});

    return rpcSend(doc, headers);
}


int64_t DaemonClient::rpcSend(const rapidjson::Document &doc, const std::map<std::string, std::string> &headers)
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
    fetch(kSubmitTag, std::move(req), m_httpListener, kHttpSubmit, static_cast<uint64_t>(requestId));
    return requestId;
}


void DaemonClient::onHttpData(const HttpData &data)
{
    if (data.userType != kHttpSubmit) {
        return;
    }

    m_ip = data.ip().c_str();

#   ifdef XMRIG_FEATURE_TLS
    m_tlsVersion     = data.tlsVersion();
    m_tlsFingerprint = data.tlsFingerprint();
#   endif

    if (data.status != 200) {
        const std::string error = std::string("HTTP ") + std::to_string(data.status);
        rapidjson::Value empty(rapidjson::kNullType);
        rapidjson::Document doc(rapidjson::kObjectType);
        auto &allocator = doc.GetAllocator();
        rapidjson::Value rpcError(rapidjson::kObjectType);
        rpcError.AddMember("message", rapidjson::Value(error.c_str(), allocator), allocator);
        parseSubmitResponse(static_cast<int64_t>(data.rpcId), empty, rpcError);
        return;
    }

    rapidjson::Document doc;
    if (doc.Parse(data.body.c_str()).HasParseError()) {
        const std::string error = std::string("JSON decode failed: ") + rapidjson::GetParseError_En(doc.GetParseError());
        rapidjson::Document synthetic(rapidjson::kObjectType);
        auto &allocator = synthetic.GetAllocator();
        rapidjson::Value rpcError(rapidjson::kObjectType);
        rpcError.AddMember("message", rapidjson::Value(error.c_str(), allocator), allocator);
        rapidjson::Value empty(rapidjson::kNullType);
        parseSubmitResponse(static_cast<int64_t>(data.rpcId), empty, rpcError);
        return;
    }

    const int64_t responseId = Json::getInt64(doc, "id", -1);
    if (responseId != static_cast<int64_t>(data.rpcId)) {
        rapidjson::Document synthetic(rapidjson::kObjectType);
        auto &allocator = synthetic.GetAllocator();
        rapidjson::Value rpcError(rapidjson::kObjectType);
        rpcError.AddMember("message", "Mismatched submitblock response id", allocator);
        rapidjson::Value empty(rapidjson::kNullType);
        parseSubmitResponse(static_cast<int64_t>(data.rpcId), empty, rpcError);
        return;
    }

    parseSubmitResponse(static_cast<int64_t>(data.rpcId),
                        Json::getObject(doc, "result"), Json::getObject(doc, "error"));
}


bool DaemonClient::parseSubmitResponse(int64_t id, const rapidjson::Value &result, const rapidjson::Value &error)
{
    auto it = m_results.find(id);
    if (it == m_results.end()) {
        return false;
    }

    std::string errorMessage;
    const char *message = nullptr;
    int64_t errorCode = 0;

    if (error.IsObject()) {
        errorMessage = Json::getString(error, "message", "submitblock RPC error");
        message = errorMessage.c_str();
        errorCode = Json::getInt64(error, "code", 0);
    }
    else if (!result.IsObject()) {
        message = "Invalid submitblock response";
    }
    else {
        const char *status = Json::getString(result, "status");
        if (!status || strcmp(status, "OK") != 0) {
            errorMessage = "submitblock status: ";
            errorMessage += status ? status : "missing";
            message = errorMessage.c_str();
        }
        else {
            const char *blockId = Json::getString(result, "block_id");
            uint8_t blockHash[32];
            if (!blockId || strlen(blockId) != sizeof(blockHash) * 2 ||
                !Cvt::fromHex(blockHash, sizeof(blockHash), blockId, sizeof(blockHash) * 2)) {
                message = "Invalid submitblock block_id";
            }
        }
    }

    const SubmitResult &submission = it->second;
    LiveEventStream::Row row("submit_block_result");
    if (submission.templateSourceId) {
        row.sourceId = submission.templateSourceId;
    }
    if (submission.templateGeneration) {
        row.templateId = std::to_string(submission.templateGeneration);
    }
    if (submission.height) {
        row.height = submission.height;
    }
    row.jobId             = submission.jobId.data() ? submission.jobId.data() : "";
    row.entropyHex        = submission.entropy.data() ? submission.entropy.data() : "";
    row.networkTargetDiff = submission.diff;
    row.shareDiff         = submission.actualDiff;
    if (submission.shareId) {
        row.shareId = submission.shareId;
    }
    row.minerRequestId  = submission.reqId;
    row.daemonRequestId = submission.seq;
    row.latencyMs       = Chrono::steadyMSecs() >= submission.startTime()
        ? Chrono::steadyMSecs() - submission.startTime() : 0;
    row.status          = message ? "rejected" : "accepted";
    if (errorCode) {
        row.errorCode = errorCode;
    }
    row.errorMessage = message ? message : "";
    LiveEventStream::publish(row);

    handleSubmitResponse(id, message);
    return true;
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
