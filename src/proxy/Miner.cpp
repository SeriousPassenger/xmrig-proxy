/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018-2025 SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2025 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "proxy/Miner.h"
#include "3rdparty/rapidjson/document.h"
#include "3rdparty/rapidjson/error/en.h"
#include "3rdparty/rapidjson/stringbuffer.h"
#include "3rdparty/rapidjson/writer.h"
#include "base/io/json/Json.h"
#include "base/io/log/Log.h"
#include "base/net/stratum/Job.h"
#include "base/net/tools/NetBuffer.h"
#include "base/tools/Cvt.h"
#include "base/tools/Chrono.h"
#include "net/JobResult.h"
#include "proxy/Counters.h"
#include "proxy/Error.h"
#include "proxy/events/AcceptEvent.h"
#include "proxy/events/CloseEvent.h"
#include "proxy/events/LoginEvent.h"
#include "proxy/events/SubmitEvent.h"
#include "proxy/live/LiveEventStream.h"


#ifdef XMRIG_FEATURE_TLS
#   include "base/net/tls/TlsContext.h"
#   include "proxy/tls/MinerTls.h"
#   include <openssl/bio.h>
#endif


#include <cinttypes>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>


namespace xmrig {


static uint64_t s_shareSequence = 0;
static int64_t nextId = 0;
char Miner::m_sendBuf[16384] = { 0 };
Storage<Miner> Miner::m_storage;
} // namespace xmrig


xmrig::Miner::Miner(const TlsContext *ctx, uint16_t port, bool strictTls) :
    m_strictTls(strictTls),
    m_rpcId(Cvt::toHex(Cvt::randomBytes(8))),
    m_tlsCtx(ctx),
    m_id(++nextId),
    m_localPort(port),
    m_expire(Chrono::steadyMSecs() + kLoginTimeout),
    m_timestamp(Chrono::currentMSecsSinceEpoch())
{
    m_reader.setListener(this);
    m_key = m_storage.add(this);

    m_socket = new uv_tcp_t;
    m_socket->data = m_storage.ptr(m_key);
    uv_tcp_init(uv_default_loop(), m_socket);

    Counters::connections++;
}


xmrig::Miner::~Miner()
{
    GlobalShareCache::removeOwner(m_key);

    if (RandomXVerifier::instance()) {
        RandomXVerifier::instance()->cancelOwner(m_key);
    }

    if (uv_is_closing(reinterpret_cast<uv_handle_t *>(m_socket))) {
        delete m_socket;
    }
    else {
        uv_close(reinterpret_cast<uv_handle_t *>(m_socket), [](uv_handle_t *handle) { delete reinterpret_cast<uv_tcp_t *>(handle); });
    }

#   ifdef XMRIG_FEATURE_TLS
    delete m_tls;
#   endif

    Counters::connections--;
}


bool xmrig::Miner::accept(uv_stream_t *server)
{
    const int rt = uv_accept(server, reinterpret_cast<uv_stream_t*>(m_socket));
    if (rt < 0) {
        LOG_ERR("[miner] accept error: \"%s\"", uv_strerror(rt));
        return false;
    }

    sockaddr_storage addr = {};
    int size = sizeof(addr);

    uv_tcp_getpeername(m_socket, reinterpret_cast<sockaddr*>(&addr), &size);

    if (reinterpret_cast<sockaddr_in *>(&addr)->sin_family == AF_INET6) {
        uv_ip6_name(reinterpret_cast<sockaddr_in6*>(&addr), m_ip, 45);
    } else {
        uv_ip4_name(reinterpret_cast<sockaddr_in*>(&addr), m_ip, 16);
    }

    uv_read_start(reinterpret_cast<uv_stream_t*>(m_socket), NetBuffer::onAlloc, Miner::onRead);

    return true;
}


void xmrig::Miner::forwardJob(const Job &job, const char *algo)
{
    m_diff = job.diff();
    m_issuedDiff         = job.diff();
    m_currentJobId       = job.id();
    m_currentJobEntropy  = job.templateEntropy();
    m_templateGeneration = job.templateGeneration();
    m_signatureData      = job.rawSigKey();
    m_viewTag            = 0;
    m_extraNonce         = -1;
    setFixedByte(job.fixedByte());

    if (!sendJob(job.rawBlob(), job.id().data(), job.rawTarget(), algo ? algo : job.algorithm().name(), job.height(), job.rawSeedHash(), job.rawSigKey())) {
        return;
    }

    m_jobHeight = job.height();
    rememberJob(job, job.rawBlob(), m_issuedDiff);

    LiveEventStream::Row row("job_sent");
    if (job.templateSourceId()) {
        row.sourceId = job.templateSourceId();
    }
    row.minerId            = m_id;
    row.mapperId           = m_mapperId;
    row.minerIp            = m_ip;
    row.listenPort         = m_localPort;
    row.worker             = m_rigId.size() ? m_rigId.data() : (m_user.data() ? m_user.data() : "");
    row.agent              = m_agent.data() ? m_agent.data() : "";
    if (job.templateGeneration()) {
        row.templateId = std::to_string(job.templateGeneration());
    }
    if (job.templateFetchedMs() && Chrono::steadyMSecs() >= job.templateFetchedMs()) {
        row.templateAgeMs = Chrono::steadyMSecs() - job.templateFetchedMs();
    }
    row.height             = job.height();
    row.prevHash           = job.templatePrevHash().data() ? job.templatePrevHash().data() : "";
    row.seedHash           = job.rawSeedHash().data() ? job.rawSeedHash().data() : "";
    row.algorithm          = algo ? algo : job.algorithm().name();
    row.jobId              = job.id().data() ? job.id().data() : "";
    row.entropyHex         = job.templateEntropy().data() ? job.templateEntropy().data() : "";
    row.minerTargetDiff    = diff();
    row.networkTargetDiff  = job.diff();
    row.hashingBlob        = job.rawBlob() ? job.rawBlob() : "";
    row.minerTargetHex     = job.rawTarget() ? job.rawTarget() : "";
    row.nonceOffset        = job.nonceOffset();
    row.nonceSize          = job.nonceSize();
    row.status             = "sent";
    LiveEventStream::publish(row);
}


void xmrig::Miner::replyWithError(int64_t id, const char *message)
{
    send(snprintf(m_sendBuf, sizeof(m_sendBuf), "{\"id\":%" PRId64 ",\"jsonrpc\":\"2.0\",\"error\":{\"code\":-1,\"message\":\"%s\"}}\n", id, message));
}


void xmrig::Miner::setJob(Job &job, int64_t extra_nonce)
{
    using namespace rapidjson;

    if (hasExtension(EXT_NICEHASH)) {
        snprintf(m_sendBuf, 4, "%02hhx", m_fixedByte);
        memcpy(job.rawBlob() + (job.nonceOffset() + 3) * 2, m_sendBuf, 2);
    }

    m_diff = job.diff();
    m_issuedDiff         = job.diff();
    m_currentJobId       = job.id();
    m_currentJobEntropy  = job.templateEntropy();
    m_templateGeneration = job.templateGeneration();
    m_signatureData      = nullptr;
    m_viewTag            = 0;
    m_extraNonce         = extra_nonce;
    bool customDiff = false;

    if (m_customDiff && m_customDiff < m_diff) {
        const uint64_t t = 0xFFFFFFFFFFFFFFFFULL / m_customDiff;
        Cvt::toHex(m_sendBuf, 9, reinterpret_cast<const uint8_t *>(&t) + 4, 4);
        const uint32_t compactTarget = static_cast<uint32_t>(t >> 32);
        if (compactTarget != 0) {
            const uint64_t expandedTarget = 0xFFFFFFFFFFFFFFFFULL /
                (0xFFFFFFFFULL / static_cast<uint64_t>(compactTarget));
            m_issuedDiff = Job::toDiff(expandedTarget);
        }
        customDiff = true;
    }

    const char* blob = job.rawBlob();
    String tmp_blob;

    if (job.hasMinerSignature()) {
        job.generateSignatureData(m_signatureData, m_viewTag);
    }
    else if (!job.rawSigKey().isNull()) {
        m_signatureData = job.rawSigKey();
    }

    if (job.hasViewTag()) {
        job.setViewTagInMinerTx(m_viewTag);
    }

    if (extra_nonce >= 0) {
        job.setExtraNonceInMinerTx(static_cast<uint32_t>(m_extraNonce));
    }

    if (job.hasMinerSignature() || (extra_nonce >= 0)) {
        job.generateHashingBlob(tmp_blob);
        blob = tmp_blob;
    }

    const std::string minerTargetHex = customDiff ? m_sendBuf : job.rawTarget();
    if (!sendJob(blob, job.id().data(), minerTargetHex.c_str(), job.algorithm().name(), job.height(), job.rawSeedHash(), m_signatureData)) {
        return;
    }

    m_jobHeight = job.height();
    rememberJob(job, blob, m_issuedDiff);

    LiveEventStream::Row row("job_sent");
    if (job.templateSourceId()) {
        row.sourceId = job.templateSourceId();
    }
    row.minerId            = m_id;
    row.mapperId           = m_mapperId;
    row.minerIp            = m_ip;
    row.listenPort         = m_localPort;
    row.worker             = m_rigId.size() ? m_rigId.data() : (m_user.data() ? m_user.data() : "");
    row.agent              = m_agent.data() ? m_agent.data() : "";
    if (job.templateGeneration()) {
        row.templateId = std::to_string(job.templateGeneration());
    }
    if (job.templateFetchedMs() && Chrono::steadyMSecs() >= job.templateFetchedMs()) {
        row.templateAgeMs = Chrono::steadyMSecs() - job.templateFetchedMs();
    }
    row.height             = job.height();
    row.prevHash           = job.templatePrevHash().data() ? job.templatePrevHash().data() : "";
    row.seedHash           = job.rawSeedHash().data() ? job.rawSeedHash().data() : "";
    row.algorithm          = job.algorithm().name();
    row.jobId              = job.id().data() ? job.id().data() : "";
    row.entropyHex         = job.templateEntropy().data() ? job.templateEntropy().data() : "";
    row.minerTargetDiff    = diff();
    row.networkTargetDiff  = job.diff();
    row.hashingBlob        = blob ? blob : "";
    row.minerTargetHex     = minerTargetHex;
    row.nonceOffset        = job.nonceOffset();
    row.nonceSize          = job.nonceSize();
    if (job.hasViewTag()) {
        row.viewTag = m_viewTag;
    }
    if (extra_nonce >= 0) {
        row.extraNonce = extra_nonce;
    }
    row.status             = "sent";
    LiveEventStream::publish(row);
}


void xmrig::Miner::success(int64_t id, const char *status)
{
    send(snprintf(m_sendBuf, sizeof(m_sendBuf), "{\"id\":%" PRId64 ",\"jsonrpc\":\"2.0\",\"error\":null,\"result\":{\"status\":\"%s\"}}\n", id, status));
}


bool xmrig::Miner::isWritable() const
{
    return m_state != ClosingState && uv_is_writable(reinterpret_cast<const uv_stream_t*>(m_socket)) == 1;
}


const xmrig::Miner::TelemetryJob *xmrig::Miner::findTelemetryJob(const String &id) const
{
    static constexpr uint64_t kTelemetryJobTtl = 120000;
    const uint64_t now = Chrono::steadyMSecs();

    if (!m_telemetryJobs.empty() && m_telemetryJobs.front().id == id &&
        now < m_telemetryJobs.front().issuedAt + kTelemetryJobTtl) {
        return &m_telemetryJobs.front();
    }

    auto it = m_telemetryJobs.begin();
    if (it != m_telemetryJobs.end()) {
        ++it;
    }

    for (; it != m_telemetryJobs.end(); ++it) {
        const TelemetryJob &job = *it;
        if (job.id == id && now < job.issuedAt + kTelemetryJobTtl) {
            return &job;
        }
    }

    return nullptr;
}


void xmrig::Miner::rememberJob(const Job &job, const char *hashingBlob, uint64_t issuedDiff)
{
    static constexpr size_t kTelemetryJobCount = 6;
    static constexpr uint64_t kTelemetryJobTtl = 120000;

    TelemetryJob telemetry;
    telemetry.algorithm          = job.algorithm();
    telemetry.entropy            = job.templateEntropy();
    telemetry.hashingBlob        = hashingBlob;
    telemetry.id                 = job.id();
    telemetry.prevHash           = job.templatePrevHash();
    telemetry.seedHash           = job.rawSeedHash();
    telemetry.signatureData      = m_signatureData;
    telemetry.height             = job.height();
    telemetry.issuedAt           = Chrono::steadyMSecs();
    telemetry.minerDiff          = issuedDiff;
    telemetry.networkDiff        = job.diff();
    telemetry.issuanceToken      = ++m_jobIssuanceSequence;
    telemetry.templateGeneration = job.templateGeneration();
    telemetry.templateSourceId   = job.templateSourceId();
    telemetry.nonceOffset        = job.nonceOffset();
    telemetry.viewTag            = m_viewTag;
    telemetry.extraNonce         = m_extraNonce;

    m_telemetryJobs.push_front(std::move(telemetry));
    while (m_telemetryJobs.size() > kTelemetryJobCount) {
        m_telemetryJobs.pop_back();
    }

    if (job.templateSourceId() != 0 && m_jobHeight != 0) {
        const uint64_t now = Chrono::steadyMSecs();
        std::vector<uint64_t> eligibleHeights;
        eligibleHeights.reserve(m_telemetryJobs.size());
        for (const TelemetryJob &retained : m_telemetryJobs) {
            if (retained.templateSourceId == job.templateSourceId() &&
                retained.height >= m_jobHeight &&
                now < retained.issuedAt + kTelemetryJobTtl) {
                eligibleHeights.push_back(retained.height);
            }
        }

        GlobalShareCache::setOwnerHeights(m_key, job.templateSourceId(), eligibleHeights);
    }
}


xmrig::GlobalShareCache::Result xmrig::Miner::rememberSubmission(const TelemetryJob &job,
                                                                  const char *jobId,
                                                                  const char *nonce,
                                                                  const char *resultHash,
                                                                  SubmissionReservation &reservation)
{
    static constexpr uint64_t kSubmissionTtl = 120000;
    static constexpr size_t kMaxRememberedSubmissions = 65536;

    reservation = {};
    if (!jobId || !nonce) {
        return GlobalShareCache::Result::Invalid;
    }

    if (job.templateSourceId != 0 && job.height != 0) {
        std::string shareKey;
        if (!GlobalShareCache::makeKey(job.entropy.data(), resultHash, shareKey)) {
            return GlobalShareCache::Result::Invalid;
        }

        return GlobalShareCache::reserve(job.templateSourceId, job.height,
                                         std::move(shareKey), reservation.global);
    }

    std::string key(jobId);
    key.push_back(':');
    key.append(nonce);
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    const uint64_t now = Chrono::steadyMSecs();
    while (!m_seenSubmissions.empty() &&
           (now >= m_seenSubmissions.front().seenAt + kSubmissionTtl ||
            m_seenSubmissions.size() >= kMaxRememberedSubmissions)) {
        const SeenSubmission &oldest = m_seenSubmissions.front();
        auto it = m_seenSubmissionTimes.find(oldest.key);
        if (it != m_seenSubmissionTimes.end() && it->second.token == oldest.token) {
            m_seenSubmissionTimes.erase(it);
        }
        m_seenSubmissions.pop_front();
    }

    auto existing = m_seenSubmissionTimes.find(key);
    if (existing != m_seenSubmissionTimes.end() && now < existing->second.seenAt + kSubmissionTtl) {
        return GlobalShareCache::Result::Duplicate;
    }

    SeenSubmission seen;
    seen.key = key;
    seen.seenAt = now;
    seen.token = ++m_submissionSequence;
    m_seenSubmissions.push_back(seen);
    SeenSubmissionStamp &stamp = m_seenSubmissionTimes[key];
    stamp.seenAt = now;
    stamp.token = seen.token;
    reservation.localKey = std::move(key);
    reservation.localToken = seen.token;
    return GlobalShareCache::Result::Accepted;
}


void xmrig::Miner::forgetSubmission(const SubmissionReservation &reservation)
{
    if (reservation.global.valid()) {
        GlobalShareCache::release(reservation.global);
    }

    if (reservation.computedGlobal.valid()) {
        GlobalShareCache::release(reservation.computedGlobal);
    }

    if (reservation.localKey.empty() || reservation.localToken == 0) {
        return;
    }

    const auto it = m_seenSubmissionTimes.find(reservation.localKey);
    if (it != m_seenSubmissionTimes.end() && it->second.token == reservation.localToken) {
        m_seenSubmissionTimes.erase(it);
    }
}


void xmrig::Miner::fillSubmitMetadata(SubmitEvent *event, const PendingShare &share) const
{
    if (!event) {
        return;
    }

    event->request.shareId = share.shareId;
    event->request.height = share.height;
    event->request.minerDiff = share.minerDiff;
    event->request.networkDiff = share.networkDiff;
    event->request.templateGeneration = share.templateGeneration;
    event->request.templateSourceId = share.templateSourceId;
    event->request.templateEntropy = share.entropy.c_str();
}


bool xmrig::Miner::startVerification(SubmitEvent *event, const TelemetryJob &job,
                                     const SubmissionReservation &submission,
                                     bool candidateFallback)
{
    RandomXVerifier *verifier = RandomXVerifier::instance();
    if (!event || !verifier || job.algorithm != Algorithm::RX_0 ||
        job.hashingBlob.isEmpty() || job.seedHash.size() != 64 ||
        job.nonceOffset * 2 + 8 > job.hashingBlob.size()) {
        return false;
    }

    auto share = std::make_shared<PendingShare>();
    share->algorithm = job.algorithm;
    share->mapperId = m_mapperId;
    share->requestId = event->request.id;
    share->extraNonce = event->request.extra_nonce;
    share->viewTag = event->request.view_tag;
    share->shareId = event->request.shareId;
    share->height = job.height;
    share->minerDiff = job.minerDiff;
    share->networkDiff = job.networkDiff;
    share->issuanceToken = job.issuanceToken;
    share->verificationGeneration = m_verificationGeneration;
    share->templateGeneration = job.templateGeneration;
    share->templateSourceId = job.templateSourceId;
    share->candidateFallback = candidateFallback;
    share->jobId = event->request.jobId.data() ? event->request.jobId.data() : "";
    share->nonce = event->request.nonce ? event->request.nonce : "";
    share->claimedHash = event->request.result ? event->request.result : "";
    share->hashingBlob = job.hashingBlob.data();
    share->prevHash = job.prevHash.data() ? job.prevHash.data() : "";
    share->seedHash = job.seedHash.data();
    share->signature = event->request.sig ? event->request.sig : "";
    share->signatureData = event->request.sig_data ? event->request.sig_data : "";
    share->commitment = event->request.commitment ? event->request.commitment : "";
    share->entropy = job.entropy.data() ? job.entropy.data() : "";
    share->submission = submission;
    memcpy(&share->hashingBlob[job.nonceOffset * 2], share->nonce.data(), 8);

    RandomXVerifier::Request request;
    request.owner = m_key;
    request.shareId = share->shareId;
    request.seedHash = share->seedHash;
    request.blob = share->hashingBlob;
    request.claimedHash = share->claimedHash;
    request.jobId = share->jobId;
    request.nonce = share->nonce;
    request.priority = candidateFallback;

    const uintptr_t key = m_key;
    const bool queued = verifier->verify(request, [key, share](const RandomXVerifier::Result &result) {
        if (!m_storage.contains(key)) {
            return;
        }

        Miner *miner = m_storage.get(key);
        if (miner) {
            miner->completeVerification(share, result);
        }
    });

    if (!queued) {
        return false;
    }

    recordInfrastructureOutcome(true);

    LiveEventStream::Row row("verify_requested");
    row.minerId = m_id;
    row.mapperId = m_mapperId;
    row.minerIp = m_ip;
    row.listenPort = m_localPort;
    row.worker = rigId(true).data() ? rigId(true).data() : "";
    row.agent = m_agent.data() ? m_agent.data() : "";
    row.sourceId = share->templateSourceId;
    row.templateId = std::to_string(share->templateGeneration);
    row.height = share->height;
    row.prevHash = share->prevHash;
    row.seedHash = share->seedHash;
    row.algorithm = share->algorithm.name();
    row.jobId = share->jobId;
    row.entropyHex = share->entropy;
    row.minerTargetDiff = share->minerDiff;
    row.networkTargetDiff = share->networkDiff;
    row.shareId = share->shareId;
    row.minerRequestId = share->requestId;
    row.nonce = share->nonce;
    row.resultHash = share->claimedHash;
    row.status = candidateFallback ? "candidate_rate_limited" : "requested";
    LiveEventStream::publish(row);

    return true;
}


void xmrig::Miner::rejectPendingShare(const PendingShare &share, Error::Code error, bool countStrike)
{
    SubmitEvent *event = SubmitEvent::create(this, share.requestId, share.jobId.c_str(), share.nonce.c_str(),
        share.claimedHash.c_str(), share.algorithm, share.signature.empty() ? nullptr : share.signature.c_str(),
        share.signatureData.empty() ? nullptr : share.signatureData.c_str(),
        share.commitment.empty() ? nullptr : share.commitment.c_str(), share.viewTag, share.extraNonce);
    fillSubmitMetadata(event, share);
    event->setError(error);
    event->start();
    replyWithError(share.requestId, Error::toString(error));
    if (countStrike) {
        recordShareOutcome(false);
    }
}


void xmrig::Miner::completeVerification(const std::shared_ptr<PendingShare> &share,
                                        const RandomXVerifier::Result &result)
{
    if (!share || m_state == ClosingState) {
        return;
    }
    const TelemetryJob *liveJob = findTelemetryJob(String(share->jobId.c_str()));
    if (share->mapperId != m_mapperId ||
        share->verificationGeneration != m_verificationGeneration ||
        !liveJob || liveJob->issuanceToken != share->issuanceToken) {
        share->retainSubmission = true;
        return rejectPendingShare(*share, Error::InvalidJobId);
    }

    LiveEventStream::Row row(result.ok ? "verify_result" : "verify_error");
    row.minerId = m_id;
    row.mapperId = share->mapperId;
    row.minerIp = m_ip;
    row.listenPort = m_localPort;
    row.worker = rigId(true).data() ? rigId(true).data() : "";
    row.agent = m_agent.data() ? m_agent.data() : "";
    row.sourceId = share->templateSourceId;
    row.templateId = std::to_string(share->templateGeneration);
    row.height = share->height;
    row.prevHash = share->prevHash;
    row.seedHash = share->seedHash;
    row.algorithm = share->algorithm.name();
    row.jobId = share->jobId;
    row.entropyHex = share->entropy;
    row.minerTargetDiff = share->minerDiff;
    row.networkTargetDiff = share->networkDiff;
    row.shareId = share->shareId;
    row.minerRequestId = share->requestId;
    row.daemonRequestId = static_cast<int64_t>(result.requestId);
    row.nonce = share->nonce;
    row.resultHash = result.ok ? result.hash : share->claimedHash;
    row.latencyMs = result.latencyMs;
    row.status = result.ok ? "computed" : "error";
    row.errorMessage = result.error;
    row.verifierQueueMs = result.queueMs;
    row.verifierHashMs = result.hashMs;
    row.verifierTotalMs = result.totalMs;

    if (!result.ok) {
        LiveEventStream::publish(row);
        if (share->candidateFallback) {
            // This request was already classified as a claimed network
            // candidate. Verification was only the over-budget abuse guard;
            // an unavailable sidecar must not make us discard a possible
            // block after accepting the request. Monerod reconstructs and
            // validates the exact job+nonce and remains authoritative.
            RandomXVerifier *verifier = RandomXVerifier::instance();
            if (!verifier || !verifier->allowEmergencyCandidate(m_key)) {
                row.event = "candidate_verify_fallback";
                row.status = "emergency_rate_limited";
                row.errorMessage = "candidate verification failed and emergency direct-submit budget is exhausted";
                LiveEventStream::publish(row);
                // No verifier or daemon accepted ownership. Preserve the
                // connection-local strike for repeated candidate abuse, but
                // let a genuine nonce be retried after capacity recovers.
                forgetSubmission(share->submission);
                return rejectPendingShare(*share, Error::CandidateRateLimit);
            }

            LiveEventStream::Row fallback = row;
            fallback.event = "candidate_verify_fallback";
            fallback.status = "direct_after_verifier_error";
            fallback.resultHash = share->claimedHash;
            LiveEventStream::publish(fallback);

            SubmitEvent *event = SubmitEvent::create(this, share->requestId, share->jobId.c_str(),
                share->nonce.c_str(), share->claimedHash.c_str(), share->algorithm,
                share->signature.empty() ? nullptr : share->signature.c_str(),
                share->signatureData.empty() ? nullptr : share->signatureData.c_str(),
                share->commitment.empty() ? nullptr : share->commitment.c_str(),
                share->viewTag, share->extraNonce);
            fillSubmitMetadata(event, *share);
            Error::Code finalError = event->error();
            event->setErrorSink(&finalError);
            if (!event->start()) {
                replyWithError(share->requestId, Error::toString(finalError));
                if (finalError == Error::BadGateway || finalError == Error::VerificationFailed) {
                    forgetSubmission(share->submission);
                    recordInfrastructureOutcome(false);
                }
                else {
                    share->retainSubmission = true;
                    recordShareOutcome(false);
                }
            }
            else {
                share->retainSubmission = true;
                recordInfrastructureOutcome(true);
            }
            return;
        }
        // The sidecar failed after accepting this request. This is an
        // infrastructure failure, not evidence of a bad miner: allow the
        // exact share to be retried and do not advance the connection's
        // rejection-strike counter.
        forgetSubmission(share->submission);
        rejectPendingShare(*share, Error::VerificationFailed, false);
        recordInfrastructureOutcome(false);
        return;
    }

    uint8_t claimed[32];
    uint8_t computed[32];
    const bool exact = Cvt::fromHex(claimed, sizeof(claimed), share->claimedHash.c_str(), share->claimedHash.size()) &&
        Cvt::fromHex(computed, sizeof(computed), result.hash.c_str(), result.hash.size()) &&
        memcmp(claimed, computed, sizeof(claimed)) == 0;

    JobResult verified(share->requestId, share->jobId.c_str(), share->nonce.c_str(), result.hash.c_str(),
                       share->algorithm, share->signature.empty() ? nullptr : share->signature.c_str(),
                       share->signatureData.empty() ? nullptr : share->signatureData.c_str(),
                       share->commitment.empty() ? nullptr : share->commitment.c_str(), share->viewTag,
                       share->extraNonce);
    row.shareDiff = verified.actualDiff();

    if (!exact && share->submission.global.valid() &&
        GlobalShareCache::hasHeight(share->templateSourceId, share->height)) {
        // Retain both identities after a definitive mismatch: the submitted
        // entropy+result pair is the requested global duplicate key, while
        // the computed pair prevents replaying the same actual work through
        // another connection with a different forged result. Infrastructure
        // paths release both reservations so genuine work can be retried.
        std::string computedKey;
        GlobalShareCache::Result computedIdentity = GlobalShareCache::Result::Invalid;
        if (GlobalShareCache::makeKey(share->entropy.c_str(), result.hash.c_str(), computedKey)) {
            computedIdentity = GlobalShareCache::reserve(
                share->templateSourceId, share->height, std::move(computedKey),
                share->submission.computedGlobal);
        }

        if (computedIdentity == GlobalShareCache::Result::Duplicate) {
            row.status = "duplicate_result";
            LiveEventStream::publish(row);
            share->retainSubmission = true;
            return rejectPendingShare(*share, Error::DuplicateShare);
        }

        if (computedIdentity != GlobalShareCache::Result::Accepted) {
            row.event = "verify_error";
            row.status = "duplicate_cache_unavailable";
            row.errorMessage = "global result cache is unavailable or full";
            LiveEventStream::publish(row);
            forgetSubmission(share->submission);
            rejectPendingShare(*share, Error::VerificationFailed, false);
            recordInfrastructureOutcome(false);
            return;
        }
    }

    // The independently computed hash is authoritative. If it solves the
    // network target, preserve the block even when the miner supplied a
    // different claimed result. Monerod remains the final consensus check.
    const bool computedCandidate = share->networkDiff != 0 && verified.actualDiff() != 0 &&
        verified.actualDiff() >= share->networkDiff;
    if (computedCandidate) {
        if (!exact) {
            row.event = "verify_mismatch";
            row.status = "candidate_escalated";
            row.errorMessage = std::string("claimed=") + share->claimedHash + " computed=" + result.hash;
        }
        else {
            row.status = "candidate";
        }
        LiveEventStream::publish(row);

        SubmitEvent *event = SubmitEvent::create(this, share->requestId, share->jobId.c_str(), share->nonce.c_str(),
            result.hash.c_str(), share->algorithm, share->signature.empty() ? nullptr : share->signature.c_str(),
            share->signatureData.empty() ? nullptr : share->signatureData.c_str(),
            share->commitment.empty() ? nullptr : share->commitment.c_str(), share->viewTag, share->extraNonce);
        fillSubmitMetadata(event, *share);
        Error::Code finalError = event->error();
        event->setErrorSink(&finalError);
        if (!event->start()) {
            replyWithError(share->requestId, Error::toString(finalError));
            if (finalError == Error::BadGateway || finalError == Error::VerificationFailed) {
                forgetSubmission(share->submission);
                recordInfrastructureOutcome(false);
            }
            else {
                share->retainSubmission = true;
                recordShareOutcome(false);
            }
        }
        else {
            share->retainSubmission = true;
            recordInfrastructureOutcome(true);
        }
        return;
    }

    if (!exact) {
        row.event = "verify_mismatch";
        row.status = "mismatch";
        row.errorMessage = std::string("claimed=") + share->claimedHash + " computed=" + result.hash;
        LiveEventStream::publish(row);
        share->retainSubmission = true;
        return rejectPendingShare(*share, Error::InvalidResult);
    }

    if (verified.actualDiff() == 0 || verified.actualDiff() < share->minerDiff) {
        row.status = "low_difficulty";
        LiveEventStream::publish(row);
        share->retainSubmission = true;
        return rejectPendingShare(*share, Error::LowDifficulty);
    }

    if (share->minerDiff >= share->networkDiff) {
        row.status = "low_difficulty";
        LiveEventStream::publish(row);
        share->retainSubmission = true;
        return rejectPendingShare(*share, Error::LowDifficulty);
    }

    row.status = "accepted_local";
    LiveEventStream::publish(row);
    success(share->requestId, "OK");
    share->retainSubmission = true;

    SubmitResult accepted(0, share->networkDiff, verified.actualDiff(), share->requestId, 0,
                          share->shareId, String(share->jobId.c_str()), share->templateGeneration,
                          share->height, String(share->entropy.c_str()), share->templateSourceId,
                          share->minerDiff);
    AcceptEvent::start(static_cast<size_t>(share->mapperId), this, accepted, false, true);
    recordShareOutcome(true);
}


void xmrig::Miner::recordShareOutcome(bool accepted)
{
    if (accepted) {
        m_consecutiveInfrastructureFailures = 0;
        m_consecutiveShareRejections = 0;
        return;
    }

    RandomXVerifier *verifier = RandomXVerifier::instance();
    if (!verifier) {
        return;
    }

    const uint32_t limit = verifier->maxConsecutiveRejections();
    if (limit == 0) {
        return;
    }

    ++m_consecutiveShareRejections;
    if (m_consecutiveShareRejections >= limit) {
        LOG_WARN("[%s] closing miner after %u consecutive rejected shares", m_ip,
                 m_consecutiveShareRejections);
        shutdown(false);
    }
}


void xmrig::Miner::recordInfrastructureOutcome(bool healthy)
{
    static constexpr uint32_t kMaxConsecutiveInfrastructureFailures = 16;

    if (healthy) {
        m_consecutiveInfrastructureFailures = 0;
        return;
    }

    ++m_consecutiveInfrastructureFailures;
    if (m_consecutiveInfrastructureFailures >= kMaxConsecutiveInfrastructureFailures) {
        LOG_WARN("closing miner connection %lld after %u consecutive verifier/daemon infrastructure failures",
                 static_cast<long long>(m_id), m_consecutiveInfrastructureFailures);
        shutdown(false);
    }
}


bool xmrig::Miner::parseRequest(int64_t id, const char *method, const rapidjson::Value &params)
{
    if (!method || !params.IsObject()) {
        return false;
    }

    if (m_state == WaitLoginState) {
        if (strcmp(method, "login") == 0) {
            const auto loginString = [&params](const char *name, size_t maxSize, bool required) -> const char * {
                if (!params.HasMember(name)) {
                    return required ? nullptr : "";
                }

                const rapidjson::Value &value = params[name];
                if (!value.IsString() || value.GetStringLength() > maxSize ||
                    strlen(value.GetString()) != value.GetStringLength()) {
                    return nullptr;
                }

                return value.GetString();
            };

            const char *login = loginString("login", 256, true);
            const char *password = loginString("pass", 1024, true);
            const char *agent = loginString("agent", 512, false);
            const char *rigId = loginString("rigid", 256, false);
            if (!login || !password || !agent || !rigId) {
                return false;
            }

            setState(WaitReadyState);
            // A fail-closed RandomX verifier may need to build the first
            // full-memory dataset before upstream can safely issue a job.
            // Keep the authenticated connection alive during that bounded
            // readiness wait instead of applying the initial 10-second
            // unauthenticated socket deadline.
            if (RandomXVerifier::instance()) {
                m_expire = Chrono::steadyMSecs() + 60000;
            }
            m_loginId = id;

            Algorithms algorithms;
            if (params.HasMember("algo")) {
                const rapidjson::Value &value = params["algo"];

                if (value.IsArray()) {
                    algorithms.reserve(value.Size());

                    for (const auto &i : value.GetArray()) {
                        if (!i.IsString() || strlen(i.GetString()) != i.GetStringLength()) {
                            continue;
                        }

                        const Algorithm algo(i.GetString());
                        if (!algo.isValid()) {
                            continue;
                        }

                        algorithms.emplace_back(algo);
                    }
                }
            }

            m_user     = login;
            m_password = password;
            m_agent    = agent;
            m_rigId    = rigId;

            LoginEvent::create(this, id, algorithms, params)->start();
            return true;
        }

        return false;
    }

    if (m_state == WaitReadyState) {
        return false;
    }

    if (strcmp(method, "submit") == 0) {
        heartbeat();

        const auto strictString = [&params](const char *name) -> const char * {
            if (!params.HasMember(name) || !params[name].IsString()) {
                return nullptr;
            }

            const rapidjson::Value &value = params[name];
            return strlen(value.GetString()) == value.GetStringLength()
                ? value.GetString() : nullptr;
        };

        const char *rpcId = strictString("id");
        if (!rpcId || m_rpcId != rpcId) {
            replyWithError(id, Error::toString(Error::Unauthenticated));
            return true;
        }

        const char *algorithmName = strictString("algo");
        Algorithm algorithm(algorithmName);
        bool invalidAlgorithmField = false;
        if (params.HasMember("algo")) {
            const rapidjson::Value &value = params["algo"];
            invalidAlgorithmField = !value.IsString() ||
                strlen(value.GetString()) != value.GetStringLength() ||
                (value.GetStringLength() != 0 && !algorithm.isValid());
        }
        const char *submittedJobId = strictString("job_id");
        const char *nonce = strictString("nonce");
        const char *resultHash = strictString("result");
        const char *signature = strictString("sig");
        const char *commitment = strictString("commitment");
        const String submittedJob(submittedJobId);
        const TelemetryJob *telemetryJob = findTelemetryJob(submittedJob);
        const String &signatureData = telemetryJob ? telemetryJob->signatureData : m_signatureData;
        const uint8_t viewTag = telemetryJob ? telemetryJob->viewTag : m_viewTag;
        const int64_t extraNonce = telemetryJob ? telemetryJob->extraNonce : m_extraNonce;

        SubmitEvent *event = SubmitEvent::create(this, id, submittedJobId, nonce, resultHash,
            algorithm, signature, signatureData, commitment, viewTag, extraNonce);
        Error::Code finalError = event->error();
        event->setErrorSink(&finalError);
        event->request.shareId = ++s_shareSequence;

        if (telemetryJob) {
            event->request.templateEntropy    = telemetryJob->entropy;
            event->request.height             = telemetryJob->height;
            event->request.minerDiff          = telemetryJob->minerDiff;
            event->request.networkDiff        = telemetryJob->networkDiff;
            event->request.templateGeneration = telemetryJob->templateGeneration;
            event->request.templateSourceId   = telemetryJob->templateSourceId;
        }

        LiveEventStream::Row row("share_received");
        if (event->request.templateSourceId) {
            row.sourceId = event->request.templateSourceId;
        }
        row.minerId            = m_id;
        row.mapperId           = m_mapperId;
        row.minerIp            = m_ip;
        row.listenPort         = m_localPort;
        row.worker             = m_rigId.size() ? m_rigId.data() : (m_user.data() ? m_user.data() : "");
        row.agent              = m_agent.data() ? m_agent.data() : "";
        row.jobId              = event->request.jobId.data() ? event->request.jobId.data() : "";
        row.shareId            = event->request.shareId;
        row.minerRequestId     = event->request.id;
        row.nonce              = event->request.nonce ? event->request.nonce : "";
        row.resultHash         = event->request.result ? event->request.result : "";
        if (telemetryJob) {
            row.prevHash       = telemetryJob->prevHash.data() ? telemetryJob->prevHash.data() : "";
            row.seedHash       = telemetryJob->seedHash.data() ? telemetryJob->seedHash.data() : "";
            row.algorithm      = telemetryJob->algorithm.name();
        }
        row.signatureHex       = event->request.sig ? event->request.sig : "";
        row.viewTag            = event->request.view_tag;
        if (event->request.extra_nonce >= 0) {
            row.extraNonce = event->request.extra_nonce;
        }
        if (event->request.minerDiff) {
            row.minerTargetDiff = event->request.minerDiff;
        }
        row.shareDiff          = event->request.actualDiff();
        row.status             = "received";
        if (event->request.networkDiff) {
            row.networkTargetDiff = event->request.networkDiff;
            if (event->request.templateGeneration) {
                row.templateId = std::to_string(event->request.templateGeneration);
            }
            if (event->request.height) {
                row.height = event->request.height;
            }
            row.entropyHex = event->request.templateEntropy.data()
                ? event->request.templateEntropy.data() : "";
        }
        LiveEventStream::publish(row);

        uint8_t nonceBytes[4];
        uint8_t resultBytes[32];
        const bool validNonceEncoding = event->request.nonce &&
            strlen(event->request.nonce) == sizeof(nonceBytes) * 2 &&
            Cvt::fromHex(nonceBytes, sizeof(nonceBytes), event->request.nonce, sizeof(nonceBytes) * 2);
        const bool validResultEncoding = event->request.result &&
            strlen(event->request.result) == sizeof(resultBytes) * 2 &&
            Cvt::fromHex(resultBytes, sizeof(resultBytes), event->request.result, sizeof(resultBytes) * 2);

        RandomXVerifier *verifier = RandomXVerifier::instance();
        const bool claimedCandidate = telemetryJob && telemetryJob->networkDiff != 0 &&
            event->request.actualDiff() >= telemetryJob->networkDiff;
        const bool staleJob = telemetryJob &&
            ShareHeightPolicy::isStale(telemetryJob->height, m_jobHeight);

        SubmissionReservation submission;

        if (!submittedJobId || !telemetryJob) {
            event->setError(Error::InvalidJobId);
        }
        else if (!validNonceEncoding) {
            event->setError(Error::InvalidNonce);
        }
        else if (!validResultEncoding) {
            event->setError(Error::InvalidResult);
        }
        else if (invalidAlgorithmField ||
                 (event->request.algorithm.isValid() && event->request.algorithm != telemetryJob->algorithm)) {
            event->setError(Error::IncorrectAlgorithm);
        }
        else if (staleJob) {
            event->setError(Error::StaleShare);
        }
        else if (!verifier && event->request.actualDiff() < telemetryJob->minerDiff) {
            event->setError(Error::LowDifficulty);
        }
        else if (hasExtension(EXT_NICEHASH) && !event->request.isCompatible(m_fixedByte)) {
            event->setError(Error::InvalidNonce);
        }
        else {
            const GlobalShareCache::Result duplicate = rememberSubmission(
                *telemetryJob, event->request.jobId.data(), event->request.nonce,
                event->request.result, submission);
            if (duplicate == GlobalShareCache::Result::Duplicate) {
                event->setError(Error::DuplicateShare);
            }
            else if (duplicate != GlobalShareCache::Result::Accepted) {
                event->setError(Error::VerificationFailed);
            }
        }

        const bool candidateNeedsVerification = event->error() == Error::NoError && verifier &&
            claimedCandidate && !verifier->allowCandidate(m_key);

        if (event->error() == Error::NoError && verifier &&
            (!claimedCandidate || candidateNeedsVerification)) {
            if (startVerification(event, *telemetryJob, submission, candidateNeedsVerification)) {
                // The verifier request owns all share fields. SubmitEvent uses
                // the process-wide placement buffer and cannot survive the
                // asynchronous Unix-socket round trip.
                event->~SubmitEvent();
                return true;
            }

            LiveEventStream::Row verifyError(candidateNeedsVerification
                ? "candidate_verify_fallback" : "verify_error");
            verifyError.minerId = m_id;
            verifyError.mapperId = m_mapperId;
            verifyError.sourceId = event->request.templateSourceId;
            verifyError.templateId = std::to_string(event->request.templateGeneration);
            verifyError.height = event->request.height;
            verifyError.seedHash = telemetryJob->seedHash.data() ? telemetryJob->seedHash.data() : "";
            verifyError.jobId = event->request.jobId.data() ? event->request.jobId.data() : "";
            verifyError.shareId = event->request.shareId;
            verifyError.minerRequestId = event->request.id;
            verifyError.nonce = event->request.nonce ? event->request.nonce : "";
            verifyError.resultHash = event->request.result ? event->request.result : "";
            if (!candidateNeedsVerification) {
                verifyError.status = "unavailable";
                verifyError.errorMessage = "verifier not ready, seed not ready, or queue full";
                event->setError(Error::VerificationFailed);
            }
            else if (!verifier->allowEmergencyCandidate(m_key)) {
                verifyError.status = "emergency_rate_limited";
                verifyError.errorMessage = "candidate verification admission unavailable and emergency direct-submit budget is exhausted";
                event->setError(Error::CandidateRateLimit);
            }
            else {
                verifyError.status = "direct_unverified";
                verifyError.errorMessage = "candidate verification admission unavailable; using bounded emergency direct submit";
            }
            LiveEventStream::publish(verifyError);
            if (event->error() != Error::NoError) {
                // Admission failed before either verifier or daemon accepted
                // ownership. Let the miner retry the same genuine nonce after
                // the transient condition clears.
                forgetSubmission(submission);
            }
        }

        if (event->error() == Error::NoError &&
            !verifier &&
            event->request.minerDiff < event->request.networkDiff &&
            event->request.actualDiff() < event->request.networkDiff) {
            success(id, "OK");

            SubmitResult result = SubmitResult(0, event->request.networkDiff, event->request.actualDiff(), event->request.id, 0,
                                               event->request.shareId, event->request.jobId,
                                               event->request.templateGeneration, event->request.height,
                                               event->request.templateEntropy, event->request.templateSourceId,
                                               event->request.minerDiff);

            // SubmitEvent lives in the global placement buffer. It is not
            // dispatched on this local custom-difficulty path, so destroy it
            // before AcceptEvent reuses the same storage.
            event->~SubmitEvent();
            AcceptEvent::start(m_mapperId, this, result, false, true);

            return true;
        }

        if (!event->start()) {
            const bool infrastructureFailure = finalError == Error::BadGateway ||
                finalError == Error::VerificationFailed;
            if (infrastructureFailure) {
                // SubmitEvent has been destroyed by Events::exec at this
                // point; use the still-owned request strings instead.
                forgetSubmission(submission);
            }
            replyWithError(id, Error::toString(finalError));
            if (infrastructureFailure) {
                recordInfrastructureOutcome(false);
            }
            else {
                recordShareOutcome(false);
            }
        }
        else {
            recordInfrastructureOutcome(true);
        }

        return finalError != Error::InvalidNonce;
    }

    if (strcmp(method, "keepalived") == 0) {
        heartbeat();
        success(id, "KEEPALIVED");
        return true;
    }

    replyWithError(id, Error::toString(Error::InvalidMethod));
    return true;
}


bool xmrig::Miner::send(BIO *bio)
{
#   ifdef XMRIG_FEATURE_TLS
    uv_buf_t buf;
    buf.len = BIO_get_mem_data(bio, &buf.base);

    if (buf.len == 0) {
        return true;
    }

    LOG_DEBUG("[%s] TLS send     (%d bytes)", m_ip, static_cast<int>(buf.len));

    const bool written = writeRaw(buf.base, buf.len);
    (void) BIO_reset(bio);

    if (written) {
        m_tx += buf.len;
    }

    return written;
#   else
    return false;
#   endif
}


void xmrig::Miner::heartbeat()
{
    m_expire = Chrono::steadyMSecs() + kSocketTimeout;
}


void xmrig::Miner::parse(char *line, size_t len)
{
    if (m_state == ClosingState) {
        return;
    }

    LOG_DEBUG("[%s] received (%d bytes): \"%s\"", m_ip, len, line);

    if (len < 32 || line[0] != '{') {
        return shutdown(true);
    }

    rapidjson::Document doc;
    if (doc.ParseInsitu<rapidjson::kParseValidateEncodingFlag>(line).HasParseError()) {
        LOG_ERR("[%s] JSON decode failed: \"%s\"", m_ip, rapidjson::GetParseError_En(doc.GetParseError()));

        return shutdown(true);
    }

    if (!doc.IsObject()) {
        return shutdown(true);
    }

    if (!doc.HasMember("id") || !doc["id"].IsInt64() ||
        !doc.HasMember("method") || !doc["method"].IsString() ||
        !doc.HasMember("params") || !doc["params"].IsObject()) {
        return shutdown(true);
    }

    const rapidjson::Value &method = doc["method"];
    if (strlen(method.GetString()) != method.GetStringLength()) {
        return shutdown(true);
    }

    if (parseRequest(doc["id"].GetInt64(), method.GetString(), doc["params"])) {
        return;
    }

    shutdown(true);
}


void xmrig::Miner::read(ssize_t nread, const uv_buf_t *buf)
{
    const auto size = static_cast<size_t>(nread);

    if (nread < 0) {
        return shutdown(nread != UV_EOF);
    }

    if (size && m_rx == 0) {
        startTLS(buf->base);
    }

    m_rx += size;

#   ifdef XMRIG_FEATURE_TLS
    if (isTLS()) {
        LOG_DEBUG("[%s] TLS received (%d bytes)", m_ip, nread);

        m_tls->read(buf->base, size);
    }
    else
    {
        if (!m_reader.parse(buf->base, size)) {
            shutdown(true);
        }
    }
#   else
    if (!m_reader.parse(buf->base, size)) {
        shutdown(true);
    }
#   endif
}


bool xmrig::Miner::send(const rapidjson::Document &doc)
{
    using namespace rapidjson;

    StringBuffer buffer(nullptr, 512);
    Writer<StringBuffer> writer(buffer);
    doc.Accept(writer);

    const size_t size = buffer.GetSize();
    if (size > (sizeof(m_sendBuf) - 2)) {
        LOG_ERR("[%s] send failed: \"send buffer overflow: %zu > %zu\"", m_ip, size, (sizeof(m_sendBuf) - 2));
        shutdown(true);

        return false;
    }

    memcpy(m_sendBuf, buffer.GetString(), size);
    m_sendBuf[size]     = '\n';
    m_sendBuf[size + 1] = '\0';

    return send(size + 1);
}


bool xmrig::Miner::send(int size)
{
    LOG_DEBUG("[%s] send (%d bytes): \"%s\"", m_ip, size, m_sendBuf);

    if (size <= 0 || !isWritable()) {
        return false;
    }

    int rc = -1;
#   ifdef XMRIG_FEATURE_TLS
    if (isTLS()) {
        return m_tls->send(m_sendBuf, size);
    }
    else
#   endif
    {
        rc = writeRaw(m_sendBuf, static_cast<size_t>(size)) ? size : -1;
    }

    if (rc < 0) {
        shutdown(true);
        return false;
    }

    m_tx += size;
    return true;
}


bool xmrig::Miner::writeRaw(const char *data, size_t size)
{
    if (!data || size == 0 || !isWritable()) {
        return false;
    }

    uv_buf_t immediate = uv_buf_init(const_cast<char *>(data), static_cast<unsigned int>(size));
    const int attempted = uv_try_write(reinterpret_cast<uv_stream_t *>(m_socket), &immediate, 1);
    if (attempted == static_cast<int>(size)) {
        return true;
    }

    size_t offset = 0;
    if (attempted > 0) {
        offset = static_cast<size_t>(attempted);
    }
    else if (attempted != UV_EAGAIN && attempted != UV_ENOSYS) {
        shutdown(true);
        return false;
    }

    struct PendingWrite
    {
        uv_write_t request{};
        std::string data;
    };

    auto *pending = new PendingWrite;
    pending->data.assign(data + offset, size - offset);
    pending->request.data = pending;

    uv_buf_t queued = uv_buf_init(&pending->data[0], static_cast<unsigned int>(pending->data.size()));
    const int rc = uv_write(&pending->request, reinterpret_cast<uv_stream_t *>(m_socket), &queued, 1,
        [](uv_write_t *request, int status) {
            auto *write = static_cast<PendingWrite *>(request->data);
            if (status < 0 && request->handle) {
                Miner *miner = getMiner(request->handle->data);
                if (miner) {
                    miner->shutdown(true);
                }
            }

            delete write;
        });

    if (rc < 0) {
        delete pending;
        shutdown(true);
        return false;
    }

    return true;
}


bool xmrig::Miner::sendJob(const char *blob, const char *jobId, const char *target, const char *algo, uint64_t height, const String &seedHash, const String &signatureKey)
{
    using namespace rapidjson;

    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    Value params(kObjectType);
    params.AddMember("blob",   StringRef(blob), allocator);
    params.AddMember("job_id", StringRef(jobId), allocator);
    params.AddMember("target", StringRef(target), allocator);
    params.AddMember("algo",   StringRef(algo), allocator);

    if (height) {
        params.AddMember("height", height, allocator);
    }

    if (!seedHash.isNull()) {
        params.AddMember("seed_hash", seedHash.toJSON(), allocator);
    }

    if (!signatureKey.isNull()) {
        // Skip tx_pubkey (first 32 bytes) because client doesn't need it for signing
        const char *key = signatureKey.size() == 192 ? (signatureKey.data() + 64) : signatureKey.data();
        params.AddMember("sig_key", Value(key, allocator), allocator);
    }

    doc.AddMember("jsonrpc", "2.0", allocator);

    if (m_state == WaitReadyState) {
        setState(ReadyState);

        doc.AddMember("id",    m_loginId, allocator);
        doc.AddMember("error", kNullType, allocator);

        Value result(kObjectType);
        result.AddMember("id",  m_rpcId.toJSON(), allocator);
        result.AddMember("job", params, allocator);

        Value extensions(kArrayType);

        if (hasExtension(EXT_ALGO)) {
            extensions.PushBack("algo", allocator);
        }

        if (hasExtension(EXT_NICEHASH)) {
            extensions.PushBack("nicehash", allocator);
        }

        if (hasExtension(EXT_CONNECT)) {
            extensions.PushBack("connect", allocator);

#           ifdef XMRIG_FEATURE_TLS
            extensions.PushBack("tls", allocator);
#           endif
        }

        extensions.PushBack("keepalive", allocator);

        result.AddMember("extensions", extensions, allocator);
        result.AddMember("status", "OK", allocator);

        doc.AddMember("result", result, allocator);
    }
    else {
        doc.AddMember("method", "job", allocator);
        doc.AddMember("params", params, allocator);
    }

    return send(doc);
}


void xmrig::Miner::setState(State state)
{
    if (m_state == state) {
        return;
    }

    if (state == ReadyState) {
        heartbeat();
        Counters::add();
    }

    if (state == ClosingState && m_state == ReadyState) {
        Counters::remove();
    }

    m_state = state;
}


void xmrig::Miner::shutdown(bool had_error)
{
    if (m_state == ClosingState) {
        return;
    }

    setState(ClosingState);
    uv_read_stop(reinterpret_cast<uv_stream_t*>(m_socket));

    // uv_shutdown gets stuck when the connection was not terminated gracefully
    if (had_error) {
        if (uv_is_closing(reinterpret_cast<uv_handle_t*>(m_socket)) == 0) {
            uv_close(reinterpret_cast<uv_handle_t*>(m_socket), [](uv_handle_t* handle) {
                Miner* miner = getMiner(handle->data);
                if (!miner) {
                    return;
                }

                CloseEvent::start(miner);
                m_storage.remove(handle->data);
            });
        }
        return;
    }

    uv_shutdown(new uv_shutdown_t, reinterpret_cast<uv_stream_t*>(m_socket), [](uv_shutdown_t* req, int) {

        if (uv_is_closing(reinterpret_cast<uv_handle_t*>(req->handle)) == 0) {
            uv_close(reinterpret_cast<uv_handle_t*>(req->handle), [](uv_handle_t *handle) {
                Miner *miner = getMiner(handle->data);
                if (!miner) {
                    return;
                }

                CloseEvent::start(miner);
                m_storage.remove(handle->data);
            });
        }

        delete req;
    });
}


void xmrig::Miner::startTLS(const char *data)
{
#   ifdef XMRIG_FEATURE_TLS
    if (m_tlsCtx && (m_strictTls || *data != '{')) {
        m_tls = new Tls(m_tlsCtx->ctx(), this);
    }
#   endif
}


void xmrig::Miner::onRead(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    auto miner = getMiner(stream->data);
    if (miner) {
        miner->read(nread, buf);
    }

    NetBuffer::release(buf);
}


void xmrig::Miner::onTimeout(uv_timer_t *handle)
{
    auto miner = getMiner(handle->data);
    if (!miner) {
        return;
    }

    miner->shutdown(true);
}
