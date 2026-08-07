/* XMRig Proxy
 * Copyright (c) 2026 XMRig Proxy contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */


#include <uv.h>


#include "base/net/stratum/DaemonTemplateSource.h"
#include "3rdparty/rapidjson/document.h"
#include "3rdparty/rapidjson/error/en.h"
#include "3rdparty/rapidjson/stringbuffer.h"
#include "3rdparty/rapidjson/writer.h"
#include "base/io/json/Json.h"
#include "base/io/json/JsonRequest.h"
#include "base/io/log/Log.h"
#include "base/kernel/Platform.h"
#include "base/net/dns/Dns.h"
#include "base/net/dns/DnsRecords.h"
#include "base/net/http/Fetch.h"
#include "base/net/http/HttpData.h"
#include "base/net/tools/NetBuffer.h"
#include "base/tools/bswap_64.h"
#include "base/tools/Chrono.h"
#include "base/tools/Timer.h"


#include <algorithm>
#include <cstring>
#include <map>
#include <sstream>


namespace xmrig {


namespace {


static const char *kTag              = "daemon-template";
static const char *kGetHeight        = "/getheight";
static const char *kJsonRpc          = "/json_rpc";
static const char *kHash             = "hash";
static const char *kHeight           = "height";
static const char *kBlocktemplateBlob = "blocktemplate_blob";
static const char *kBlockhashingBlob = "blockhashing_blob";

static constexpr uint64_t kReserveSize = 16;
static constexpr size_t kMaxZmqMessage = 64 * 1024;

static const int kHttpTemplate = 0x445401;
static const int kHttpHeight   = 0x445402;
static const int kTimerPeriodic = 0x445410;
static const int kTimerZmqRetry = 0x445411;
static constexpr uint32_t kMaxZmqHeightRetries = 10;

static const char kZmqGreeting[64] = {
    static_cast<char>(-1), 0, 0, 0, 0, 0, 0, 0, 0, 127, 3, 0, 'N', 'U', 'L', 'L'
};
static constexpr size_t kZmqGreetingSize1 = 11;
static const char kZmqHandshake[] = "\4\x19\5READY\xbSocket-Type\0\0\0\3SUB";
static const char kZmqSubscribe[] = "\0\x18\1json-minimal-chain_main";

enum ZmqState {
    ZmqDisconnected,
    ZmqConnecting,
    ZmqGreeting1,
    ZmqGreeting2,
    ZmqHandshake,
    ZmqConnected
};

static std::map<std::string, std::weak_ptr<DaemonTemplateSource> > registry;
static DaemonTemplateSource::Listener *observer = nullptr;


static uint64_t requestTimeout(uint64_t interval)
{
    return std::max<uint64_t>(5000, std::min<uint64_t>(interval, 60000));
}


static std::string httpError(int status)
{
    std::ostringstream out;
    if (status < 0) {
        out << "HTTP transport error: " << uv_strerror(status);
    }
    else {
        out << "HTTP status " << status;
    }

    return out.str();
}


} // namespace


struct DaemonTemplateSource::ZmqSocketContext
{
    uv_tcp_t socket{};
    std::weak_ptr<DaemonTemplateSource> source;
};


struct DaemonTemplateSource::ZmqConnectContext
{
    uv_connect_t request{};
    ZmqSocketContext *socket = nullptr;
    std::weak_ptr<DaemonTemplateSource> source;
};


DaemonTemplateSource::DaemonTemplateSource(const Pool &pool, const String &expandedWallet) :
    m_pool(pool),
    m_wallet(expandedWallet),
    m_timer(new Timer(this)),
    m_zmqTimer(new Timer(this)),
    m_interval(std::max<uint64_t>(1000, pool.pollInterval()))
{
}


DaemonTemplateSource::~DaemonTemplateSource()
{
    shutdown();

    delete m_timer;
    m_timer = nullptr;

    delete m_zmqTimer;
    m_zmqTimer = nullptr;
}


DaemonTemplateSource::Ptr DaemonTemplateSource::acquire(const Pool &pool, const String &expandedWallet)
{
    if (!pool.isValid() || pool.mode() != Pool::MODE_DAEMON || expandedWallet.isEmpty()) {
        return nullptr;
    }

    for (auto it = registry.begin(); it != registry.end();) {
        if (it->second.expired()) {
            it = registry.erase(it);
        }
        else {
            ++it;
        }
    }

    const std::string key = makeRegistryKey(pool, expandedWallet);
    const auto found = registry.find(key);
    if (found != registry.end()) {
        auto source = found->second.lock();
        if (source && !source->isShutdown()) {
            return source;
        }

        registry.erase(found);
    }

    auto source = Ptr(new DaemonTemplateSource(pool, expandedWallet));
    registry.emplace(key, source);
    source->start();

    return source;
}


void DaemonTemplateSource::setObserver(Listener *value)
{
    observer = value;
}


void DaemonTemplateSource::shutdownAll()
{
    std::vector<Ptr> sources;
    sources.reserve(registry.size());

    for (const auto &entry : registry) {
        auto source = entry.second.lock();
        if (source) {
            sources.emplace_back(std::move(source));
        }
    }

    registry.clear();

    for (const auto &source : sources) {
        source->shutdown();
    }
}


void DaemonTemplateSource::subscribe(Listener *listener, bool replayLatest)
{
    if (!listener || m_shutdown) {
        return;
    }

    m_listeners.insert(listener);

    if (replayLatest && m_latest && m_listeners.count(listener)) {
        auto keepAlive = shared_from_this();
        listener->onDaemonTemplate(m_latest);
    }
}


void DaemonTemplateSource::unsubscribe(Listener *listener)
{
    m_listeners.erase(listener);
}


const char *DaemonTemplateSource::kindName(RequestKind kind)
{
    switch (kind) {
    case RequestKind::BlockTemplate:
        return "block_template";

    case RequestKind::Height:
        return "height";
    }

    return "unknown";
}


const char *DaemonTemplateSource::reasonName(RefreshReason reason)
{
    switch (reason) {
    case RefreshReason::Initial:
        return "initial";

    case RefreshReason::Timer:
        return "timer";

    case RefreshReason::Zmq:
        return "zmq";
    }

    return "unknown";
}


std::string DaemonTemplateSource::makeRegistryKey(const Pool &pool, const String &expandedWallet)
{
    using namespace rapidjson;

    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();
    doc.AddMember("pool", pool.toJSON(doc), allocator);
    doc.AddMember("expanded_wallet", expandedWallet.toJSON(doc), allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    doc.Accept(writer);

    return std::string(buffer.GetString(), buffer.GetSize());
}


void DaemonTemplateSource::start()
{
    if (m_started || m_shutdown) {
        return;
    }

    m_started = true;
    m_timer->singleShot(m_interval, kTimerPeriodic);

    // Template acquisition must never wait for ZMQ to connect.
    requestTemplate(RefreshReason::Initial);
    startZmq();
}


void DaemonTemplateSource::shutdown()
{
    if (m_shutdown) {
        return;
    }

    m_shutdown = true;
    m_started  = false;
    m_heightFollowup = false;
    m_heightPending = false;
    m_heightRetryFollowup = false;
    m_templatePending = false;
    m_zmqResolving = false;

    if (m_timer) {
        m_timer->stop();
    }

    if (m_zmqTimer) {
        m_zmqTimer->stop();
    }

    m_dns.reset();
    closeZmq();
    m_listeners.clear();
    m_latest.reset();
}


void DaemonTemplateSource::onTimer(const Timer *timer)
{
    if (m_shutdown) {
        return;
    }

    if (timer == m_zmqTimer && timer->id() == kTimerZmqRetry) {
        requestHeight(m_heightRetryFollowup);
        return;
    }

    if (m_pool.zmq_port() > 0 && !m_zmqSocket && !m_zmqResolving) {
        startZmq();
    }

    requestTemplate(RefreshReason::Timer);
}


int DaemonTemplateSource::reasonPriority(RefreshReason reason)
{
    switch (reason) {
    case RefreshReason::Zmq:
        return 3;

    case RefreshReason::Initial:
        return 2;

    case RefreshReason::Timer:
        return 1;
    }

    return 0;
}


void DaemonTemplateSource::requestTemplate(RefreshReason reason)
{
    if (m_shutdown) {
        return;
    }

    if (m_templateInFlight) {
        if (!m_templatePending || reasonPriority(reason) > reasonPriority(m_pendingReason)) {
            m_pendingReason = reason;
        }
        m_templatePending = true;
        return;
    }

    m_templateInFlight = true;
    m_templateRequest = {};
    m_templateRequest.kind = RequestKind::BlockTemplate;
    m_templateRequest.reason = reason;
    m_templateRequest.requestId = ++m_requestSequence;
    m_templateRequest.generation = m_generation + 1;
    m_templateRequest.startedSteadyMs = Chrono::steadyMSecs();
    m_templateRequest.startedUnixMs = Chrono::currentMSecsSinceEpoch();

    notifyRequest(m_templateRequest);
    if (m_shutdown) {
        m_templateInFlight = false;
        return;
    }

    using namespace rapidjson;
    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    Value params(kObjectType);
    params.AddMember("wallet_address", m_wallet.toJSON(doc), allocator);
    params.AddMember("reserve_size", kReserveSize, allocator);

    JsonRequest::create(doc, static_cast<int64_t>(m_templateRequest.requestId), "getblocktemplate", params);

    FetchRequest req(HTTP_POST, m_pool.host(), m_pool.port(), kJsonRpc, doc, m_pool.isTLS(), false);
    req.fingerprint = m_pool.fingerprint();
    req.timeout = requestTimeout(m_pool.jobTimeout());

    std::weak_ptr<IHttpListener> listener(std::static_pointer_cast<IHttpListener>(shared_from_this()));
    fetch(kTag, std::move(req), listener, kHttpTemplate, m_templateRequest.requestId);
}


void DaemonTemplateSource::requestHeight(bool followup)
{
    if (m_shutdown) {
        return;
    }

    // A height sampled before the active template is installed would compare
    // against the old cached parent and enqueue a duplicate GBT. Coalesce all
    // such notifications and check the tip once the template completes.
    if (m_heightInFlight || m_templateInFlight) {
        m_heightPending = true;
        return;
    }

    m_heightInFlight = true;
    m_heightFollowup = followup;
    m_heightRequest = {};
    m_heightRequest.kind = RequestKind::Height;
    m_heightRequest.reason = RefreshReason::Zmq;
    m_heightRequest.requestId = ++m_requestSequence;
    m_heightRequest.generation = m_generation;
    m_heightRequest.startedSteadyMs = Chrono::steadyMSecs();
    m_heightRequest.startedUnixMs = Chrono::currentMSecsSinceEpoch();

    notifyRequest(m_heightRequest);
    if (m_shutdown) {
        m_heightInFlight = false;
        m_heightFollowup = false;
        return;
    }

    FetchRequest req(HTTP_GET, m_pool.host(), m_pool.port(), kGetHeight, m_pool.isTLS(), false);
    req.fingerprint = m_pool.fingerprint();
    req.timeout = requestTimeout(m_pool.jobTimeout());

    std::weak_ptr<IHttpListener> listener(std::static_pointer_cast<IHttpListener>(shared_from_this()));
    fetch(kTag, std::move(req), listener, kHttpHeight, m_heightRequest.requestId);
}


void DaemonTemplateSource::complete(RequestMetadata &request)
{
    const uint64_t steady = Chrono::steadyMSecs();
    request.completedUnixMs = Chrono::currentMSecsSinceEpoch();
    request.latencyMs = steady >= request.startedSteadyMs ? steady - request.startedSteadyMs : 0;
}


void DaemonTemplateSource::onHttpData(const HttpData &data)
{
    auto keepAlive = shared_from_this();
    if (m_shutdown) {
        return;
    }

    if (data.userType == kHttpTemplate) {
        if (!m_templateInFlight || data.rpcId != m_templateRequest.requestId) {
            return;
        }

        if (data.status != 200) {
            const std::string error = httpError(data.status);
            return failTemplate(error.c_str());
        }

        rapidjson::Document doc;
        if (doc.Parse(data.body.c_str()).HasParseError()) {
            std::ostringstream error;
            error << "JSON decode failed: " << rapidjson::GetParseError_En(doc.GetParseError());
            return failTemplate(error.str().c_str());
        }

        if (Json::getInt64(doc, "id", -1) != static_cast<int64_t>(m_templateRequest.requestId)) {
            return failTemplate("Mismatched getblocktemplate response id");
        }

        const rapidjson::Value &rpcError = Json::getObject(doc, "error");
        if (rpcError.IsObject()) {
            return failTemplate(Json::getString(rpcError, "message", "getblocktemplate RPC error"));
        }

        const rapidjson::Value &result = Json::getObject(doc, "result");
        if (!result.IsObject()) {
            return failTemplate("Missing getblocktemplate result");
        }

        std::shared_ptr<Snapshot> snapshot = std::make_shared<Snapshot>();
        snapshot->blocktemplateBlob = Json::getString(result, kBlocktemplateBlob);
        snapshot->blockhashingBlob  = Json::getString(result, kBlockhashingBlob);
        snapshot->seedHash          = Json::getString(result, "seed_hash");
        snapshot->nextSeedHash      = Json::getString(result, "next_seed_hash");
        snapshot->ip                = data.ip().c_str();
        snapshot->prevHash          = Json::getString(result, "prev_hash");
        snapshot->difficulty        = Json::getUint64(result, "difficulty");
        snapshot->height            = Json::getUint64(result, kHeight);
        snapshot->reservedOffset    = Json::getUint64(result, "reserved_offset");
        snapshot->reserveSize       = kReserveSize;

#       ifdef XMRIG_FEATURE_TLS
        snapshot->tlsFingerprint    = data.tlsFingerprint();
        snapshot->tlsVersion        = data.tlsVersion();
#       endif

        if (snapshot->blocktemplateBlob.isEmpty() || snapshot->blockhashingBlob.isEmpty() ||
            snapshot->prevHash.isEmpty() || snapshot->difficulty == 0 || snapshot->height == 0 ||
            snapshot->reservedOffset == 0 || (snapshot->blocktemplateBlob.size() & 1) != 0 ||
            snapshot->reservedOffset + kReserveSize > snapshot->blocktemplateBlob.size() / 2) {
            return failTemplate("Invalid or incomplete getblocktemplate result");
        }

        complete(m_templateRequest);
        const bool advancedCachedTip = !m_latest || snapshot->prevHash != m_latest->prevHash;
        snapshot->generation = ++m_generation;
        snapshot->fetchedSteadyMs = Chrono::steadyMSecs();
        m_templateRequest.generation = snapshot->generation;
        snapshot->request = m_templateRequest;

        m_templateInFlight = false;
        m_lastSuccessSteadyMs = Chrono::steadyMSecs();
        m_latest = snapshot;

        // Schedule the next periodic refresh relative to this successful
        // snapshot, avoiding the phase drift of a repeating timer.
        m_timer->singleShot(m_interval, kTimerPeriodic);

        notifySnapshot(snapshot);
        drainTemplateQueue();
        drainHeightQueue(advancedCachedTip);
        return;
    }

    if (data.userType == kHttpHeight) {
        if (!m_heightInFlight || data.rpcId != m_heightRequest.requestId) {
            return;
        }

        if (data.status != 200) {
            const std::string error = httpError(data.status);
            return failHeight(error.c_str());
        }

        rapidjson::Document doc;
        if (doc.Parse(data.body.c_str()).HasParseError()) {
            std::ostringstream error;
            error << "JSON decode failed: " << rapidjson::GetParseError_En(doc.GetParseError());
            return failHeight(error.str().c_str());
        }

        const uint64_t daemonHeight = Json::getUint64(doc, kHeight);
        const String daemonHash = Json::getString(doc, kHash);
        if (daemonHeight == 0 || daemonHash.isEmpty()) {
            return failHeight("Invalid /getheight response");
        }

        complete(m_heightRequest);
        const bool followup = m_heightFollowup;
        const bool heightPending = m_heightPending;
        m_heightInFlight = false;
        m_heightFollowup = false;
        m_heightPending = false;

        // A ZMQ publication can precede RPC readiness very slightly. Asking
        // for a template only after /getheight provides the daemon that
        // ordering barrier while remaining immediate. If RPC still reports
        // our cached parent, retry briefly instead of installing an old job.
        if (m_latest && daemonHash == m_latest->prevHash) {
            if (followup) {
                // The template that just completed already installed this
                // tip. A duplicate/coalesced notification is satisfied; it
                // must not be mistaken for daemon RPC lag.
                m_zmqTimer->stop();
                m_zmqHeightRetries = 0;
                m_heightRetryFollowup = false;

                if (heightPending) {
                    // This is a distinct coalesced publication, not evidence
                    // that the daemon is behind on the tip we just installed.
                    // Give RPC its normal publication barrier, then perform
                    // exactly one follow-up whose same-tip result is final.
                    m_heightRetryFollowup = true;
                    m_zmqTimer->singleShot(100, kTimerZmqRetry);
                }
            }
            else if (++m_zmqHeightRetries <= kMaxZmqHeightRetries) {
                m_heightRetryFollowup = false;
                m_zmqTimer->singleShot(100, kTimerZmqRetry);
            }
            else {
                LOG_WARN("%s ZMQ notification did not advance /getheight after %u retries",
                         kTag, kMaxZmqHeightRetries);
                m_zmqHeightRetries = 0;
                m_heightRetryFollowup = false;
            }
        }
        else {
            m_zmqTimer->stop();
            m_zmqHeightRetries = 0;
            m_heightRetryFollowup = false;

            // Any notification received while this height request was in
            // flight may describe the same block or a genuinely later one.
            // Preserve one coalesced check, but defer it until this GBT has
            // installed its parent hash.
            m_heightPending = heightPending;
            requestTemplate(RefreshReason::Zmq);
        }
    }
}


void DaemonTemplateSource::failTemplate(const char *error)
{
    complete(m_templateRequest);
    m_templateInFlight = false;
    LOG_ERR("%s getblocktemplate failed for %s:%u: \"%s\"", kTag,
            m_pool.host().data(), m_pool.port(), error ? error : "unknown error");
    notifyError(m_templateRequest, error ? error : "getblocktemplate failed");
    drainTemplateQueue();
    drainHeightQueue(false);

    if (!m_shutdown && !m_templateInFlight && !m_templatePending) {
        m_timer->singleShot(std::min<uint64_t>(m_interval, 5000), kTimerPeriodic);
    }
}


void DaemonTemplateSource::failHeight(const char *error)
{
    complete(m_heightRequest);
    const bool followup = m_heightFollowup;
    m_heightInFlight = false;
    m_heightFollowup = false;
    LOG_ERR("%s /getheight failed for %s:%u: \"%s\"", kTag,
            m_pool.host().data(), m_pool.port(), error ? error : "unknown error");
    notifyError(m_heightRequest, error ? error : "/getheight failed");

    m_heightPending = false;
    if (!m_shutdown) {
        if (++m_zmqHeightRetries <= kMaxZmqHeightRetries) {
            m_heightRetryFollowup = followup;
            m_zmqTimer->singleShot(std::min<uint64_t>(m_interval, 1000), kTimerZmqRetry);
        }
        else {
            m_zmqHeightRetries = 0;
            m_heightRetryFollowup = false;
        }
    }
}


void DaemonTemplateSource::drainHeightQueue(bool coveredByTemplate)
{
    if (m_shutdown || !m_heightPending || m_heightInFlight || m_templateInFlight) {
        return;
    }

    m_heightPending = false;
    requestHeight(coveredByTemplate);
}


void DaemonTemplateSource::drainTemplateQueue()
{
    if (m_shutdown || !m_templatePending || m_templateInFlight) {
        return;
    }

    const RefreshReason reason = m_pendingReason;
    m_templatePending = false;
    m_pendingReason = RefreshReason::Timer;

    if (reason == RefreshReason::Timer && m_latest &&
        Chrono::steadyMSecs() < m_lastSuccessSteadyMs + m_interval) {
        return;
    }

    requestTemplate(reason);
}


void DaemonTemplateSource::notifyRequest(const RequestMetadata &request)
{
    auto keepAlive = shared_from_this();
    if (observer) {
        observer->onDaemonTemplateRequest(request);
    }

    const std::vector<Listener *> listeners(m_listeners.begin(), m_listeners.end());
    for (Listener *listener : listeners) {
        if (m_shutdown || !m_listeners.count(listener)) {
            continue;
        }

        listener->onDaemonTemplateRequest(request);
    }
}


void DaemonTemplateSource::notifyError(const RequestMetadata &request, const char *error)
{
    auto keepAlive = shared_from_this();
    if (observer) {
        observer->onDaemonTemplateError(request, error);
    }

    const std::vector<Listener *> listeners(m_listeners.begin(), m_listeners.end());
    for (Listener *listener : listeners) {
        if (m_shutdown || !m_listeners.count(listener)) {
            continue;
        }

        listener->onDaemonTemplateError(request, error);
    }
}


void DaemonTemplateSource::notifySnapshot(const std::shared_ptr<const Snapshot> &snapshot)
{
    auto keepAlive = shared_from_this();
    if (observer) {
        observer->onDaemonTemplate(snapshot);
    }

    const std::vector<Listener *> listeners(m_listeners.begin(), m_listeners.end());
    for (Listener *listener : listeners) {
        if (m_shutdown || !m_listeners.count(listener)) {
            continue;
        }

        listener->onDaemonTemplate(snapshot);
    }
}


void DaemonTemplateSource::notifyZmq()
{
    auto keepAlive = shared_from_this();
    NotificationMetadata notification;
    notification.sequence = ++m_notificationSequence;
    notification.unixMs = Chrono::currentMSecsSinceEpoch();

    if (observer) {
        observer->onDaemonZmqNotification(notification);
    }

    const std::vector<Listener *> listeners(m_listeners.begin(), m_listeners.end());
    for (Listener *listener : listeners) {
        if (m_shutdown || !m_listeners.count(listener)) {
            continue;
        }

        listener->onDaemonZmqNotification(notification);
    }

    if (!m_shutdown) {
        m_zmqTimer->stop();
        m_zmqHeightRetries = 0;
        m_heightRetryFollowup = false;
        requestHeight(false);
    }
}


void DaemonTemplateSource::startZmq()
{
    if (m_shutdown || m_pool.zmq_port() <= 0 || m_zmqResolving || m_zmqSocket) {
        return;
    }

    m_zmqResolving = true;
    auto request = Dns::resolve(m_pool.host(), this);
    m_dns = std::move(request);

    // Dns::resolve can deliver a cached answer synchronously.
    if (!m_zmqResolving) {
        m_dns.reset();
    }
}


void DaemonTemplateSource::onResolved(const DnsRecords &records, int status, const char *error)
{
    auto keepAlive = shared_from_this();
    m_zmqResolving = false;
    m_dns.reset();

    if (m_shutdown) {
        return;
    }

    if (status < 0 || records.isEmpty()) {
        LOG_ERR("%s ZMQ DNS error: \"%s\"", kTag, error ? error : "no address");
        return;
    }

    startZmqSocket(records);
}


void DaemonTemplateSource::startZmqSocket(const DnsRecords &records)
{
    if (m_shutdown || m_zmqSocket) {
        return;
    }

    auto *socket = new ZmqSocketContext();
    socket->source = shared_from_this();

    int rc = uv_tcp_init(uv_default_loop(), &socket->socket);
    if (rc < 0) {
        LOG_ERR("%s ZMQ socket init failed: \"%s\"", kTag, uv_strerror(rc));
        delete socket;
        return;
    }

    socket->socket.data = socket;
    uv_tcp_nodelay(&socket->socket, 1);
    if (Platform::hasKeepalive()) {
        uv_tcp_keepalive(&socket->socket, 1, 60);
    }

    m_zmqSocket = socket;
    m_zmqState = ZmqConnecting;

    auto *connect = new ZmqConnectContext();
    connect->request.data = connect;
    connect->socket = socket;
    connect->source = shared_from_this();

    rc = uv_tcp_connect(&connect->request, &socket->socket,
                        records.get().addr(static_cast<uint16_t>(m_pool.zmq_port())), onZmqConnect);
    if (rc < 0) {
        delete connect;
        LOG_ERR("%s ZMQ connect start failed: \"%s\"", kTag, uv_strerror(rc));
        closeZmq();
    }
}


void DaemonTemplateSource::onZmqConnect(uv_connect_t *req, int status)
{
    auto *connect = static_cast<ZmqConnectContext *>(req->data);
    auto source = connect->source.lock();
    ZmqSocketContext *socket = connect->socket;
    delete connect;

    if (!source || source->m_shutdown || source->m_zmqSocket != socket) {
        if (!uv_is_closing(reinterpret_cast<uv_handle_t *>(&socket->socket))) {
            uv_close(reinterpret_cast<uv_handle_t *>(&socket->socket), onZmqClose);
        }
        return;
    }

    if (status < 0) {
        LOG_ERR("%s ZMQ connect error: \"%s\"", kTag, uv_strerror(status));
        source->closeZmq();
        return;
    }

    source->m_zmqState = ZmqGreeting1;
    source->m_zmqSendBuf.reserve(256);
    source->m_zmqRecvBuf.reserve(1024);

    if (source->writeZmq(kZmqGreeting, kZmqGreetingSize1) && source->m_zmqSocket) {
        const int rc = uv_read_start(reinterpret_cast<uv_stream_t *>(&socket->socket),
                                     NetBuffer::onAlloc, onZmqRead);
        if (rc < 0) {
            LOG_ERR("%s ZMQ read start failed: \"%s\"", kTag, uv_strerror(rc));
            source->closeZmq();
        }
    }
}


void DaemonTemplateSource::onZmqRead(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    auto *socket = static_cast<ZmqSocketContext *>(stream->data);
    auto source = socket->source.lock();
    if (source && source->m_zmqSocket == socket) {
        source->readZmq(nread, buf);
    }

    NetBuffer::release(buf);
}


void DaemonTemplateSource::onZmqClose(uv_handle_t *handle)
{
    auto *socket = static_cast<ZmqSocketContext *>(handle->data);
    auto source = socket->source.lock();
    if (source && source->m_zmqSocket == socket) {
        source->m_zmqSocket = nullptr;
        source->m_zmqState = ZmqDisconnected;
    }

    delete socket;
}


void DaemonTemplateSource::closeZmq()
{
    ZmqSocketContext *socket = m_zmqSocket;
    m_zmqSocket = nullptr;
    m_zmqState = ZmqDisconnected;
    m_zmqRecvBuf.clear();
    m_zmqSendBuf.clear();

    if (!socket) {
        return;
    }

    uv_read_stop(reinterpret_cast<uv_stream_t *>(&socket->socket));
    if (Platform::hasKeepalive()) {
        uv_tcp_keepalive(&socket->socket, 0, 60);
    }

    if (!uv_is_closing(reinterpret_cast<uv_handle_t *>(&socket->socket))) {
        uv_close(reinterpret_cast<uv_handle_t *>(&socket->socket), onZmqClose);
    }
}


bool DaemonTemplateSource::writeZmq(const char *data, size_t size)
{
    if (!m_zmqSocket) {
        return false;
    }

    m_zmqSendBuf.assign(data, data + size);
    uv_buf_t buf = uv_buf_init(m_zmqSendBuf.data(), static_cast<unsigned int>(m_zmqSendBuf.size()));
    const int rc = uv_try_write(reinterpret_cast<uv_stream_t *>(&m_zmqSocket->socket), &buf, 1);

    if (rc >= 0 && static_cast<size_t>(rc) == size) {
        return true;
    }

    LOG_ERR("%s ZMQ write failed: %d", kTag, rc);
    closeZmq();
    return false;
}


void DaemonTemplateSource::readZmq(ssize_t nread, const uv_buf_t *buf)
{
    if (nread <= 0) {
        if (nread != UV_EOF) {
            LOG_ERR("%s ZMQ read failed: \"%s\"", kTag, uv_strerror(static_cast<int>(nread)));
        }
        closeZmq();
        return;
    }

    m_zmqRecvBuf.insert(m_zmqRecvBuf.end(), buf->base, buf->base + nread);

    for (;;) {
        switch (m_zmqState) {
        case ZmqGreeting1:
            if (m_zmqRecvBuf.size() < kZmqGreetingSize1) {
                return;
            }
            if (m_zmqRecvBuf[0] != static_cast<char>(-1) || m_zmqRecvBuf[9] != 127 || m_zmqRecvBuf[10] != 3) {
                LOG_ERR("%s ZMQ handshake failed: invalid greeting", kTag);
                closeZmq();
                return;
            }
            if (!writeZmq(kZmqGreeting + kZmqGreetingSize1, sizeof(kZmqGreeting) - kZmqGreetingSize1)) {
                return;
            }
            m_zmqState = ZmqGreeting2;
            break;

        case ZmqGreeting2:
            if (m_zmqRecvBuf.size() < sizeof(kZmqGreeting)) {
                return;
            }
            if (memcmp(m_zmqRecvBuf.data() + 12, kZmqGreeting + 12, 20) != 0) {
                LOG_ERR("%s ZMQ handshake failed: invalid mechanism", kTag);
                closeZmq();
                return;
            }
            m_zmqRecvBuf.erase(m_zmqRecvBuf.begin(), m_zmqRecvBuf.begin() + sizeof(kZmqGreeting));
            m_zmqState = ZmqHandshake;
            if (!writeZmq(kZmqHandshake, sizeof(kZmqHandshake) - 1)) {
                return;
            }
            break;

        case ZmqHandshake:
            if (m_zmqRecvBuf.size() < 2) {
                return;
            }
            if (m_zmqRecvBuf[0] != 4) {
                LOG_ERR("%s ZMQ handshake failed: invalid READY frame", kTag);
                closeZmq();
                return;
            }
            {
                const size_t size = static_cast<unsigned char>(m_zmqRecvBuf[1]);
                if (size < 18 || m_zmqRecvBuf.size() < size + 2) {
                    if (size >= 18) {
                        return;
                    }
                    LOG_ERR("%s ZMQ handshake failed: invalid READY size", kTag);
                    closeZmq();
                    return;
                }
                if (memcmp(m_zmqRecvBuf.data() + 2, kZmqHandshake + 2, 18) != 0) {
                    LOG_ERR("%s ZMQ handshake failed: invalid READY data", kTag);
                    closeZmq();
                    return;
                }
                m_zmqRecvBuf.erase(m_zmqRecvBuf.begin(), m_zmqRecvBuf.begin() + size + 2);
            }
            if (!writeZmq(kZmqSubscribe, sizeof(kZmqSubscribe) - 1)) {
                return;
            }
            m_zmqState = ZmqConnected;
            break;

        case ZmqConnected:
            if (!parseZmqMessage()) {
                return;
            }
            break;

        default:
            return;
        }
    }
}


bool DaemonTemplateSource::parseZmqMessage()
{
    size_t offset = 0;
    size_t dataSize = 0;
    bool more = false;

    do {
        if (m_zmqRecvBuf.size() - offset < 2) {
            return false;
        }

        const uint8_t flags = static_cast<uint8_t>(m_zmqRecvBuf[offset++]);
        more = (flags & 1U) != 0;
        const bool longSize = (flags & 2U) != 0;
        const bool command = (flags & 4U) != 0;

        uint64_t size = 0;
        if (longSize) {
            if (m_zmqRecvBuf.size() - offset < sizeof(uint64_t)) {
                return false;
            }

            uint64_t encoded = 0;
            memcpy(&encoded, m_zmqRecvBuf.data() + offset, sizeof(encoded));
            size = bswap_64(encoded);
            offset += sizeof(uint64_t);
        }
        else {
            size = static_cast<uint8_t>(m_zmqRecvBuf[offset++]);
        }

        if (size > kMaxZmqMessage || dataSize > kMaxZmqMessage - static_cast<size_t>(size)) {
            LOG_ERR("%s ZMQ message is too large", kTag);
            closeZmq();
            return false;
        }

        if (size > m_zmqRecvBuf.size() - offset) {
            return false;
        }

        if (!command) {
            dataSize += static_cast<size_t>(size);
        }
        offset += static_cast<size_t>(size);
    } while (more);

    m_zmqRecvBuf.erase(m_zmqRecvBuf.begin(), m_zmqRecvBuf.begin() + offset);

    if (dataSize > 0) {
        notifyZmq();
    }

    return true;
}


} /* namespace xmrig */
