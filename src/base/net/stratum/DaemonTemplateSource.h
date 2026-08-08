/* XMRig Proxy
 * Copyright (c) 2026 XMRig Proxy contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef XMRIG_DAEMONTEMPLATESOURCE_H
#define XMRIG_DAEMONTEMPLATESOURCE_H


#include "base/kernel/interfaces/IDnsListener.h"
#include "base/kernel/interfaces/IHttpListener.h"
#include "base/kernel/interfaces/ITimerListener.h"
#include "base/net/stratum/Pool.h"
#include "base/tools/String.h"


#include <memory>
#include <set>
#include <string>
#include <vector>
#include <uv.h>


namespace xmrig {


class DnsRequest;
class Timer;


/**
 * One process-wide getblocktemplate/ZMQ coordinator per exact daemon pool and
 * expanded wallet identity. All methods are expected to run on libuv's main
 * loop thread, like the rest of the stratum client stack.
 */
class DaemonTemplateSource : public IDnsListener,
                             public IHttpListener,
                             public ITimerListener,
                             public std::enable_shared_from_this<DaemonTemplateSource>
{
public:
    enum class RequestKind : uint8_t {
        BlockTemplate,
        Height
    };

    enum class RefreshReason : uint8_t {
        Initial,
        Timer,
        Zmq
    };

    struct RequestMetadata
    {
        RequestKind kind       = RequestKind::BlockTemplate;
        RefreshReason reason   = RefreshReason::Initial;
        uint64_t sourceId      = 0;
        uint64_t requestId     = 0;
        uint64_t generation    = 0;
        uint64_t startedUnixMs = 0;
        uint64_t completedUnixMs = 0;
        uint64_t latencyMs     = 0;

        // Internal monotonic timestamp used to calculate latency. Consumers
        // should use the Unix timestamps above for event records.
        uint64_t startedSteadyMs = 0;
    };

    struct NotificationMetadata
    {
        uint64_t sourceId = 0;
        uint64_t sequence = 0;
        uint64_t unixMs   = 0;
    };

    struct Snapshot
    {
        String blocktemplateBlob;
        String blockhashingBlob;
        String seedHash;
        String previousSeedHash;
        String nextSeedHash;
        String ip;
        String prevHash;
        uint64_t difficulty   = 0;
        uint64_t height       = 0;
        uint64_t reservedOffset = 0;
        uint64_t reserveSize  = 0;
        uint64_t sourceId     = 0;
        uint64_t generation   = 0;
        uint64_t fetchedSteadyMs = 0;
        String tlsFingerprint;
        String tlsVersion;
        RequestMetadata request;
    };

    class Listener
    {
    public:
        virtual ~Listener() = default;

        virtual void onDaemonTemplate(const std::shared_ptr<const Snapshot> &snapshot) = 0;

        // Optional hooks deliberately carry data only; the source has no
        // dependency on proxy logging or telemetry.
        virtual void onDaemonTemplateRequest(const RequestMetadata &) {}
        virtual void onDaemonTemplateError(const RequestMetadata &, const char *) {}
        virtual void onDaemonZmqNotification(const NotificationMetadata &) {}
        virtual void onDaemonTipChanged(uint64_t, uint64_t, const String &) {}
    };

    using Ptr = std::shared_ptr<DaemonTemplateSource>;

    ~DaemonTemplateSource() override;

    /**
     * The caller must pass BaseClient's already-expanded wallet (`m_user`),
     * not Pool::user(), so environment-expanded identities cannot collide.
     */
    static Ptr acquire(const Pool &pool, const String &expandedWallet);
    static void setObserver(Listener *observer);
    static void shutdownAll();

    void subscribe(Listener *listener, bool replayLatest = true);
    void unsubscribe(Listener *listener);

    inline bool isShutdown() const                              { return m_shutdown; }
    inline const Pool &pool() const                             { return m_pool; }
    inline const String &wallet() const                         { return m_wallet; }
    inline uint64_t interval() const                            { return m_interval; }
    inline uint64_t sourceId() const                            { return m_sourceId; }
    inline std::shared_ptr<const Snapshot> latest() const       { return m_latest; }

    static const char *kindName(RequestKind kind);
    static const char *reasonName(RefreshReason reason);

protected:
    void onHttpData(const HttpData &data) override;
    void onResolved(const DnsRecords &records, int status, const char *error) override;
    void onTimer(const Timer *timer) override;

private:
    struct ZmqConnectContext;
    struct ZmqSocketContext;

    DaemonTemplateSource(const Pool &pool, const String &expandedWallet);

    static std::string makeRegistryKey(const Pool &pool, const String &expandedWallet);

    void closeZmq();
    void complete(RequestMetadata &request);
    void drainHeightQueue(bool coveredByTemplate = true);
    void drainTemplateQueue();
    void failHeight(const char *error);
    void failTemplate(const char *error);
    void notifyError(const RequestMetadata &request, const char *error);
    void notifyRequest(const RequestMetadata &request);
    void notifySnapshot(const std::shared_ptr<const Snapshot> &snapshot);
    void notifyZmq();
    void requestHeight(bool followup = false);
    void requestTemplate(RefreshReason reason);
    void shutdown();
    void start();
    void startZmq();
    void startZmqSocket(const DnsRecords &records);
    bool writeZmq(const char *data, size_t size);
    void readZmq(ssize_t nread, const uv_buf_t *buf);
    bool parseZmqMessage();

    static int reasonPriority(RefreshReason reason);
    static void onZmqClose(uv_handle_t *handle);
    static void onZmqConnect(uv_connect_t *req, int status);
    static void onZmqRead(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

    bool m_heightInFlight       = false;
    bool m_heightFollowup       = false;
    bool m_heightPending        = false;
    bool m_heightRetryFollowup  = false;
    bool m_shutdown             = false;
    bool m_started              = false;
    bool m_templateInFlight     = false;
    bool m_templatePending      = false;
    bool m_zmqResolving         = false;
    int m_zmqState              = 0;
    Pool m_pool;
    RefreshReason m_pendingReason = RefreshReason::Timer;
    RequestMetadata m_heightRequest;
    RequestMetadata m_templateRequest;
    std::set<Listener *> m_listeners;
    std::shared_ptr<DnsRequest> m_dns;
    std::shared_ptr<const Snapshot> m_latest;
    String m_wallet;
    String m_previousSeedHash;
    String m_observedTipHash;
    Timer *m_timer              = nullptr;
    Timer *m_zmqTimer           = nullptr;
    uint64_t m_generation       = 0;
    uint64_t m_interval         = 0;
    uint64_t m_lastSuccessSteadyMs = 0;
    uint64_t m_notificationSequence = 0;
    uint64_t m_requestSequence  = 0;
    uint64_t m_sourceId         = 0;
    uint32_t m_zmqHeightRetries = 0;
    ZmqSocketContext *m_zmqSocket = nullptr;
    std::vector<char> m_zmqRecvBuf;
    std::vector<char> m_zmqSendBuf;
};


} /* namespace xmrig */


#endif /* XMRIG_DAEMONTEMPLATESOURCE_H */
