/* XMRig
 * Copyright 2016-2026 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
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

#ifndef XMRIG_LIVEEVENTSTREAM_H
#define XMRIG_LIVEEVENTSTREAM_H


#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>


#include <uv.h>

#include "proxy/interfaces/IEventListener.h"

#ifdef XMRIG_FEATURE_HTTP
#   include "base/net/stratum/DaemonTemplateSource.h"
#endif


namespace xmrig {


class LiveEventStream : public IEventListener
#ifdef XMRIG_FEATURE_HTTP
                      , public DaemonTemplateSource::Listener
#endif
{
public:
    template<typename T>
    struct OptionalNumber
    {
        OptionalNumber() = default;
        OptionalNumber(T number) : value(number), set(true) {}

        inline OptionalNumber<T> &operator=(T number)
        {
            value = number;
            set   = true;

            return *this;
        }

        inline void reset()
        {
            value = 0;
            set   = false;
        }

        T value  = 0;
        bool set = false;
    };


    struct Row
    {
        Row() = default;
        explicit Row(const char *type) : event(type ? type : "") {}
        explicit Row(const std::string &type) : event(type) {}

        std::string event;
        OptionalNumber<int64_t> minerId;
        OptionalNumber<int64_t> mapperId;
        std::string minerIp;
        OptionalNumber<uint64_t> listenPort;
        std::string worker;
        std::string agent;
        OptionalNumber<uint64_t> sourceId;
        std::string templateId;
        OptionalNumber<uint64_t> templateAgeMs;
        std::string refreshReason;
        OptionalNumber<uint64_t> height;
        std::string prevHash;
        std::string seedHash;
        std::string algorithm;
        std::string jobId;
        std::string entropyHex;
        OptionalNumber<uint64_t> minerTargetDiff;
        OptionalNumber<uint64_t> networkTargetDiff;
        OptionalNumber<uint64_t> shareId;
        OptionalNumber<int64_t> minerRequestId;
        OptionalNumber<int64_t> daemonRequestId;
        std::string nonce;
        std::string resultHash;
        OptionalNumber<uint64_t> shareDiff;
        std::string status;
        OptionalNumber<int64_t> errorCode;
        std::string errorMessage;
        OptionalNumber<uint64_t> latencyMs;
        OptionalNumber<uint64_t> connectionMs;
        OptionalNumber<uint64_t> rxBytes;
        OptionalNumber<uint64_t> txBytes;
        std::string previousSeedHash;
        std::string nextSeedHash;
        std::string hashingBlob;
        std::string blocktemplateBlob;
        std::string submittedBlockBlob;
        std::string minerTargetHex;
        OptionalNumber<uint64_t> nonceOffset;
        OptionalNumber<uint64_t> nonceSize;
        OptionalNumber<uint64_t> reservedOffset;
        OptionalNumber<uint64_t> reservedSize;
        OptionalNumber<uint64_t> extraNonceOffset;
        OptionalNumber<int64_t> extraNonce;
        std::string signatureHex;
        OptionalNumber<uint64_t> viewTag;
        std::string blockId;
        std::string minerTxHash;
        std::string verifierQueueMs;
        std::string verifierHashMs;
        std::string verifierTotalMs;
        std::string verifierPrepareMs;
        OptionalNumber<uint64_t> verifierActive;
        OptionalNumber<uint64_t> verifierQueued;
        OptionalNumber<uint64_t> verifierQueueLimit;
        OptionalNumber<uint64_t> verifierSeedCount;
        OptionalNumber<uint64_t> verifierSeedCapacity;
        std::string verifierSeedRole;
        std::string verifierSeedStatus;
        OptionalNumber<uint64_t> verifierVmPoolSize;
        std::string verifierStatsJson;
    };


    explicit LiveEventStream(const std::string &path, uv_loop_t *loop = uv_default_loop());
    ~LiveEventStream();

    LiveEventStream(const LiveEventStream &)            = delete;
    LiveEventStream &operator=(const LiveEventStream &) = delete;

    bool start();
    void stop();

    inline bool isRunning() const noexcept         { return m_running; }
    inline const std::string &path() const noexcept { return m_path; }
    inline size_t clientCount() const noexcept      { return m_clients.size(); }

    // Socket output is a no-op without a running subscriber. The live
    // instance may still retain pre-login ordering state until login/close.
    static bool publish(const Row &row);
    static LiveEventStream *instance() noexcept;

protected:
    void onEvent(IEvent *event) override;
    void onRejectedEvent(IEvent *event) override;

#   ifdef XMRIG_FEATURE_HTTP
    void onDaemonTemplate(const std::shared_ptr<const DaemonTemplateSource::Snapshot> &snapshot) override;
    void onDaemonTemplateRequest(const DaemonTemplateSource::RequestMetadata &request) override;
    void onDaemonTemplateError(const DaemonTemplateSource::RequestMetadata &request, const char *error) override;
    void onDaemonZmqNotification(const DaemonTemplateSource::NotificationMetadata &notification) override;
    void onDaemonTipChanged(uint64_t sourceId, uint64_t height, const String &hash) override;
#   endif

private:
    struct Client;
    struct WriteRequest;

    enum : size_t {
        kMaxClients = 5,
        kMaxPendingBytesPerClient = 8 * 1024 * 1024
    };

    bool broadcast(const Row &row);
    bool publishOrdered(const Row &row);
    bool prepareSocketPath();
    bool rememberOwnedSocket();
    void accept(int status);
    void closeClient(Client *client);
    void unlinkOwnedSocket();
    void write(Client *client, const std::shared_ptr<std::string> &data);

    std::string csv(const Row &row, uint64_t sequence) const;
    static const std::string &csvHeader();
    static void onAllocate(uv_handle_t *handle, size_t suggestedSize, uv_buf_t *buf);
    static void onClientClosed(uv_handle_t *handle);
    static void onConnection(uv_stream_t *server, int status);
    static void onRead(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
    static void onServerClosed(uv_handle_t *handle);
    static void onWrite(uv_write_t *request, int status);

    bool m_ownsSocket       = false;
    bool m_running          = false;
    std::string m_path;
    std::vector<Client *> m_clients;
    std::map<int64_t, std::vector<Row> > m_preLoginJobs;
    uint64_t m_eventSequence = 0;
    std::string m_streamId;
    uint64_t m_socketDevice  = 0;
    uint64_t m_socketInode   = 0;
    uv_loop_t *m_loop;
    uv_pipe_t *m_server      = nullptr;

    static LiveEventStream *m_instance;
};


} // namespace xmrig


#endif // XMRIG_LIVEEVENTSTREAM_H
