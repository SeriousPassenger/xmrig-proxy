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


#include "proxy/live/LiveEventStream.h"

#include "base/tools/Chrono.h"
#include "proxy/events/AcceptEvent.h"
#include "proxy/events/CloseEvent.h"
#include "proxy/events/ConnectionEvent.h"
#include "proxy/events/LoginEvent.h"
#include "proxy/events/SubmitEvent.h"
#include "proxy/Miner.h"


#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <memory>
#include <string>
#include <vector>


#ifndef _WIN32
#   include <cerrno>
#   include <cstring>
#   include <sys/socket.h>
#   include <sys/stat.h>
#   include <sys/un.h>
#   include <unistd.h>
#endif


namespace xmrig {


LiveEventStream *LiveEventStream::m_instance = nullptr;


struct LiveEventStream::Client
{
    explicit Client(LiveEventStream *stream) : owner(stream) {}

    LiveEventStream *owner;
    bool closing = false;
    uv_pipe_t pipe{};
};


struct LiveEventStream::WriteRequest
{
    WriteRequest(Client *subscriber, const std::shared_ptr<std::string> &row) :
        client(subscriber),
        data(row)
    {
        request.data = this;
    }

    uv_write_t request{};
    Client *client;
    std::shared_ptr<std::string> data;
};


namespace {


template<typename T>
std::string number(const LiveEventStream::OptionalNumber<T> &field)
{
    return field.set ? std::to_string(field.value) : std::string();
}


std::string sanitize(const std::string &input)
{
    std::string output;
    output.reserve(input.size());

    for (const unsigned char c : input) {
        switch (c) {
        case '\r':
            output += "\\r";
            break;

        case '\n':
            output += "\\n";
            break;

        case '\t':
            output += "\\t";
            break;

        default:
            if (c < 0x20 || c == 0x7f) {
                char escaped[5]{};
                std::snprintf(escaped, sizeof(escaped), "\\x%02X", c);
                output += escaped;
            }
            else {
                output.push_back(static_cast<char>(c));
            }
            break;
        }
    }

    return output;
}


void appendCsvField(std::string &output, const std::string &input)
{
    if (!output.empty()) {
        output.push_back(',');
    }

    const std::string value = sanitize(input);
    const bool quoted = value.find_first_of(",\"") != std::string::npos;

    if (!quoted) {
        output += value;
        return;
    }

    output.push_back('"');
    for (const char c : value) {
        if (c == '"') {
            output.push_back('"');
        }

        output.push_back(c);
    }
    output.push_back('"');
}


std::string utcNow()
{
    using namespace std::chrono;

    const auto now = system_clock::now();
    const int64_t millisecondsSinceEpoch = duration_cast<milliseconds>(now.time_since_epoch()).count();
    const time_t seconds = static_cast<time_t>(millisecondsSinceEpoch / 1000);
    const int millisecondsPart = static_cast<int>(millisecondsSinceEpoch % 1000);
    tm utc{};

#   ifdef _WIN32
    gmtime_s(&utc, &seconds);
#   else
    gmtime_r(&seconds, &utc);
#   endif

    char timestamp[24]{};
    if (std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", &utc) == 0) {
        return {};
    }

    char suffix[8]{};
    std::snprintf(suffix, sizeof(suffix), ".%03dZ", millisecondsPart);

    return std::string(timestamp) + suffix;
}


} // namespace


xmrig::LiveEventStream::LiveEventStream(const std::string &path, uv_loop_t *loop) :
    m_path(path),
    m_loop(loop ? loop : uv_default_loop())
{
}


xmrig::LiveEventStream::~LiveEventStream()
{
    stop();
}


bool xmrig::LiveEventStream::start()
{
#   ifdef _WIN32
    return false;
#   else
    if (m_running) {
        return true;
    }

    if (m_path.empty() || (m_instance && m_instance != this) || !prepareSocketPath()) {
        return false;
    }

    m_server = new uv_pipe_t;
    if (uv_pipe_init(m_loop, m_server, 0) < 0) {
        delete m_server;
        m_server = nullptr;
        return false;
    }

    m_server->data = this;

    if (uv_pipe_bind(m_server, m_path.c_str()) < 0) {
        m_server->data = nullptr;
        uv_close(reinterpret_cast<uv_handle_t *>(m_server), onServerClosed);
        m_server = nullptr;
        return false;
    }

    if (!rememberOwnedSocket()) {
        stop();
        return false;
    }

    if (uv_listen(reinterpret_cast<uv_stream_t *>(m_server), static_cast<int>(kMaxClients), onConnection) < 0) {
        stop();
        return false;
    }

    m_running  = true;
    m_instance = this;

    return true;
#   endif
}


void xmrig::LiveEventStream::stop()
{
    if (m_instance == this) {
        m_instance = nullptr;
    }

    m_running = false;

    while (!m_clients.empty()) {
        closeClient(m_clients.back());
    }

    if (m_server) {
        uv_pipe_t *server = m_server;
        m_server = nullptr;
        server->data = nullptr;

        if (!uv_is_closing(reinterpret_cast<uv_handle_t *>(server))) {
            uv_close(reinterpret_cast<uv_handle_t *>(server), onServerClosed);
        }
    }

    unlinkOwnedSocket();
}


bool xmrig::LiveEventStream::publish(const Row &row)
{
    LiveEventStream *stream = m_instance;
    return stream && stream->m_running && stream->broadcast(row);
}


xmrig::LiveEventStream *xmrig::LiveEventStream::instance() noexcept
{
    return m_instance;
}


#ifdef XMRIG_FEATURE_HTTP
void xmrig::LiveEventStream::onDaemonTemplateRequest(const DaemonTemplateSource::RequestMetadata &request)
{
    Row row(request.kind == DaemonTemplateSource::RequestKind::BlockTemplate
        ? "template_refresh" : "daemon_height_check");
    row.refreshReason   = DaemonTemplateSource::reasonName(request.reason);
    row.daemonRequestId = static_cast<int64_t>(request.requestId);
    if (request.generation) {
        row.templateId = std::to_string(request.generation);
    }
    row.status = "requested";

    publish(row);
}


void xmrig::LiveEventStream::onDaemonTemplate(const std::shared_ptr<const DaemonTemplateSource::Snapshot> &snapshot)
{
    if (!snapshot) {
        return;
    }

    Row row("template_cached");
    row.templateId       = std::to_string(snapshot->generation);
    row.refreshReason    = DaemonTemplateSource::reasonName(snapshot->request.reason);
    row.height           = snapshot->height;
    row.prevHash         = snapshot->prevHash.data() ? snapshot->prevHash.data() : "";
    row.seedHash         = snapshot->seedHash.data() ? snapshot->seedHash.data() : "";
    row.networkTargetDiff = snapshot->difficulty;
    row.daemonRequestId  = static_cast<int64_t>(snapshot->request.requestId);
    row.latencyMs        = snapshot->request.latencyMs;
    row.status           = "updated";

    publish(row);
}


void xmrig::LiveEventStream::onDaemonTemplateError(const DaemonTemplateSource::RequestMetadata &request,
                                                    const char *error)
{
    Row row(request.kind == DaemonTemplateSource::RequestKind::BlockTemplate
        ? "template_error" : "daemon_height_error");
    row.refreshReason   = DaemonTemplateSource::reasonName(request.reason);
    row.daemonRequestId = static_cast<int64_t>(request.requestId);
    if (request.generation) {
        row.templateId = std::to_string(request.generation);
    }
    row.latencyMs    = request.latencyMs;
    row.status       = "error";
    row.errorMessage = error ? error : "daemon request failed";

    publish(row);
}


void xmrig::LiveEventStream::onDaemonZmqNotification(const DaemonTemplateSource::NotificationMetadata &notification)
{
    (void) notification;
    Row row("zmq_new_block");
    row.refreshReason   = "zmq";
    row.status          = "notified";

    publish(row);
}
#endif


void xmrig::LiveEventStream::onEvent(IEvent *event)
{
    if (!event) {
        return;
    }

    Row row;
    Miner *miner = nullptr;

    switch (event->type()) {
    case IEvent::ConnectionType: {
        const auto *e = static_cast<ConnectionEvent *>(event);
        miner          = e->miner();
        row.event      = "worker_connected";
        row.listenPort = static_cast<uint64_t>(e->port());
        row.status     = "connected";
        break;
    }

    case IEvent::LoginType:
        miner      = static_cast<LoginEvent *>(event)->miner();
        row.event  = "worker_login";
        row.status = "accepted";
        break;

    case IEvent::CloseType:
        miner      = static_cast<CloseEvent *>(event)->miner();
        row.event  = "worker_disconnected";
        row.status = "disconnected";
        if (miner) {
            const uint64_t now = Chrono::currentMSecsSinceEpoch();
            row.connectionMs = now >= miner->timestamp() ? now - miner->timestamp() : 0;
            row.rxBytes      = miner->rx();
            row.txBytes      = miner->tx();
        }
        break;

    case IEvent::AcceptType: {
        const auto *e = static_cast<AcceptEvent *>(event);
        miner          = e->miner();
        row.event      = "share_result";
        row.mapperId   = static_cast<int64_t>(e->mapperId());
        if (e->result.shareId) {
            row.shareId = e->result.shareId;
        }
        row.minerRequestId = e->result.reqId;
        if (!e->isCustomDiff() && e->result.seq) {
            row.daemonRequestId = e->result.seq;
        }
        row.jobId      = e->result.jobId.data() ? e->result.jobId.data() : "";
        row.entropyHex = e->result.entropy.data() ? e->result.entropy.data() : "";
        if (e->result.templateGeneration) {
            row.templateId = std::to_string(e->result.templateGeneration);
        }
        if (e->result.height) {
            row.height = e->result.height;
        }
        row.minerTargetDiff   = e->statsDiff();
        row.networkTargetDiff = e->result.diff;
        row.shareDiff       = e->result.actualDiff;
        row.latencyMs       = e->result.elapsed;
        row.status = e->isCustomDiff() ? "accepted_local" : "accepted_upstream";
        break;
    }

    case IEvent::SubmitType:
        // Raw share receipt is emitted directly by Miner before this event is
        // dispatched. An accepted SubmitEvent is only an intermediate state.
        return;
    }

    if (miner) {
        row.minerId = miner->id();
        if (!row.mapperId.set && miner->mapperId() >= 0) {
            row.mapperId = static_cast<int64_t>(miner->mapperId());
        }
        row.minerIp = miner->ip();
        row.listenPort = miner->localPort();
        row.worker  = miner->rigId(true).data() ? miner->rigId(true).data() : "";
        row.agent   = miner->agent().data() ? miner->agent().data() : "";
    }

    publish(row);
}


void xmrig::LiveEventStream::onRejectedEvent(IEvent *event)
{
    if (!event) {
        return;
    }

    Row row;
    Miner *miner = nullptr;

    switch (event->type()) {
    case IEvent::LoginType:
        miner            = static_cast<LoginEvent *>(event)->miner();
        row.event        = "worker_login";
        row.status       = "rejected";
        row.errorMessage = "login rejected";
        break;

    case IEvent::SubmitType: {
        const auto *e = static_cast<SubmitEvent *>(event);
        miner          = e->miner();
        row.event      = "share_result";
        row.shareId    = e->request.shareId;
        row.minerRequestId = e->request.id;
        row.jobId      = e->request.jobId.data() ? e->request.jobId.data() : "";
        row.nonce      = e->request.nonce ? e->request.nonce : "";
        row.resultHash = e->request.result ? e->request.result : "";
        if (e->request.minerDiff) {
            row.minerTargetDiff = e->request.minerDiff;
        }
        if (e->request.networkDiff) {
            row.networkTargetDiff = e->request.networkDiff;
        }
        if (e->request.templateGeneration) {
            row.templateId = std::to_string(e->request.templateGeneration);
        }
        if (e->request.height) {
            row.height = e->request.height;
        }
        row.entropyHex = e->request.templateEntropy.data()
            ? e->request.templateEntropy.data() : "";
        row.shareDiff       = e->request.actualDiff();
        row.status          = "rejected_local";
        row.errorCode       = static_cast<int64_t>(e->error());
        row.errorMessage    = e->message();
        break;
    }

    case IEvent::AcceptType: {
        const auto *e = static_cast<AcceptEvent *>(event);
        miner          = e->miner();
        row.event      = "share_result";
        row.mapperId   = static_cast<int64_t>(e->mapperId());
        if (e->result.shareId) {
            row.shareId = e->result.shareId;
        }
        row.minerRequestId = e->result.reqId;
        if (e->result.seq) {
            row.daemonRequestId = e->result.seq;
        }
        row.jobId      = e->result.jobId.data() ? e->result.jobId.data() : "";
        row.entropyHex = e->result.entropy.data() ? e->result.entropy.data() : "";
        if (e->result.templateGeneration) {
            row.templateId = std::to_string(e->result.templateGeneration);
        }
        if (e->result.height) {
            row.height = e->result.height;
        }
        row.minerTargetDiff   = e->statsDiff();
        row.networkTargetDiff = e->result.diff;
        row.shareDiff       = e->result.actualDiff;
        row.latencyMs       = e->result.elapsed;
        row.status          = "rejected_upstream";
        row.errorMessage    = e->error() ? e->error() : "upstream rejected submission";
        break;
    }

    default:
        return;
    }

    if (miner) {
        row.minerId = miner->id();
        if (!row.mapperId.set && miner->mapperId() >= 0) {
            row.mapperId = static_cast<int64_t>(miner->mapperId());
        }
        row.minerIp = miner->ip();
        row.listenPort = miner->localPort();
        row.worker  = miner->rigId(true).data() ? miner->rigId(true).data() : "";
        row.agent   = miner->agent().data() ? miner->agent().data() : "";
    }

    publish(row);
}


bool xmrig::LiveEventStream::broadcast(const Row &row)
{
    if (row.event.empty() || m_clients.empty()) {
        return false;
    }

    const auto data = std::make_shared<std::string>(csv(row, ++m_eventSequence));
    const std::vector<Client *> clients(m_clients);

    for (Client *client : clients) {
        write(client, data);
    }

    return true;
}


bool xmrig::LiveEventStream::prepareSocketPath()
{
#   ifdef _WIN32
    return false;
#   else
    struct stat info{};
    if (lstat(m_path.c_str(), &info) == 0) {
        if (!S_ISSOCK(info.st_mode)) {
            return false;
        }

        // Do not steal the pathname from another running proxy. A refused
        // connection identifies the normal stale-socket case after a crash.
        if (m_path.size() >= sizeof(sockaddr_un::sun_path)) {
            return false;
        }

        const int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
        if (descriptor < 0) {
            return false;
        }

        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, m_path.c_str(), m_path.size() + 1);

        const socklen_t addressSize = static_cast<socklen_t>(
            offsetof(sockaddr_un, sun_path) + m_path.size() + 1);
        const int result = connect(descriptor, reinterpret_cast<const sockaddr *>(&address), addressSize);
        const int connectError = errno;
        close(descriptor);

        if (result == 0 || (connectError != ECONNREFUSED && connectError != ENOENT)) {
            return false;
        }

        return unlink(m_path.c_str()) == 0;
    }

    return errno == ENOENT;
#   endif
}


bool xmrig::LiveEventStream::rememberOwnedSocket()
{
#   ifdef _WIN32
    return false;
#   else
    struct stat info{};
    if (lstat(m_path.c_str(), &info) != 0 || !S_ISSOCK(info.st_mode)) {
        return false;
    }

    m_ownsSocket  = true;
    m_socketDevice = static_cast<uint64_t>(info.st_dev);
    m_socketInode  = static_cast<uint64_t>(info.st_ino);

    return chmod(m_path.c_str(), 0660) == 0;
#   endif
}


void xmrig::LiveEventStream::accept(int status)
{
    if (status < 0 || !m_running || !m_server) {
        return;
    }

    Client *client = new Client(this);
    if (uv_pipe_init(m_loop, &client->pipe, 0) < 0) {
        delete client;
        return;
    }

    client->pipe.data = client;

    if (uv_accept(reinterpret_cast<uv_stream_t *>(m_server), reinterpret_cast<uv_stream_t *>(&client->pipe)) < 0) {
        closeClient(client);
        return;
    }

    if (m_clients.size() >= kMaxClients) {
        closeClient(client);
        return;
    }

    m_clients.push_back(client);

    if (uv_read_start(reinterpret_cast<uv_stream_t *>(&client->pipe), onAllocate, onRead) < 0) {
        closeClient(client);
        return;
    }

    write(client, std::make_shared<std::string>(csvHeader()));
}


void xmrig::LiveEventStream::closeClient(Client *client)
{
    if (!client || client->closing) {
        return;
    }

    client->closing = true;

    if (client->owner) {
        std::vector<Client *> &clients = client->owner->m_clients;
        const auto it = std::find(clients.begin(), clients.end(), client);
        if (it != clients.end()) {
            clients.erase(it);
        }
    }

    client->owner = nullptr;
    uv_read_stop(reinterpret_cast<uv_stream_t *>(&client->pipe));

    if (!uv_is_closing(reinterpret_cast<uv_handle_t *>(&client->pipe))) {
        uv_close(reinterpret_cast<uv_handle_t *>(&client->pipe), onClientClosed);
    }
}


void xmrig::LiveEventStream::unlinkOwnedSocket()
{
#   ifndef _WIN32
    if (m_ownsSocket) {
        struct stat info{};
        if (lstat(m_path.c_str(), &info) == 0 &&
            S_ISSOCK(info.st_mode) &&
            static_cast<uint64_t>(info.st_dev) == m_socketDevice &&
            static_cast<uint64_t>(info.st_ino) == m_socketInode) {
            unlink(m_path.c_str());
        }
    }
#   endif

    m_ownsSocket   = false;
    m_socketDevice = 0;
    m_socketInode  = 0;
}


void xmrig::LiveEventStream::write(Client *client, const std::shared_ptr<std::string> &data)
{
    if (!client || client->closing || !data || data->empty() ||
        !uv_is_writable(reinterpret_cast<uv_stream_t *>(&client->pipe))) {
        closeClient(client);
        return;
    }

    WriteRequest *request = new WriteRequest(client, data);
    uv_buf_t buffer = uv_buf_init(const_cast<char *>(request->data->data()),
                                  static_cast<unsigned int>(request->data->size()));

    if (uv_write(&request->request, reinterpret_cast<uv_stream_t *>(&client->pipe), &buffer, 1, onWrite) < 0) {
        delete request;
        closeClient(client);
    }
}


std::string xmrig::LiveEventStream::csv(const Row &row, uint64_t sequence)
{
    std::string output;
    output.reserve(1024);

    appendCsvField(output, "1");
    appendCsvField(output, std::to_string(sequence));
    appendCsvField(output, utcNow());
    appendCsvField(output, row.event);
    appendCsvField(output, number(row.minerId));
    appendCsvField(output, number(row.mapperId));
    appendCsvField(output, row.minerIp);
    appendCsvField(output, number(row.listenPort));
    appendCsvField(output, row.worker);
    appendCsvField(output, row.agent);
    appendCsvField(output, row.templateId);
    appendCsvField(output, number(row.templateAgeMs));
    appendCsvField(output, row.refreshReason);
    appendCsvField(output, number(row.height));
    appendCsvField(output, row.prevHash);
    appendCsvField(output, row.seedHash);
    appendCsvField(output, row.algorithm);
    appendCsvField(output, row.jobId);
    appendCsvField(output, row.entropyHex);
    appendCsvField(output, number(row.minerTargetDiff));
    appendCsvField(output, number(row.networkTargetDiff));
    appendCsvField(output, number(row.shareId));
    appendCsvField(output, number(row.minerRequestId));
    appendCsvField(output, number(row.daemonRequestId));
    appendCsvField(output, row.nonce);
    appendCsvField(output, row.resultHash);
    appendCsvField(output, number(row.shareDiff));
    appendCsvField(output, row.status);
    appendCsvField(output, number(row.errorCode));
    appendCsvField(output, row.errorMessage);
    appendCsvField(output, number(row.latencyMs));
    appendCsvField(output, number(row.connectionMs));
    appendCsvField(output, number(row.rxBytes));
    appendCsvField(output, number(row.txBytes));
    output.push_back('\n');

    return output;
}


const std::string &xmrig::LiveEventStream::csvHeader()
{
    static const std::string header =
        "schema_version,event_seq,time_utc,event,miner_id,mapper_id,miner_ip,listen_port,worker,agent,"
        "template_id,template_age_ms,refresh_reason,height,prev_hash,seed_hash,algo,job_id,entropy_hex,"
        "miner_target_diff,network_target_diff,share_id,miner_request_id,daemon_request_id,nonce,result_hash,"
        "share_diff,status,error_code,error_message,latency_ms,connection_ms,rx_bytes,tx_bytes\n";

    return header;
}


void xmrig::LiveEventStream::onAllocate(uv_handle_t *, size_t suggestedSize, uv_buf_t *buf)
{
    const size_t size = std::max<size_t>(1, std::min<size_t>(suggestedSize, 64));
    buf->base = new char[size];
    buf->len  = size;
}


void xmrig::LiveEventStream::onClientClosed(uv_handle_t *handle)
{
    delete static_cast<Client *>(handle->data);
}


void xmrig::LiveEventStream::onConnection(uv_stream_t *server, int status)
{
    if (server && server->data) {
        static_cast<LiveEventStream *>(server->data)->accept(status);
    }
}


void xmrig::LiveEventStream::onRead(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    delete [] buf->base;

    Client *client = stream ? static_cast<Client *>(stream->data) : nullptr;
    if (client && nread != 0) {
        if (client->owner) {
            client->owner->closeClient(client);
        }
    }
}


void xmrig::LiveEventStream::onServerClosed(uv_handle_t *handle)
{
    delete reinterpret_cast<uv_pipe_t *>(handle);
}


void xmrig::LiveEventStream::onWrite(uv_write_t *request, int status)
{
    WriteRequest *write = request ? static_cast<WriteRequest *>(request->data) : nullptr;
    if (!write) {
        return;
    }

    Client *client = write->client;
    delete write;

    if (status < 0 && client && client->owner) {
        client->owner->closeClient(client);
    }
}


} // namespace xmrig
