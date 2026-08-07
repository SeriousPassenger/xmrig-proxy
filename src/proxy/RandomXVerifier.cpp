/* XMRig Proxy
 * Copyright (c) 2026 XMRig Proxy contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "proxy/RandomXVerifier.h"


#include "3rdparty/rapidjson/document.h"
#include "3rdparty/rapidjson/error/en.h"
#include "3rdparty/rapidjson/stringbuffer.h"
#include "3rdparty/rapidjson/writer.h"
#include "base/io/json/Json.h"
#include "base/io/log/Log.h"
#include "base/tools/Chrono.h"
#include "base/tools/Cvt.h"
#include "proxy/live/LiveEventStream.h"


#include <algorithm>
#include <cmath>
#include <cstring>
#include <utility>


namespace xmrig {


namespace {


static constexpr size_t kMaxFrameSize = 16 * 1024;
static constexpr uint64_t kControlTimeoutMs = 120000;
static constexpr uint64_t kReconnectDelayMs = 1000;
static constexpr uint64_t kSeedRetentionMs = 120000;
static constexpr uint64_t kCandidateWindowMs = 60000;
static constexpr uint64_t kSeedRetryDelayMs = 1000;


bool validHash(const std::string &hash)
{
    uint8_t bytes[32];
    return hash.size() == sizeof(bytes) * 2 &&
        Cvt::fromHex(bytes, sizeof(bytes), hash.data(), hash.size());
}


bool validBlob(const std::string &blob)
{
    if (blob.empty() || (blob.size() & 1) != 0 || blob.size() > 8192) {
        return false;
    }

    std::vector<uint8_t> bytes(blob.size() / 2);
    return Cvt::fromHex(bytes.data(), bytes.size(), blob.data(), blob.size());
}


bool hasCapability(const rapidjson::Value &capabilities, const char *name)
{
    if (!capabilities.IsArray() || !name) {
        return false;
    }

    for (const rapidjson::Value &value : capabilities.GetArray()) {
        if (value.IsString() && strcmp(value.GetString(), name) == 0) {
            return true;
        }
    }

    return false;
}


bool validMetric(const rapidjson::Document &doc, const char *name)
{
    if (!name || !doc.HasMember(name) || !doc[name].IsNumber()) {
        return false;
    }

    const double value = doc[name].GetDouble();
    return std::isfinite(value) && value >= 0.0;
}


bool zeroHash(const std::string &hash)
{
    return hash.size() == 64 && hash.find_first_not_of('0') == std::string::npos;
}


void publishSeedEvent(const char *event, const std::string &seedHash, const char *status,
                      const char *error = nullptr, uint64_t latencyMs = 0)
{
    LiveEventStream::Row row(event);
    row.seedHash = seedHash;
    row.status = status ? status : "";
    row.errorMessage = error ? error : "";
    if (latencyMs > 0) {
        row.latencyMs = latencyMs;
    }
    LiveEventStream::publish(row);
}


} // namespace


struct RandomXVerifier::ConnectRequest
{
    uv_connect_t request{};
    RandomXVerifier *owner = nullptr;
};


struct RandomXVerifier::WriteRequest
{
    uv_write_t request{};
    RandomXVerifier *owner = nullptr;
    std::vector<char> data;
};


RandomXVerifier *RandomXVerifier::m_instance = nullptr;


RandomXVerifier::RandomXVerifier(const std::string &path, uint64_t timeoutMs, uint32_t maxQueue,
                                 uint32_t maxPendingPerMiner, uint32_t candidateLimit,
                                 uint32_t maxConsecutiveRejections, uv_loop_t *loop) :
    m_path(path),
    m_timeoutMs(timeoutMs),
    m_candidateLimit(candidateLimit),
    m_maxConsecutiveRejections(maxConsecutiveRejections),
    m_maxPendingPerMiner(maxPendingPerMiner),
    m_maxQueue(maxQueue),
    m_loop(loop)
{
    m_instance = this;
}


RandomXVerifier::~RandomXVerifier()
{
    stop();
    if (m_instance == this) {
        m_instance = nullptr;
    }
}


RandomXVerifier *RandomXVerifier::instance() noexcept
{
    return m_instance;
}


bool RandomXVerifier::start()
{
    m_stopping = false;
    return connect();
}


bool RandomXVerifier::connect()
{
    if (m_stopping || m_pipe || m_path.empty()) {
        return false;
    }

    m_pipe = new uv_pipe_t;
    m_pipe->data = this;
    const int rc = uv_pipe_init(m_loop, m_pipe, 0);
    if (rc < 0) {
        delete m_pipe;
        m_pipe = nullptr;
        m_reconnectAtMs = Chrono::steadyMSecs() + kReconnectDelayMs;
        return false;
    }

    auto *request = new ConnectRequest;
    request->owner = this;
    request->request.data = request;
    uv_pipe_connect(&request->request, m_pipe, m_path.c_str(), onConnect);
    return true;
}


void RandomXVerifier::stop()
{
    if (m_stopping) {
        return;
    }

    m_stopping = true;
    failAll("verifier stopped");
    m_controls.clear();
    m_candidateWindows.clear();
    m_ready = false;
    m_connected = false;

    uv_pipe_t *pipe = m_pipe;
    m_pipe = nullptr;
    if (pipe && uv_is_closing(reinterpret_cast<uv_handle_t *>(pipe)) == 0) {
        uv_read_stop(reinterpret_cast<uv_stream_t *>(pipe));
        uv_close(reinterpret_cast<uv_handle_t *>(pipe), onClose);
    }
}


void RandomXVerifier::tick()
{
    const uint64_t now = Chrono::steadyMSecs();

    std::vector<uint64_t> expired;
    for (const auto &entry : m_pending) {
        if (now >= entry.second.sentAtMs + m_timeoutMs) {
            expired.push_back(entry.first);
        }
    }

    for (uint64_t id : expired) {
        auto it = m_pending.find(id);
        if (it == m_pending.end()) {
            continue;
        }

        Pending pending = std::move(it->second);
        m_pending.erase(it);
        auto owner = m_pendingByOwner.find(pending.request.owner);
        if (owner != m_pendingByOwner.end() && --owner->second == 0) {
            m_pendingByOwner.erase(owner);
        }
        Result result;
        result.error = "verifier request timed out";
        result.requestId = id;
        result.latencyMs = now - pending.sentAtMs;
        pending.callback(result);
    }

    for (auto it = m_controls.begin(); it != m_controls.end();) {
        const uint64_t timeout = it->second.op == "hello"
            ? std::max<uint64_t>(1000, std::min<uint64_t>(m_timeoutMs, 5000))
            : kControlTimeoutMs;
        if (now < it->second.sentAtMs + timeout) {
            ++it;
            continue;
        }

        if (it->second.op == "hello") {
            disconnect("verifier hello timed out");
            return;
        }
        if (it->second.op == "prepare_seed") {
            auto seed = m_seeds.find(it->second.seedHash);
            if (seed != m_seeds.end()) {
                seed->second.status = SeedStatus::Wanted;
                seed->second.retryAtMs = now + kSeedRetryDelayMs;
            }
            LOG_WARN("RandomX verifier seed %.16s prepare timed out", it->second.seedHash.c_str());
            publishSeedEvent("verifier_seed_error", it->second.seedHash, "error",
                             "prepare_seed timed out", now - it->second.sentAtMs);
        }
        it = m_controls.erase(it);
    }

    std::vector<std::string> releases;
    for (const auto &entry : m_seeds) {
        if (now >= entry.second.lastSeenMs + kSeedRetentionMs) {
            releases.push_back(entry.first);
        }
    }

    for (const std::string &seedHash : releases) {
        if (m_connected && m_ready) {
            sendControl("release_seed", seedHash);
        }
        m_seeds.erase(seedHash);
    }

    if (m_connected && m_ready) {
        requestWantedSeeds();
    }

    if (!m_stopping && !m_pipe && now >= m_reconnectAtMs) {
        connect();
    }
}


void RandomXVerifier::prepareSeed(const std::string &seedHash)
{
    if (!validHash(seedHash) || zeroHash(seedHash)) {
        return;
    }

    SeedState &seed = m_seeds[seedHash];
    if (seed.order == 0) {
        seed.order = ++m_seedOrder;
    }
    seed.lastSeenMs = Chrono::steadyMSecs();

    const uint64_t now = Chrono::steadyMSecs();
    if (m_connected && m_ready && seed.status == SeedStatus::Wanted && now >= seed.retryAtMs) {
        if (sendControl("prepare_seed", seedHash)) {
            seed.status = SeedStatus::Requested;
            seed.retryAtMs = 0;
            publishSeedEvent("verifier_seed_prepare", seedHash, "requested");
        }
    }
}


bool RandomXVerifier::isSeedReady(const std::string &seedHash) const
{
    auto it = m_seeds.find(seedHash);
    return m_connected && m_ready && it != m_seeds.end() && it->second.status == SeedStatus::Ready;
}


bool RandomXVerifier::verify(const Request &request, Callback callback)
{
    const auto ownerEntry = m_pendingByOwner.find(request.owner);
    const uint32_t ownerPending = ownerEntry == m_pendingByOwner.end() ? 0 : ownerEntry->second;
    if (!callback || !m_connected || !m_ready || m_pending.size() >= m_maxQueue ||
        ownerPending >= m_maxPendingPerMiner ||
        !isSeedReady(request.seedHash) || !validHash(request.seedHash) ||
        !validHash(request.claimedHash) || !validBlob(request.blob)) {
        return false;
    }

    using namespace rapidjson;
    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();
    const uint64_t id = m_nextRequestId++;

    doc.AddMember("v", 1, allocator);
    doc.AddMember("id", Value().SetUint64(id), allocator);
    doc.AddMember("op", "verify", allocator);
    doc.AddMember("seed_hash", Value(request.seedHash.c_str(), allocator), allocator);
    doc.AddMember("blob", Value(request.blob.c_str(), allocator), allocator);
    doc.AddMember("claimed_hash", Value(request.claimedHash.c_str(), allocator), allocator);
    doc.AddMember("job_id", Value(request.jobId.c_str(), allocator), allocator);
    doc.AddMember("nonce", Value(request.nonce.c_str(), allocator), allocator);
    doc.AddMember("share_id", Value().SetUint64(request.shareId), allocator);

    if (!sendDocument(doc)) {
        return false;
    }

    // A queued libuv write cannot complete before control returns to the
    // event loop, so installing the owned request after uv_write succeeds is
    // race-free and avoids callbacks while Miner still owns SubmitEvent's
    // process-wide placement buffer.
    Pending pending;
    pending.request = request;
    pending.callback = std::move(callback);
    pending.sentAtMs = Chrono::steadyMSecs();
    m_pending.emplace(id, std::move(pending));
    ++m_pendingByOwner[request.owner];

    return true;
}


bool RandomXVerifier::allowCandidate(uintptr_t owner)
{
    if (m_candidateLimit == 0) {
        return true;
    }

    const uint64_t now = Chrono::steadyMSecs();
    std::deque<uint64_t> &window = m_candidateWindows[owner];
    while (!window.empty() && now >= window.front() + kCandidateWindowMs) {
        window.pop_front();
    }

    if (window.size() >= m_candidateLimit) {
        return false;
    }

    window.push_back(now);
    return true;
}


void RandomXVerifier::cancelOwner(uintptr_t owner)
{
    m_candidateWindows.erase(owner);

    for (auto it = m_pending.begin(); it != m_pending.end();) {
        if (it->second.request.owner == owner) {
            it = m_pending.erase(it);
        }
        else {
            ++it;
        }
    }
    m_pendingByOwner.erase(owner);
}


bool RandomXVerifier::sendControl(const char *op, const std::string &seedHash)
{
    if (!m_connected || !op) {
        return false;
    }

    using namespace rapidjson;
    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();
    const uint64_t id = m_nextRequestId++;

    doc.AddMember("v", 1, allocator);
    doc.AddMember("id", Value().SetUint64(id), allocator);
    doc.AddMember("op", Value(op, allocator), allocator);
    if (!seedHash.empty()) {
        doc.AddMember("seed_hash", Value(seedHash.c_str(), allocator), allocator);
    }
    if (strcmp(op, "prepare_seed") == 0) {
        doc.AddMember("mode", "fast", allocator);
        doc.AddMember("allow_light_fallback", false, allocator);
    }
    else if (strcmp(op, "hello") == 0) {
        doc.AddMember("client", "xmrig-proxy", allocator);
    }

    Control control;
    control.op = op;
    control.seedHash = seedHash;
    control.sentAtMs = Chrono::steadyMSecs();
    m_controls.emplace(id, std::move(control));

    if (!sendDocument(doc)) {
        m_controls.erase(id);
        return false;
    }

    return true;
}


bool RandomXVerifier::sendDocument(const rapidjson::Document &doc)
{
    if (!m_pipe || !m_connected || uv_is_writable(reinterpret_cast<uv_stream_t *>(m_pipe)) != 1) {
        return false;
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    if (buffer.GetSize() == 0 || buffer.GetSize() > kMaxFrameSize) {
        return false;
    }

    auto *write = new WriteRequest;
    write->owner = this;
    write->request.data = write;
    write->data.resize(4 + buffer.GetSize());
    const uint32_t size = static_cast<uint32_t>(buffer.GetSize());
    write->data[0] = static_cast<char>((size >> 24) & 0xff);
    write->data[1] = static_cast<char>((size >> 16) & 0xff);
    write->data[2] = static_cast<char>((size >> 8) & 0xff);
    write->data[3] = static_cast<char>(size & 0xff);
    memcpy(write->data.data() + 4, buffer.GetString(), buffer.GetSize());

    uv_buf_t data = uv_buf_init(write->data.data(), static_cast<unsigned int>(write->data.size()));
    const int rc = uv_write(&write->request, reinterpret_cast<uv_stream_t *>(m_pipe), &data, 1, onWrite);
    if (rc < 0) {
        delete write;
        disconnect(uv_strerror(rc), false);
        return false;
    }

    return true;
}


void RandomXVerifier::requestWantedSeeds()
{
    std::vector<std::pair<uint64_t, std::string> > wanted;
    for (const auto &entry : m_seeds) {
        if (entry.second.status == SeedStatus::Wanted && Chrono::steadyMSecs() >= entry.second.retryAtMs) {
            wanted.emplace_back(entry.second.order, entry.first);
        }
    }
    std::sort(wanted.begin(), wanted.end());

    for (const auto &entry : wanted) {
        auto seed = m_seeds.find(entry.second);
        if (seed != m_seeds.end() && sendControl("prepare_seed", seed->first)) {
            seed->second.status = SeedStatus::Requested;
            seed->second.retryAtMs = 0;
            publishSeedEvent("verifier_seed_prepare", seed->first, "requested");
        }
    }
}


void RandomXVerifier::disconnect(const char *error, bool failPending)
{
    if (!m_connected && !m_pipe) {
        return;
    }

    m_connected = false;
    m_ready = false;
    m_receiveBuffer.clear();
    m_controls.clear();
    for (auto &seed : m_seeds) {
        seed.second.status = SeedStatus::Wanted;
        seed.second.retryAtMs = 0;
    }

    if (failPending) {
        failAll(error ? error : "verifier disconnected");
    }

    uv_pipe_t *pipe = m_pipe;
    m_pipe = nullptr;
    if (pipe && uv_is_closing(reinterpret_cast<uv_handle_t *>(pipe)) == 0) {
        uv_read_stop(reinterpret_cast<uv_stream_t *>(pipe));
        uv_close(reinterpret_cast<uv_handle_t *>(pipe), onClose);
    }

    m_reconnectAtMs = Chrono::steadyMSecs() + kReconnectDelayMs;
    LOG_WARN("RandomX verifier disconnected: %s", error ? error : "unknown error");
}


void RandomXVerifier::failAll(const char *error)
{
    std::map<uint64_t, Pending> pending;
    pending.swap(m_pending);
    m_pendingByOwner.clear();
    const uint64_t now = Chrono::steadyMSecs();

    for (auto &entry : pending) {
        Result result;
        result.error = error ? error : "verifier unavailable";
        result.requestId = entry.first;
        result.latencyMs = now >= entry.second.sentAtMs ? now - entry.second.sentAtMs : 0;
        entry.second.callback(result);
    }
}


void RandomXVerifier::handleFrame(const char *data, size_t size)
{
    rapidjson::Document doc;
    if (!data || size == 0 || doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
        return disconnect("malformed verifier JSON response");
    }

    handleResponse(doc);
}


void RandomXVerifier::handleResponse(const rapidjson::Document &doc)
{
    if (Json::getUint(doc, "v", 0) != 1) {
        return disconnect("unsupported verifier protocol version");
    }

    const uint64_t id = Json::getUint64(doc, "id", 0);
    if (id == 0) {
        return disconnect("verifier response missing id");
    }

    auto control = m_controls.find(id);
    if (control != m_controls.end()) {
        const bool ok = Json::getBool(doc, "ok", false);
        const std::string op = control->second.op;
        const std::string seedHash = control->second.seedHash;
        const uint64_t sentAtMs = control->second.sentAtMs;
        m_controls.erase(control);

        if (op == "hello") {
            if (!ok) {
                return disconnect(Json::getString(doc, "error", "verifier hello rejected"));
            }

            const rapidjson::Value &capabilities = Json::getArray(doc, "capabilities");
            if (strcmp(Json::getString(doc, "service", ""), "xmrig-randomx-verifier") != 0 ||
                strcmp(Json::getString(doc, "mode", ""), "fast") != 0 ||
                Json::getBool(doc, "allow_light_fallback", true) ||
                Json::getUint(doc, "max_frame", 0) == 0 || Json::getUint(doc, "max_frame", 0) > kMaxFrameSize ||
                Json::getUint(doc, "vm_pool_size", 0) == 0 ||
                !hasCapability(capabilities, "prepare_seed") ||
                !hasCapability(capabilities, "release_seed") ||
                !hasCapability(capabilities, "verify")) {
                return disconnect("verifier hello lacks required fast-mode capabilities");
            }
            m_ready = true;
            LOG_INFO("RandomX verifier ready at %s", m_path.c_str());
            requestWantedSeeds();
        }
        else if (op == "prepare_seed") {
            uint8_t requestedSeed[32];
            uint8_t responseSeed[32];
            const char *returnedSeedHash = Json::getString(doc, "seed_hash", "");
            const char *state = Json::getString(doc, "state", "");
            const bool matchingSeed = Cvt::fromHex(requestedSeed, sizeof(requestedSeed), seedHash.c_str(), seedHash.size()) &&
                returnedSeedHash && strlen(returnedSeedHash) == sizeof(responseSeed) * 2 &&
                Cvt::fromHex(responseSeed, sizeof(responseSeed), returnedSeedHash, sizeof(responseSeed) * 2) &&
                memcmp(requestedSeed, responseSeed, sizeof(requestedSeed)) == 0;

            if (ok && (!matchingSeed || strcmp(state, "ready") != 0)) {
                LOG_ERR("RandomX verifier seed %.16s returned invalid readiness metadata", seedHash.c_str());
                return disconnect("invalid prepare_seed readiness response");
            }

            auto seed = m_seeds.find(seedHash);
            if (seed != m_seeds.end()) {
                seed->second.status = ok ? SeedStatus::Ready : SeedStatus::Wanted;
                seed->second.retryAtMs = ok ? 0 : Chrono::steadyMSecs() + kSeedRetryDelayMs;
            }
            const uint64_t now = Chrono::steadyMSecs();
            const uint64_t elapsedMs = now >= sentAtMs ? now - sentAtMs : 0;
            const char *error = Json::getString(doc, "error", "");
            publishSeedEvent(ok ? "verifier_seed_ready" : "verifier_seed_error", seedHash,
                             ok ? "ready" : "error", error, elapsedMs);
            if (ok) {
                const double prepareMs = Json::getDouble(doc, "prepare_ms", -1.0);
                if (prepareMs >= 0.0) {
                    LOG_INFO("RandomX verifier seed %.16s ready in %llu ms (sidecar %.1f ms)", seedHash.c_str(),
                             static_cast<unsigned long long>(elapsedMs), prepareMs);
                }
                else {
                    LOG_INFO("RandomX verifier seed %.16s ready in %llu ms", seedHash.c_str(),
                             static_cast<unsigned long long>(elapsedMs));
                }
            }
            else {
                LOG_WARN("RandomX verifier seed %.16s prepare failed: %s", seedHash.c_str(),
                         error && error[0] ? error : "sidecar returned ok=false");
            }
        }
        else if (op == "release_seed") {
            publishSeedEvent("verifier_seed_release", seedHash, ok ? "released" : "error",
                             Json::getString(doc, "error", ""));
        }
        return;
    }

    auto it = m_pending.find(id);
    if (it == m_pending.end()) {
        return;
    }

    Pending pending = std::move(it->second);
    m_pending.erase(it);
    auto owner = m_pendingByOwner.find(pending.request.owner);
    if (owner != m_pendingByOwner.end() && --owner->second == 0) {
        m_pendingByOwner.erase(owner);
    }

    Result result;
    result.requestId = id;
    result.latencyMs = Chrono::steadyMSecs() >= pending.sentAtMs
        ? Chrono::steadyMSecs() - pending.sentAtMs : 0;
    result.ok = Json::getBool(doc, "ok", false);
    result.hash = Json::getString(doc, "hash", "");
    result.error = Json::getString(doc, "error", "");

    if (result.ok && !validHash(result.hash)) {
        result.ok = false;
        result.error = "verifier returned an invalid hash";
    }
    else if (result.ok &&
             (!doc.HasMember("match") || !doc["match"].IsBool() ||
              !validMetric(doc, "queue_ms") || !validMetric(doc, "hash_ms") ||
              !validMetric(doc, "total_ms"))) {
        result.ok = false;
        result.error = "verifier returned a malformed success response";
    }
    else if (result.ok) {
        uint8_t claimed[32];
        uint8_t computed[32];
        const bool exact = Cvt::fromHex(claimed, sizeof(claimed), pending.request.claimedHash.c_str(),
                                        pending.request.claimedHash.size()) &&
            Cvt::fromHex(computed, sizeof(computed), result.hash.c_str(), result.hash.size()) &&
            memcmp(claimed, computed, sizeof(claimed)) == 0;
        if (doc["match"].GetBool() != exact) {
            result.ok = false;
            result.error = "verifier returned an inconsistent match flag";
        }
    }
    else if (!result.ok && result.error.empty()) {
        result.error = "verifier rejected request without an error";
    }

    pending.callback(result);
}


void RandomXVerifier::parseFrames()
{
    while (m_receiveBuffer.size() >= 4) {
        const uint32_t size =
            (static_cast<uint32_t>(static_cast<uint8_t>(m_receiveBuffer[0])) << 24) |
            (static_cast<uint32_t>(static_cast<uint8_t>(m_receiveBuffer[1])) << 16) |
            (static_cast<uint32_t>(static_cast<uint8_t>(m_receiveBuffer[2])) << 8) |
             static_cast<uint32_t>(static_cast<uint8_t>(m_receiveBuffer[3]));

        if (size == 0 || size > kMaxFrameSize) {
            return disconnect("invalid verifier frame length");
        }
        if (m_receiveBuffer.size() < 4 + size) {
            return;
        }

        handleFrame(m_receiveBuffer.data() + 4, size);
        if (!m_connected) {
            return;
        }
        m_receiveBuffer.erase(m_receiveBuffer.begin(), m_receiveBuffer.begin() + 4 + size);
    }
}


void RandomXVerifier::onAllocate(uv_handle_t *, size_t suggestedSize, uv_buf_t *buf)
{
    const size_t size = std::max<size_t>(1024, std::min<size_t>(suggestedSize, 64 * 1024));
    buf->base = new char[size];
    buf->len = size;
}


void RandomXVerifier::onClose(uv_handle_t *handle)
{
    delete reinterpret_cast<uv_pipe_t *>(handle);
}


void RandomXVerifier::onConnect(uv_connect_t *request, int status)
{
    auto *connect = request ? static_cast<ConnectRequest *>(request->data) : nullptr;
    RandomXVerifier *owner = connect ? connect->owner : nullptr;
    delete connect;

    if (!owner || owner != m_instance || owner->m_stopping) {
        return;
    }
    if (status < 0) {
        return owner->disconnect(uv_strerror(status));
    }

    owner->m_connected = true;
    owner->m_ready = false;
    uv_read_start(reinterpret_cast<uv_stream_t *>(owner->m_pipe), onAllocate, onRead);
    if (!owner->sendControl("hello")) {
        owner->disconnect("failed to send verifier hello");
    }
}


void RandomXVerifier::onRead(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    RandomXVerifier *owner = stream ? static_cast<RandomXVerifier *>(stream->data) : nullptr;
    if (owner && owner == m_instance && nread > 0) {
        owner->m_receiveBuffer.insert(owner->m_receiveBuffer.end(), buf->base, buf->base + nread);
        owner->parseFrames();
    }
    delete [] buf->base;

    if (owner && owner == m_instance && nread < 0) {
        owner->disconnect(uv_strerror(static_cast<int>(nread)));
    }
}


void RandomXVerifier::onWrite(uv_write_t *request, int status)
{
    auto *write = request ? static_cast<WriteRequest *>(request->data) : nullptr;
    RandomXVerifier *owner = write ? write->owner : nullptr;
    delete write;

    if (status < 0 && owner && owner == m_instance) {
        owner->disconnect(uv_strerror(status));
    }
}


} // namespace xmrig
