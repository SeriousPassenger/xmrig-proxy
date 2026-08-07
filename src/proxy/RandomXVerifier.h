/* XMRig Proxy
 * Copyright (c) 2026 XMRig Proxy contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef XMRIG_RANDOMXVERIFIER_H
#define XMRIG_RANDOMXVERIFIER_H


#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <vector>


#include <uv.h>
#include "3rdparty/rapidjson/fwd.h"


namespace xmrig {


class RandomXVerifier
{
public:
    struct Request
    {
        uintptr_t owner = 0;
        uint64_t shareId = 0;
        std::string seedHash;
        std::string blob;
        std::string claimedHash;
        std::string jobId;
        std::string nonce;
    };

    struct Result
    {
        bool ok = false;
        std::string hash;
        std::string error;
        uint64_t latencyMs = 0;
        uint64_t requestId = 0;
    };

    using Callback = std::function<void(const Result &)>;

    RandomXVerifier(const std::string &path, uint64_t timeoutMs, uint32_t maxQueue,
                    uint32_t maxPendingPerMiner, uint32_t candidateLimit,
                    uint32_t maxConsecutiveRejections, uv_loop_t *loop = uv_default_loop());
    ~RandomXVerifier();

    RandomXVerifier(const RandomXVerifier &) = delete;
    RandomXVerifier &operator=(const RandomXVerifier &) = delete;

    bool start();
    bool verify(const Request &request, Callback callback);
    bool allowCandidate(uintptr_t owner);
    bool isSeedReady(const std::string &seedHash) const;
    void cancelOwner(uintptr_t owner);
    void prepareSeed(const std::string &seedHash);
    void stop();
    void tick();

    inline bool isConnected() const noexcept { return m_connected; }
    inline bool isReady() const noexcept { return m_ready; }
    inline size_t pending() const noexcept { return m_pending.size(); }
    inline uint32_t maxConsecutiveRejections() const noexcept { return m_maxConsecutiveRejections; }
    inline const std::string &path() const noexcept { return m_path; }

    static RandomXVerifier *instance() noexcept;

private:
    enum class SeedStatus : uint8_t {
        Wanted,
        Requested,
        Ready
    };

    struct SeedState
    {
        SeedStatus status = SeedStatus::Wanted;
        uint64_t lastSeenMs = 0;
        uint64_t retryAtMs = 0;
        uint64_t order = 0;
    };

    struct Pending
    {
        Request request;
        Callback callback;
        uint64_t sentAtMs = 0;
    };

    struct Control
    {
        std::string op;
        std::string seedHash;
        uint64_t sentAtMs = 0;
    };

    struct ConnectRequest;
    struct WriteRequest;

    bool connect();
    bool sendControl(const char *op, const std::string &seedHash = std::string());
    bool sendDocument(const rapidjson::Document &doc);
    void disconnect(const char *error, bool failPending = true);
    void failAll(const char *error);
    void handleFrame(const char *data, size_t size);
    void handleResponse(const rapidjson::Document &doc);
    void parseFrames();
    void requestWantedSeeds();

    static void onAllocate(uv_handle_t *handle, size_t suggestedSize, uv_buf_t *buf);
    static void onClose(uv_handle_t *handle);
    static void onConnect(uv_connect_t *request, int status);
    static void onRead(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
    static void onWrite(uv_write_t *request, int status);

    bool m_connected = false;
    bool m_ready = false;
    bool m_stopping = false;
    std::map<uint64_t, Control> m_controls;
    std::map<uintptr_t, std::deque<uint64_t> > m_candidateWindows;
    std::map<uintptr_t, uint32_t> m_pendingByOwner;
    std::map<uint64_t, Pending> m_pending;
    std::map<std::string, SeedState> m_seeds;
    std::string m_path;
    std::vector<char> m_receiveBuffer;
    uint64_t m_nextRequestId = 1;
    uint64_t m_reconnectAtMs = 0;
    uint64_t m_seedOrder = 0;
    uint64_t m_timeoutMs;
    uint32_t m_candidateLimit;
    uint32_t m_maxConsecutiveRejections;
    uint32_t m_maxPendingPerMiner;
    uint32_t m_maxQueue;
    uv_loop_t *m_loop;
    uv_pipe_t *m_pipe = nullptr;

    static RandomXVerifier *m_instance;
};


} // namespace xmrig


#endif // XMRIG_RANDOMXVERIFIER_H
