/* XMRig
 * Copyright (c) 2018-2021 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2021 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
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

#include "core/config/Config.h"
#include "3rdparty/rapidjson/document.h"
#include "base/io/json/Json.h"
#include "base/io/log/Log.h"
#include "base/kernel/interfaces/IJsonReader.h"
#include "base/net/dns/Dns.h"
#include "donate.h"


#include <array>
#include <cassert>
#include <climits>
#include <cstring>
#include <uv.h>


namespace xmrig {


static const std::array<const char *, 3> modeNames = { "nicehash", "simple", "extra_nonce"};


} // namespace xmrig


#if defined(_WIN32) && !defined(strncasecmp)
#   define strncasecmp _strnicmp
#endif


const char *xmrig::Config::modeName() const
{
    return modeNames[m_mode];
}


bool xmrig::Config::isVerbose() const
{
    return Log::isVerbose();
}


bool xmrig::Config::read(const IJsonReader &reader, const char *fileName)
{
    if (!BaseConfig::read(reader, fileName)) {
        return false;
    }

    m_customDiffStats = reader.getBool("custom-diff-stats", m_customDiffStats);
    m_debug        = reader.getBool("debug", m_debug);
    m_algoExt      = reader.getBool("algo-ext", m_algoExt);
    m_reuseTimeout = reader.getInt("reuse-timeout", m_reuseTimeout);
    m_accessLog    = reader.getString("access-log-file");
    m_password     = reader.getString("access-password");

    const rapidjson::Value &eventStream = reader.getObject("event-stream");
    if (eventStream.IsObject()) {
        m_eventStreamEnabled = Json::getBool(eventStream, "enabled", m_eventStreamEnabled);
        const char *path = Json::getString(eventStream, "path");
        if (path && path[0] == '/') {
            m_eventStreamPath = path;
        }
    }

    const rapidjson::Value &randomXVerifier = reader.getObject("randomx-verifier");
    if (randomXVerifier.IsObject()) {
        m_randomXVerifierEnabled = Json::getBool(randomXVerifier, "enabled", m_randomXVerifierEnabled);

        if (randomXVerifier.HasMember("path")) {
            const char *path = Json::getString(randomXVerifier, "path");
            if (!path || path[0] != '/' || strlen(path) > 103) {
                LOG_ERR("randomx-verifier.path must be an absolute Unix socket path of at most 103 bytes");
                return false;
            }
            m_randomXVerifierPath = path;
        }

        m_randomXVerifierTimeout = std::max<uint64_t>(100, std::min<uint64_t>(60000,
            Json::getUint64(randomXVerifier, "timeout-ms", m_randomXVerifierTimeout)));
        m_randomXVerifierMaxQueue = std::max<unsigned>(1, std::min<unsigned>(65536,
            Json::getUint(randomXVerifier, "max-queue", m_randomXVerifierMaxQueue)));
        m_randomXVerifierMaxPendingPerMiner = std::max<unsigned>(1, std::min<unsigned>(1024,
            Json::getUint(randomXVerifier, "max-pending-per-miner", m_randomXVerifierMaxPendingPerMiner)));
        m_randomXVerifierMaxPendingPerMiner = std::min(m_randomXVerifierMaxPendingPerMiner,
                                                       m_randomXVerifierMaxQueue);
        m_randomXVerifierMaxConsecutiveRejections = std::min<unsigned>(1000,
            Json::getUint(randomXVerifier, "max-consecutive-rejections", m_randomXVerifierMaxConsecutiveRejections));
        m_randomXVerifierCandidateLimit = std::min<unsigned>(10000,
            Json::getUint(randomXVerifier, "candidate-max-per-minute", m_randomXVerifierCandidateLimit));

        if (m_randomXVerifierEnabled &&
            (m_randomXVerifierPath.isEmpty() || m_randomXVerifierPath.data()[0] != '/' ||
             m_randomXVerifierPath.size() > 103)) {
            LOG_ERR("randomx-verifier is enabled without a valid absolute Unix socket path");
            return false;
        }
    }

    setCustomDiff(reader.getUint64("custom-diff", m_diff));
    setMode(reader.getString("mode"));
    setWorkersMode(reader.getValue("workers"));

    if (m_randomXVerifierEnabled) {
        if (m_mode != SIMPLE_MODE) {
            LOG_ERR("randomx-verifier requires mode=simple");
            return false;
        }
        if (m_pools.donateLevel() != 0) {
            LOG_ERR("randomx-verifier requires donate-level=0");
            return false;
        }

        size_t enabledPools = 0;
        for (const Pool &pool : m_pools.data()) {
            if (!pool.isEnabled()) {
                continue;
            }

            ++enabledPools;
            const Algorithm algorithm = pool.algorithm().isValid() ? pool.algorithm() : pool.coin().algorithm();
            if (pool.mode() != Pool::MODE_DAEMON || pool.coin() != Coin::MONERO || algorithm != Algorithm::RX_0) {
                LOG_ERR("randomx-verifier requires every enabled pool to be a Monero rx/0 daemon pool");
                return false;
            }
        }

        if (enabledPools == 0) {
            LOG_ERR("randomx-verifier requires at least one enabled Monero daemon pool");
            return false;
        }
    }

    const rapidjson::Value &bind = reader.getArray("bind");
    if (bind.IsArray()) {
        for (const rapidjson::Value &value : bind.GetArray()) {
            if (value.IsObject()) {
                BindHost host(value);
                if (host.isValid()) {
                    m_bind.push_back(std::move(host));
                }
            }
            else if (value.IsString()) {
                BindHost host(value.GetString());
                if (host.isValid()) {
                    m_bind.push_back(std::move(host));
                }
            }
        }
    }

    if (m_bind.empty()) {
        m_bind.push_back(BindHost("0.0.0.0", 3333, 4));
        m_bind.push_back(BindHost("::", 3333, 6));
    }

    return true;
}


void xmrig::Config::getJSON(rapidjson::Document &doc) const
{
    using namespace rapidjson;

    doc.SetObject();

    auto &allocator = doc.GetAllocator();

    doc.AddMember("access-log-file",                m_accessLog.toJSON(), allocator);
    doc.AddMember("access-password",                m_password.toJSON(), allocator);
    doc.AddMember("algo-ext",                       m_algoExt, allocator);

    Value api(kObjectType);
    api.AddMember(StringRef(kApiId),                m_apiId.toJSON(), allocator);
    api.AddMember(StringRef(kApiWorkerId),          m_apiWorkerId.toJSON(), allocator);
    doc.AddMember(StringRef(kApi),                  api, allocator);
    doc.AddMember(StringRef(kHttp),                 m_http.toJSON(doc), allocator);

    doc.AddMember(StringRef(kBackground),           isBackground(), allocator);

    Value eventStream(kObjectType);
    eventStream.AddMember("enabled",               m_eventStreamEnabled, allocator);
    eventStream.AddMember("path",                  m_eventStreamPath.toJSON(doc), allocator);
    doc.AddMember("event-stream",                  eventStream, allocator);

    Value randomXVerifier(kObjectType);
    randomXVerifier.AddMember("enabled", m_randomXVerifierEnabled, allocator);
    randomXVerifier.AddMember("path", m_randomXVerifierPath.toJSON(doc), allocator);
    randomXVerifier.AddMember("timeout-ms", m_randomXVerifierTimeout, allocator);
    randomXVerifier.AddMember("max-queue", m_randomXVerifierMaxQueue, allocator);
    randomXVerifier.AddMember("max-pending-per-miner", m_randomXVerifierMaxPendingPerMiner, allocator);
    randomXVerifier.AddMember("max-consecutive-rejections", m_randomXVerifierMaxConsecutiveRejections, allocator);
    randomXVerifier.AddMember("candidate-max-per-minute", m_randomXVerifierCandidateLimit, allocator);
    doc.AddMember("randomx-verifier", randomXVerifier, allocator);

    Value bind(kArrayType);
    for (const auto &host : m_bind) {
        bind.PushBack(host.toJSON(doc), allocator);
    }

    doc.AddMember("bind",                           bind, allocator);
    doc.AddMember(StringRef(kColors),               Log::isColors(), allocator);
    doc.AddMember("custom-diff",                    diff(), allocator);
    doc.AddMember("custom-diff-stats",              m_customDiffStats, allocator);
    doc.AddMember(StringRef(Pools::kDonateLevel),   m_pools.donateLevel(), allocator);
    doc.AddMember(StringRef(kLogFile),              m_logFile.toJSON(), allocator);
    doc.AddMember("mode",                           StringRef(modeName()), allocator);
    doc.AddMember(StringRef(Pools::kPools),         m_pools.toJSON(doc), allocator);
    doc.AddMember(StringRef(Pools::kRetries),       m_pools.retries(), allocator);
    doc.AddMember(StringRef(Pools::kRetryPause),    m_pools.retryPause(), allocator);
    doc.AddMember("reuse-timeout",                  reuseTimeout(), allocator);

#   ifdef XMRIG_FEATURE_TLS
    doc.AddMember(StringRef(kTls),                  m_tls.toJSON(doc), allocator);
#   endif

    doc.AddMember(StringRef(DnsConfig::kField),     Dns::config().toJSON(doc), allocator);
    doc.AddMember(StringRef(kUserAgent),            m_userAgent.toJSON(), allocator);
    doc.AddMember(StringRef(kSyslog),               isSyslog(), allocator);
    doc.AddMember(StringRef(kVerbose),              isVerbose(), allocator);
    doc.AddMember(StringRef(kWatch),                m_watch,     allocator);
    doc.AddMember("workers",                        Workers::modeToJSON(workersMode()), allocator);
}


void xmrig::Config::toggleVerbose()
{
    Log::setVerbose(Log::isVerbose() ? 0 : 1);
}


void xmrig::Config::setCustomDiff(uint64_t diff)
{
    if (diff >= 100 && diff < INT_MAX) {
        m_diff = diff;
    }
}


void xmrig::Config::setMode(const char *mode)
{
    if (mode == nullptr) {
        m_mode = NICEHASH_MODE;
        return;
    }

    for (size_t i = 0; i < modeNames.size(); i++) {
        if (modeNames[i] && !strcmp(mode, modeNames[i])) {
            m_mode = static_cast<Mode>(i);
            break;
        }
    }
}


void xmrig::Config::setWorkersMode(const rapidjson::Value &value)
{
    if (value.IsBool()) {
        m_workersMode = value.GetBool() ? Workers::RigID : Workers::None;
    }
    else if (value.IsString()) {
        m_workersMode = Workers::parseMode(value.GetString());
    }
}
