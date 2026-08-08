/* XMRig
 * Copyright (c) 2016-2026 XMRig, <support@xmrig.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef XMRIG_DAEMONRECONCILIATION_H
#define XMRIG_DAEMONRECONCILIATION_H


#include "3rdparty/rapidjson/fwd.h"


#include <cstdint>
#include <string>


namespace xmrig {


class DaemonReconciliation
{
public:
    struct SubmitDecision
    {
        enum class Outcome : uint8_t {
            Accepted,
            Rejected,
            Indeterminate
        };

        Outcome outcome = Outcome::Indeterminate;
        std::string blockId;
        std::string reason;
    };

    struct Match
    {
        bool accepted = false;
        std::string blockId;
        std::string reason;
    };

    static constexpr uint32_t kMaxAttempts = 4;
    static constexpr uint64_t kRetryDelayMs = 2000;

    static inline bool hasRemainingAttempts(uint32_t completedAttempts)
    {
        return completedAttempts < kMaxAttempts;
    }

    static inline uint64_t nextAttemptAt(uint64_t now)
    {
        return now + kRetryDelayMs;
    }

    static SubmitDecision classifySubmitResult(const rapidjson::Value &result);
    static Match matchCanonicalBlock(const rapidjson::Value &result,
                                     uint64_t expectedHeight,
                                     const char *expectedMinerTxHash,
                                     const char *expectedBlockBlob);
};


} /* namespace xmrig */


#endif /* XMRIG_DAEMONRECONCILIATION_H */
