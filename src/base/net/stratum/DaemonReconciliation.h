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

    static constexpr uint32_t kMaxSubmitAttempts = 4;
    static constexpr uint64_t kRetryDelayMs = 2000;

    static inline bool hasRemainingSubmitAttempts(uint32_t completedAttempts)
    {
        return completedAttempts < kMaxSubmitAttempts;
    }

    static inline bool shouldRetrySubmit(SubmitDecision::Outcome outcome,
                                         uint32_t completedAttempts)
    {
        return outcome != SubmitDecision::Outcome::Accepted &&
            hasRemainingSubmitAttempts(completedAttempts);
    }

    static inline uint64_t nextSubmitAttemptAt(uint64_t now)
    {
        return now + kRetryDelayMs;
    }

    static inline bool isSubmitRetryDue(uint64_t retryAt, uint64_t now)
    {
        return retryAt && now >= retryAt;
    }

    static inline SubmitDecision::Outcome terminalSubmitOutcome(
        SubmitDecision::Outcome lastOutcome, bool hadIndeterminateOutcome)
    {
        return hadIndeterminateOutcome &&
            lastOutcome != SubmitDecision::Outcome::Accepted
                ? SubmitDecision::Outcome::Indeterminate
                : lastOutcome;
    }

    static SubmitDecision classifySubmitResult(const rapidjson::Value &result);
};


} /* namespace xmrig */


#endif /* XMRIG_DAEMONRECONCILIATION_H */
