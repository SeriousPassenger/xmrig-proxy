/* XMRig
 * Copyright (c) 2016-2026 XMRig, <support@xmrig.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */


#include "base/net/stratum/DaemonReconciliation.h"

#include "3rdparty/rapidjson/document.h"


#include <cctype>


namespace xmrig {


constexpr uint32_t DaemonReconciliation::kMaxSubmitAttempts;
constexpr uint64_t DaemonReconciliation::kRetryDelayMs;


namespace {


bool normalizedHex(const rapidjson::Value &object, const char *key, size_t size,
                   std::string &out)
{
    out.clear();
    if (!object.IsObject() || !key) {
        return false;
    }

    const auto member = object.FindMember(key);
    if (member == object.MemberEnd() || !member->value.IsString() ||
        member->value.GetStringLength() != size) {
        return false;
    }

    out.assign(member->value.GetString(), member->value.GetStringLength());
    for (char &c : out) {
        const unsigned char value = static_cast<unsigned char>(c);
        if (!std::isxdigit(value)) {
            out.clear();
            return false;
        }
        c = static_cast<char>(std::tolower(value));
    }

    return true;
}


} // namespace


DaemonReconciliation::SubmitDecision
DaemonReconciliation::classifySubmitResult(const rapidjson::Value &result)
{
    SubmitDecision decision;
    if (!result.IsObject()) {
        decision.reason = "Invalid submitblock response";
        return decision;
    }

    const auto status = result.FindMember("status");
    if (status == result.MemberEnd() || !status->value.IsString()) {
        decision.reason = "Missing or invalid submitblock status";
        return decision;
    }

    const std::string statusText(status->value.GetString(),
                                 status->value.GetStringLength());
    if (statusText.empty() || statusText.find('\0') != std::string::npos) {
        decision.reason = "Missing or invalid submitblock status";
        return decision;
    }

    if (statusText != "OK") {
        decision.outcome = SubmitDecision::Outcome::Rejected;
        decision.reason = "submitblock status: ";
        decision.reason += statusText;
        return decision;
    }

    // A successful daemon response is the primary acceptance decision. The
    // block ID is optional metadata on older daemons; if present and valid it
    // is canonical, but its absence or malformed value cannot undo status OK.
    decision.outcome = SubmitDecision::Outcome::Accepted;
    const auto blockId = result.FindMember("block_id");
    if (blockId == result.MemberEnd()) {
        decision.reason = "submitblock returned status OK without block_id";
        return decision;
    }

    if (!normalizedHex(result, "block_id", 64, decision.blockId)) {
        decision.reason = "submitblock returned status OK with an invalid block_id";
    }

    return decision;
}
} /* namespace xmrig */
