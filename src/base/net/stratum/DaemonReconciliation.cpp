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


#include <algorithm>
#include <cctype>
#include <cstring>
#include <utility>


namespace xmrig {


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


bool normalizedHex(const rapidjson::Value &object, const char *key,
                   std::string &out)
{
    out.clear();
    if (!object.IsObject() || !key) {
        return false;
    }

    const auto member = object.FindMember(key);
    if (member == object.MemberEnd() || !member->value.IsString() ||
        member->value.GetStringLength() == 0 ||
        (member->value.GetStringLength() & 1U) != 0) {
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


bool optionalFalse(const rapidjson::Value &object, const char *key)
{
    const auto member = object.FindMember(key);
    return member == object.MemberEnd() ||
        (member->value.IsBool() && !member->value.GetBool());
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


DaemonReconciliation::Match DaemonReconciliation::matchCanonicalBlock(
    const rapidjson::Value &result, uint64_t expectedHeight,
    const char *expectedMinerTxHash, const char *expectedBlockBlob)
{
    Match match;
    if (!result.IsObject()) {
        match.reason = "invalid get_block result";
        return match;
    }

    const auto status = result.FindMember("status");
    if (status == result.MemberEnd() || !status->value.IsString() ||
        status->value.GetStringLength() != 2 ||
        memcmp(status->value.GetString(), "OK", 2) != 0) {
        match.reason = "get_block did not return status OK";
        return match;
    }

    if (!optionalFalse(result, "untrusted")) {
        match.reason = "get_block response is untrusted or malformed";
        return match;
    }

    const auto headerMember = result.FindMember("block_header");
    if (headerMember == result.MemberEnd() || !headerMember->value.IsObject()) {
        match.reason = "get_block response has no block header";
        return match;
    }

    const rapidjson::Value &header = headerMember->value;
    const auto height = header.FindMember("height");
    if (height == header.MemberEnd() || !height->value.IsUint64() ||
        height->value.GetUint64() != expectedHeight) {
        match.reason = "get_block returned a different height";
        return match;
    }

    const auto orphan = header.FindMember("orphan_status");
    if (orphan == header.MemberEnd() || !orphan->value.IsBool() ||
        orphan->value.GetBool()) {
        match.reason = "get_block did not return a canonical main-chain block";
        return match;
    }

    std::string blockId;
    std::string minerTxHash;
    if (!normalizedHex(header, "hash", 64, blockId)) {
        match.reason = "get_block returned an invalid canonical block hash";
        return match;
    }
    if (!normalizedHex(header, "miner_tx_hash", 64, minerTxHash)) {
        match.reason = "get_block returned an invalid miner transaction hash";
        return match;
    }

    std::string expectedMiner = expectedMinerTxHash ? expectedMinerTxHash : "";
    std::transform(expectedMiner.begin(), expectedMiner.end(), expectedMiner.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (expectedMiner.size() != 64 || minerTxHash != expectedMiner) {
        match.reason = "canonical block has a different miner transaction";
        return match;
    }

    std::string returnedBlob;
    if (!normalizedHex(result, "blob", returnedBlob)) {
        match.reason = "get_block returned an invalid canonical block blob";
        return match;
    }

    std::string expectedBlob = expectedBlockBlob ? expectedBlockBlob : "";
    std::transform(expectedBlob.begin(), expectedBlob.end(), expectedBlob.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (returnedBlob != expectedBlob) {
        match.reason = "canonical block blob differs from the submitted block";
        return match;
    }

    // Current monerod repeats miner_tx_hash at result scope. If present,
    // require it to agree with both the header and the submitted coinbase.
    const auto topMiner = result.FindMember("miner_tx_hash");
    if (topMiner != result.MemberEnd()) {
        std::string topMinerTxHash;
        if (!normalizedHex(result, "miner_tx_hash", 64, topMinerTxHash) ||
            topMinerTxHash != minerTxHash) {
            match.reason = "get_block returned inconsistent miner transaction hashes";
            return match;
        }
    }

    match.accepted = true;
    match.blockId = std::move(blockId);
    return match;
}


} /* namespace xmrig */
