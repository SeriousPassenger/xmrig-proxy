/* XMRig Proxy
 * Copyright (c) 2026 XMRig Proxy contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "proxy/GlobalShareCache.h"


#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>


namespace xmrig {


namespace {


struct HeightEntries
{
    size_t owners = 0;
    std::unordered_map<std::string, uint64_t> entries;
};


struct SourceEntries
{
    uint64_t currentHeight = 0;
    std::unordered_map<uint64_t, HeightEntries> heights;
};


struct OwnerHeights
{
    uint64_t sourceId = 0;
    std::vector<uint64_t> heights;
};


std::unordered_map<uint64_t, SourceEntries> s_sources;
std::unordered_map<uintptr_t, OwnerHeights> s_owners;
std::unordered_map<std::string, uint64_t> s_keys;
uint64_t s_sequence = 0;


int hexValue(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}


bool appendHex(std::string &out, const char *hex, size_t size)
{
    if (!hex || (size & 1U) != 0) {
        return false;
    }

    const size_t offset = out.size();
    out.resize(offset + size / 2);
    for (size_t i = 0; i < size; i += 2) {
        const int high = hexValue(static_cast<unsigned char>(hex[i]));
        const int low  = hexValue(static_cast<unsigned char>(hex[i + 1]));
        if (high < 0 || low < 0) {
            out.resize(offset);
            return false;
        }

        out[offset + i / 2] = static_cast<char>((high << 4) | low);
    }

    return true;
}


void eraseEntries(HeightEntries &height)
{
    for (const auto &entry : height.entries) {
        const auto keyIt = s_keys.find(entry.first);
        if (keyIt != s_keys.end() && keyIt->second == entry.second) {
            s_keys.erase(keyIt);
        }
    }
}


void eraseHeightIfUnused(uint64_t sourceId, uint64_t height)
{
    const auto sourceIt = s_sources.find(sourceId);
    if (sourceIt == s_sources.end() || sourceIt->second.currentHeight == height) {
        return;
    }

    auto heightIt = sourceIt->second.heights.find(height);
    if (heightIt == sourceIt->second.heights.end() || heightIt->second.owners != 0) {
        return;
    }

    eraseEntries(heightIt->second);
    sourceIt->second.heights.erase(heightIt);
}


void detachOwner(uintptr_t owner)
{
    const auto ownerIt = s_owners.find(owner);
    if (ownerIt == s_owners.end()) {
        return;
    }

    const OwnerHeights previous = ownerIt->second;
    s_owners.erase(ownerIt);

    const auto sourceIt = s_sources.find(previous.sourceId);
    if (sourceIt == s_sources.end()) {
        return;
    }

    for (const uint64_t height : previous.heights) {
        const auto heightIt = sourceIt->second.heights.find(height);
        if (heightIt != sourceIt->second.heights.end() && heightIt->second.owners != 0) {
            --heightIt->second.owners;
        }
    }

    for (const uint64_t height : previous.heights) {
        eraseHeightIfUnused(previous.sourceId, height);
    }
}


} // namespace


bool GlobalShareCache::makeKey(const char *entropyHex, const char *resultHash,
                               std::string &key)
{
    key.clear();
    if (!entropyHex || !resultHash || strlen(entropyHex) != 32 || strlen(resultHash) != 64) {
        return false;
    }

    key.reserve(kKeySize);
    if (!appendHex(key, entropyHex, 32) || !appendHex(key, resultHash, 64)) {
        key.clear();
        return false;
    }

    return true;
}


void GlobalShareCache::observeHeight(uint64_t sourceId, uint64_t height)
{
    if (sourceId == 0 || height == 0) {
        return;
    }

    SourceEntries &source = s_sources[sourceId];
    source.currentHeight = height;
    source.heights.emplace(height, HeightEntries{});

    for (auto it = source.heights.begin(); it != source.heights.end();) {
        if (it->first != height && it->second.owners == 0) {
            eraseEntries(it->second);
            it = source.heights.erase(it);
        }
        else {
            ++it;
        }
    }
}


void GlobalShareCache::setOwnerHeights(uintptr_t owner, uint64_t sourceId,
                                       const std::vector<uint64_t> &heights)
{
    if (owner == 0) {
        return;
    }

    if (sourceId == 0 || heights.empty()) {
        detachOwner(owner);
        return;
    }

    OwnerHeights ownerHeights;
    ownerHeights.sourceId = sourceId;

    std::unordered_set<uint64_t> unique;
    for (const uint64_t height : heights) {
        if (height == 0 || !unique.insert(height).second) {
            continue;
        }

        ownerHeights.heights.push_back(height);
    }

    if (ownerHeights.heights.empty()) {
        detachOwner(owner);
        return;
    }

    // Attach the replacement references before detaching the previous set.
    // That keeps a non-current bucket alive when it remains eligible across
    // a same-height refresh or a downward reorganization.
    SourceEntries &source = s_sources[sourceId];
    for (const uint64_t height : ownerHeights.heights) {
        ++source.heights[height].owners;
    }

    detachOwner(owner);
    s_owners.emplace(owner, std::move(ownerHeights));
}


void GlobalShareCache::removeOwner(uintptr_t owner)
{
    if (owner != 0) {
        detachOwner(owner);
    }
}


void GlobalShareCache::release(const Reservation &reservation)
{
    if (!reservation.valid()) {
        return;
    }

    const auto sourceIt = s_sources.find(reservation.sourceId);
    if (sourceIt == s_sources.end()) {
        return;
    }

    const auto heightIt = sourceIt->second.heights.find(reservation.height);
    if (heightIt == sourceIt->second.heights.end()) {
        return;
    }

    auto &entries = heightIt->second.entries;
    const auto entryIt = entries.find(reservation.key);
    if (entryIt != entries.end() && entryIt->second == reservation.token) {
        entries.erase(entryIt);
        const auto keyIt = s_keys.find(reservation.key);
        if (keyIt != s_keys.end() && keyIt->second == reservation.token) {
            s_keys.erase(keyIt);
        }
    }
}


GlobalShareCache::Result GlobalShareCache::reserve(uint64_t sourceId, uint64_t height,
                                                   std::string key, Reservation &reservation)
{
    reservation = {};
    if (sourceId == 0 || height == 0 || key.size() != kKeySize) {
        return Result::Invalid;
    }

    const auto sourceIt = s_sources.find(sourceId);
    if (sourceIt == s_sources.end()) {
        return Result::Invalid;
    }

    const auto heightIt = sourceIt->second.heights.find(height);
    if (heightIt == sourceIt->second.heights.end()) {
        return Result::Invalid;
    }

    HeightEntries &heightEntries = heightIt->second;
    if (s_keys.find(key) != s_keys.end()) {
        return Result::Duplicate;
    }

    size_t sourceSize = 0;
    for (const auto &entry : sourceIt->second.heights) {
        sourceSize += entry.second.entries.size();
    }
    if (s_keys.size() >= kMaxEntries || sourceSize >= kMaxEntriesPerSource) {
        return Result::Capacity;
    }

    uint64_t token = ++s_sequence;
    if (token == 0) {
        token = ++s_sequence;
    }

    auto inserted = heightEntries.entries.emplace(key, token);
    if (!inserted.second) {
        return Result::Duplicate;
    }

    const auto global = s_keys.emplace(std::move(key), token);
    if (!global.second) {
        heightEntries.entries.erase(inserted.first);
        return Result::Duplicate;
    }

    reservation.key = global.first->first;
    reservation.sourceId = sourceId;
    reservation.height = height;
    reservation.token = token;
    return Result::Accepted;
}


void GlobalShareCache::removeSource(uint64_t sourceId)
{
    const auto sourceIt = s_sources.find(sourceId);
    if (sourceIt == s_sources.end()) {
        return;
    }

    for (auto ownerIt = s_owners.begin(); ownerIt != s_owners.end();) {
        if (ownerIt->second.sourceId == sourceId) {
            ownerIt = s_owners.erase(ownerIt);
        }
        else {
            ++ownerIt;
        }
    }

    for (auto &height : sourceIt->second.heights) {
        eraseEntries(height.second);
    }
    s_sources.erase(sourceIt);
}


bool GlobalShareCache::hasHeight(uint64_t sourceId, uint64_t height)
{
    const auto sourceIt = s_sources.find(sourceId);
    return sourceIt != s_sources.end() &&
        sourceIt->second.heights.find(height) != sourceIt->second.heights.end();
}


size_t GlobalShareCache::size()
{
    return s_keys.size();
}


size_t GlobalShareCache::size(uint64_t sourceId)
{
    const auto sourceIt = s_sources.find(sourceId);
    if (sourceIt == s_sources.end()) {
        return 0;
    }

    size_t count = 0;
    for (const auto &height : sourceIt->second.heights) {
        count += height.second.entries.size();
    }
    return count;
}


uint64_t GlobalShareCache::height(uint64_t sourceId)
{
    const auto sourceIt = s_sources.find(sourceId);
    return sourceIt == s_sources.end() ? 0 : sourceIt->second.currentHeight;
}


void GlobalShareCache::clear()
{
    s_owners.clear();
    s_sources.clear();
    s_keys.clear();
}


} // namespace xmrig
