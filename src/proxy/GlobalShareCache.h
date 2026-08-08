/* XMRig Proxy
 * Copyright (c) 2026 XMRig Proxy contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef XMRIG_GLOBALSHARECACHE_H
#define XMRIG_GLOBALSHARECACHE_H


#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>


namespace xmrig {


/**
 * Process-wide duplicate detection for daemon jobs.
 *
 * The proxy and every Miner callback run on libuv's main loop, so this cache
 * deliberately has no locking. A share key is the decoded 16-byte private
 * template entropy followed by the decoded 32-byte PoW result. This rejects a
 * replay through another connection without treating equal nonces used on
 * different templates as duplicates.
 */
class GlobalShareCache
{
public:
    enum class Result : uint8_t {
        Accepted,
        Duplicate,
        Capacity,
        Invalid
    };

    struct Reservation
    {
        std::string key;
        uint64_t sourceId = 0;
        uint64_t height   = 0;
        uint64_t token    = 0;

        inline bool valid() const noexcept { return token != 0; }
    };

    static constexpr size_t kMaxEntries = 131072;
    static constexpr size_t kMaxEntriesPerSource = 65536;
    static constexpr size_t kKeySize = 48;

    static bool makeKey(const char *entropyHex, const char *resultHash,
                        std::string &key);
    static void observeHeight(uint64_t sourceId, uint64_t height);
    static void setOwnerHeights(uintptr_t owner, uint64_t sourceId,
                                const std::vector<uint64_t> &heights);
    static void removeOwner(uintptr_t owner);
    static void release(const Reservation &reservation);
    static Result reserve(uint64_t sourceId, uint64_t height,
                          std::string key, Reservation &reservation);
    static void removeSource(uint64_t sourceId);

    // Introspection is intentionally tiny and exists for deterministic unit
    // tests and operational assertions; it does not expose submitted work.
    static bool hasHeight(uint64_t sourceId, uint64_t height);
    static size_t size();
    static size_t size(uint64_t sourceId);
    static uint64_t height(uint64_t sourceId);
    static void clear();
};


} // namespace xmrig


#endif // XMRIG_GLOBALSHARECACHE_H
