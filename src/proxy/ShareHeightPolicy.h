/* XMRig Proxy
 * Copyright (c) 2026 XMRig Proxy contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef XMRIG_SHAREHEIGHTPOLICY_H
#define XMRIG_SHAREHEIGHTPOLICY_H


#include <cstdint>


namespace xmrig {


class ShareHeightPolicy
{
public:
    static inline bool isStale(uint64_t submittedHeight, uint64_t latestSentHeight) noexcept
    {
        return submittedHeight != 0 && latestSentHeight > submittedHeight;
    }
};


} // namespace xmrig


#endif // XMRIG_SHAREHEIGHTPOLICY_H
