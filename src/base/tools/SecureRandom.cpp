/* XMRig
 * Copyright (c) 2016-2026 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
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

#include "base/tools/SecureRandom.h"


#include <uv.h>


#include <algorithm>
#include <cstdint>


bool xmrig::SecureRandom::fill(void *data, size_t size) noexcept
{
    if (size == 0) {
        return true;
    }

    if (data == nullptr) {
        return false;
    }

#   if UV_VERSION_HEX >= 0x012100
    auto *p = static_cast<uint8_t *>(data);

    // uv_random() limits one request to 256 KiB. Chunking keeps this API
    // correct for the full size_t range while preserving fail-closed behavior.
    constexpr size_t kMaxRequestSize = 256U * 1024U;

    while (size > 0) {
        const size_t n = std::min(size, kMaxRequestSize);

        // A null callback selects libuv's synchronous OS-CSPRNG path. In this
        // form, loop and request are unused and may both be null.
        if (uv_random(nullptr, nullptr, p, n, 0, nullptr) != 0) {
            return false;
        }

        p += n;
        size -= n;
    }

    return true;
#   else
    // uv_random() was added in libuv 1.33.0. Never fall back to a PRNG when
    // the build uses an older libuv; callers must treat this as a hard error.
    (void) data;
    (void) size;

    return false;
#   endif
}


bool xmrig::SecureRandom::bytes(size_t size, Buffer &out) noexcept
{
    try {
        out.resize(size);
    }
    catch (...) {
        out.clear();
        return false;
    }

    if (!fill(out.data(), out.size())) {
        out.clear();
        return false;
    }

    return true;
}
