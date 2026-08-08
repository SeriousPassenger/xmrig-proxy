/* XMRig
 * Copyright (c) 2020      cohcho      <https://github.com/cohcho>
 * Copyright (c) 2018-2020 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2020 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
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


#include "base/net/tools/LineReader.h"
#include "base/kernel/constants.h"
#include "base/kernel/interfaces/ILineListener.h"
#include "base/net/tools/NetBuffer.h"

#include <cassert>
#include <cstring>


xmrig::LineReader::~LineReader()
{
    NetBuffer::release(m_buf);
}


bool xmrig::LineReader::parse(char *data, size_t size)
{
    assert(m_listener != nullptr);
    if (!m_listener) {
        return false;
    }
    if (size == 0) {
        return true;
    }

    return getline(data, size);
}


void xmrig::LineReader::reset()
{
    if (m_buf) {
        NetBuffer::release(m_buf);
        m_buf = nullptr;
        m_pos = 0;
    }

    m_overflow = false;
}


bool xmrig::LineReader::add(const char *data, size_t size)
{
    // Keep one byte available for the NUL terminator required by the
    // in-situ JSON parsers used by both downstream and upstream clients.
    constexpr size_t maxPayload = XMRIG_NET_BUFFER_CHUNK_SIZE - 1;
    if (m_overflow || m_pos > maxPayload || size > maxPayload - m_pos) {
        if (m_buf) {
            NetBuffer::release(m_buf);
            m_buf = nullptr;
        }

        m_pos = 0;
        m_overflow = true;
        return false;
    }

    if (!m_buf) {
        m_buf = NetBuffer::allocate();
        m_pos = 0;
    }

    memcpy(m_buf + m_pos, data, size);
    m_pos += size;
    m_buf[m_pos] = '\0';
    return true;
}


bool xmrig::LineReader::getline(char *data, size_t size)
{
    char *end        = nullptr;
    char *start      = data;
    size_t remaining = size;
    bool valid       = true;

    while ((end = static_cast<char*>(memchr(start, '\n', remaining))) != nullptr) {
        *end = '\0';

        end++;

        const auto len = static_cast<size_t>(end - start);
        if (m_overflow) {
            // Discard the tail of the oversized physical record. Do not let a
            // syntactically valid suffix be interpreted as a new request.
            m_overflow = false;
            return false;
        }
        else if (m_pos) {
            // The delimiter is not part of the JSON payload and must not make
            // an otherwise exactly-at-limit fragmented record overflow.
            if (add(start, len - 1)) {
                // add() always maintains the terminator. This matters when a
                // JSON record is split across TCP/TLS reads: ParseInsitu()
                // receives a C string rather than an explicit length.
                m_listener->onLine(m_buf, m_pos);
                m_pos = 0;
            }
            else {
                m_overflow = false;
                return false;
            }
        }
        else if (len > 1) {
            if (len - 1 >= XMRIG_NET_BUFFER_CHUNK_SIZE) {
                return false;
            }
            else {
                m_listener->onLine(start, len - 1);
            }
        }

        remaining -= len;
        start = end;
    }

    if (remaining == 0) {
        reset();
        return valid;
    }

    if (!add(start, remaining)) {
        valid = false;
    }

    return valid;
}
