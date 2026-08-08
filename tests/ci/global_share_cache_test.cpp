#include "proxy/GlobalShareCache.h"
#include "proxy/ShareHeightPolicy.h"


#include <cassert>
#include <string>


using xmrig::GlobalShareCache;
using xmrig::ShareHeightPolicy;


namespace {


std::string repeated(char value, size_t count)
{
    return std::string(count, value);
}


} // namespace


int main()
{
    static constexpr uint64_t kSourceA = 1;
    static constexpr uint64_t kSourceB = 2;
    static constexpr uint64_t kHeight  = 3735895;
    static constexpr uintptr_t kMinerA = 101;
    static constexpr uintptr_t kMinerB = 102;

    const std::string entropy = repeated('2', 32);
    const std::string otherEntropy = repeated('4', 32);
    const std::string resultLower = repeated('a', 64);
    const std::string resultUpper = repeated('A', 64);
    const std::string otherResult = repeated('b', 64);
    const std::string sourceBEntropy = repeated('6', 32);
    const std::string sourceBResult = repeated('d', 64);

    GlobalShareCache::clear();
    GlobalShareCache::observeHeight(kSourceA, kHeight);
    GlobalShareCache::observeHeight(kSourceB, kHeight);
    GlobalShareCache::setOwnerHeights(kMinerA, kSourceA, { kHeight });
    GlobalShareCache::setOwnerHeights(kMinerB, kSourceA, { kHeight });
    assert(GlobalShareCache::height(kSourceA) == kHeight);
    assert(GlobalShareCache::hasHeight(kSourceA, kHeight));

    // Template identity and parent changes are irrelevant to staleness. Only
    // the newest height successfully sent to that miner is authoritative.
    assert(!ShareHeightPolicy::isStale(kHeight, kHeight));
    assert(ShareHeightPolicy::isStale(kHeight, kHeight + 1));
    assert(!ShareHeightPolicy::isStale(kHeight + 1, kHeight));
    assert(!ShareHeightPolicy::isStale(0, kHeight));
    assert(!ShareHeightPolicy::isStale(kHeight, 0));

    std::string share;
    std::string sameShare;
    std::string differentTemplate;
    std::string differentResult;
    assert(GlobalShareCache::makeKey(entropy.c_str(), resultLower.c_str(), share));
    assert(GlobalShareCache::makeKey(entropy.c_str(), resultUpper.c_str(), sameShare));
    assert(GlobalShareCache::makeKey(otherEntropy.c_str(), resultLower.c_str(), differentTemplate));
    assert(GlobalShareCache::makeKey(entropy.c_str(), otherResult.c_str(), differentResult));
    assert(share.size() == 48);
    assert(share == sameShare);
    assert(share != differentTemplate);
    assert(share != differentResult);
    std::string invalid;
    assert(!GlobalShareCache::makeKey("00", resultLower.c_str(), invalid));
    assert(!GlobalShareCache::makeKey(entropy.c_str(), repeated('z', 64).c_str(), invalid));
    GlobalShareCache::Reservation invalidReservation;
    assert(GlobalShareCache::reserve(kSourceA, kHeight, "short", invalidReservation) ==
           GlobalShareCache::Result::Invalid);

    GlobalShareCache::Reservation first;
    GlobalShareCache::Reservation duplicate;
    assert(GlobalShareCache::reserve(kSourceA, kHeight, share, first) ==
           GlobalShareCache::Result::Accepted);
    assert(GlobalShareCache::reserve(kSourceA, kHeight, sameShare, duplicate) ==
           GlobalShareCache::Result::Duplicate);

    // Equal results on different private templates are different shares.
    GlobalShareCache::Reservation otherTemplate;
    assert(GlobalShareCache::reserve(kSourceA, kHeight, differentTemplate, otherTemplate) ==
           GlobalShareCache::Result::Accepted);

    // A different result on the same private template is different work.
    GlobalShareCache::Reservation otherShare;
    assert(GlobalShareCache::reserve(kSourceA, kHeight, differentResult, otherShare) ==
           GlobalShareCache::Result::Accepted);

    // Identity is process-global rather than connection- or source-scoped.
    GlobalShareCache::Reservation otherSource;
    assert(GlobalShareCache::reserve(kSourceB, kHeight, share, otherSource) ==
           GlobalShareCache::Result::Duplicate);
    std::string sourceBShare;
    assert(GlobalShareCache::makeKey(sourceBEntropy.c_str(), sourceBResult.c_str(), sourceBShare));
    assert(GlobalShareCache::reserve(kSourceB, kHeight, sourceBShare, otherSource) ==
           GlobalShareCache::Result::Accepted);

    // Same-height template/parent changes preserve duplicate records.
    GlobalShareCache::observeHeight(kSourceA, kHeight);
    assert(GlobalShareCache::size(kSourceA) == 3);

    // One miner successfully receives the next-height job while another
    // remains on the old job. Observing the new source height must preserve
    // the old duplicate bucket for that lagging miner.
    GlobalShareCache::setOwnerHeights(kMinerA, kSourceA, { kHeight + 1 });
    GlobalShareCache::observeHeight(kSourceA, kHeight + 1);
    assert(GlobalShareCache::height(kSourceA) == kHeight + 1);
    assert(GlobalShareCache::size(kSourceA) == 3);
    assert(GlobalShareCache::size(kSourceB) == 1);

    // The lagging miner may still submit retained work at its last-sent
    // height, and an old submission can never roll the source height back.
    std::string laggingKey;
    assert(GlobalShareCache::makeKey(entropy.c_str(), repeated('c', 64).c_str(), laggingKey));
    GlobalShareCache::Reservation oldHeight;
    assert(GlobalShareCache::reserve(kSourceA, kHeight, laggingKey, oldHeight) ==
           GlobalShareCache::Result::Accepted);
    assert(GlobalShareCache::height(kSourceA) == kHeight + 1);

    // The next-height template has independent entropy and therefore a new
    // global identity. Reusing the old identity here would be a duplicate
    // even though it was presented through another source or height bucket.
    std::string currentKey;
    assert(GlobalShareCache::makeKey(repeated('8', 32).c_str(), resultLower.c_str(), currentKey));
    GlobalShareCache::Reservation current;
    assert(GlobalShareCache::reserve(kSourceA, kHeight + 1, currentKey, current) ==
           GlobalShareCache::Result::Accepted);

    // Once the last lagging miner receives the new-height job, its old bucket
    // is no longer submit-eligible and is released immediately.
    GlobalShareCache::setOwnerHeights(kMinerB, kSourceA, { kHeight + 1 });
    assert(GlobalShareCache::size(kSourceA) == 1);
    assert(!GlobalShareCache::hasHeight(kSourceA, kHeight));
    assert(GlobalShareCache::reserve(kSourceA, kHeight, laggingKey, oldHeight) ==
           GlobalShareCache::Result::Invalid);

    GlobalShareCache::release(current);

    GlobalShareCache::Reservation retry;
    assert(GlobalShareCache::reserve(kSourceA, kHeight + 1, currentKey, retry) ==
           GlobalShareCache::Result::Accepted);
    GlobalShareCache::release(current); // stale token must not erase retry
    assert(GlobalShareCache::reserve(kSourceA, kHeight + 1, currentKey, duplicate) ==
           GlobalShareCache::Result::Duplicate);

    // A downward reorganization follows the same strict-greater-than stale
    // rule: a retained higher-height job remains eligible, so its duplicate
    // bucket must remain available alongside the newly sent lower height.
    GlobalShareCache::setOwnerHeights(kMinerA, kSourceA, { kHeight, kHeight + 1 });
    GlobalShareCache::setOwnerHeights(kMinerB, kSourceA, { kHeight });
    GlobalShareCache::observeHeight(kSourceA, kHeight);
    assert(!ShareHeightPolicy::isStale(kHeight + 1, kHeight));
    assert(GlobalShareCache::hasHeight(kSourceA, kHeight + 1));
    assert(GlobalShareCache::reserve(kSourceA, kHeight + 1, currentKey, duplicate) ==
           GlobalShareCache::Result::Duplicate);
    GlobalShareCache::setOwnerHeights(kMinerA, kSourceA, { kHeight, kHeight + 1 });
    assert(GlobalShareCache::reserve(kSourceA, kHeight + 1, currentKey, duplicate) ==
           GlobalShareCache::Result::Duplicate);

    // A true new-block transition clears the prior bucket after all miners
    // have successfully moved, without disturbing another daemon source.
    GlobalShareCache::setOwnerHeights(kMinerA, kSourceA, { kHeight + 2 });
    GlobalShareCache::setOwnerHeights(kMinerB, kSourceA, { kHeight + 2 });
    GlobalShareCache::observeHeight(kSourceA, kHeight + 2);
    assert(GlobalShareCache::height(kSourceA) == kHeight + 2);
    assert(GlobalShareCache::size(kSourceA) == 0);
    assert(GlobalShareCache::size(kSourceB) == 1);

    GlobalShareCache::removeOwner(kMinerA);
    GlobalShareCache::removeOwner(kMinerB);

    GlobalShareCache::clear();
    assert(GlobalShareCache::size() == 0);
    return 0;
}
