/* XMRig
 * Copyright (c) 2019      Howard Chu  <https://github.com/hyc>
 * Copyright (c) 2018-2026 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2026 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef XMRIG_DAEMONCLIENT_H
#define XMRIG_DAEMONCLIENT_H


#include "base/kernel/interfaces/IHttpListener.h"
#include "base/net/stratum/BaseClient.h"
#include "base/net/stratum/DaemonTemplateSource.h"
#include "base/net/stratum/SubmitResult.h"
#include "base/tools/cryptonote/WalletAddress.h"


#include <deque>
#include <map>
#include <memory>
#include <string>


namespace xmrig {


class DaemonClient : public BaseClient,
                     public IHttpListener,
                     public DaemonTemplateSource::Listener
{
public:
    XMRIG_DISABLE_COPY_MOVE_DEFAULT(DaemonClient)

    DaemonClient(int id, IClientListener *listener);
    ~DaemonClient() override;

protected:
    bool disconnect() override;
    bool isTLS() const override;
    int64_t submit(const JobResult &result) override;
    void connect() override;
    void connect(const Pool &pool) override;
    void setPool(const Pool &pool) override;

    void onHttpData(const HttpData &data) override;
    void onDaemonTemplate(const std::shared_ptr<const DaemonTemplateSource::Snapshot> &snapshot) override;

    inline bool hasExtension(Extension) const noexcept override      { return false; }
    inline const char *mode() const override                         { return "daemon"; }
    inline const char *tlsFingerprint() const override               { return m_tlsFingerprint; }
    inline const char *tlsVersion() const override                   { return m_tlsVersion; }
    inline int64_t send(const rapidjson::Value &, Callback) override { return -1; }
    inline int64_t send(const rapidjson::Value &) override           { return -1; }
    void deleteLater() override;
    void tick(uint64_t) override;

private:
    struct JobContext
    {
        String blocktemplate;
        String entropy;
        String hashingBlob;
        String jobId;
        String prevHash;
        String seedHash;
        bool hasMinerSignature = false;
        bool hasViewTag        = false;
        size_t ephPublicKeyOffset = 0;
        size_t extraNonceOffset   = 0;
        size_t nonceOffset        = 0;
        size_t nonceSize          = 0;
        size_t signatureOffset    = 0;
        size_t txPublicKeyOffset  = 0;
        uint64_t createdSteadyMs  = 0;
        uint64_t difficulty       = 0;
        uint64_t generation       = 0;
        uint64_t height           = 0;
        uint64_t sourceId         = 0;
    };

    struct PendingSubmission
    {
        SubmitResult result;
        String blockBlob;
        String expectedBlockId;
        String minerTxHash;
        std::string lastIndeterminateError;
        std::string retryRejection;
        int64_t retryRejectionCode = 0;
        uint64_t attemptStartedMs  = 0;
        uint32_t attempts          = 1;
    };

    const JobContext *findContext(const String &jobId) const;
    bool finalizeSubmission(int64_t id, SubmitResult::Outcome outcome, const char *message,
                            int64_t errorCode = 0, const char *blockId = nullptr,
                            bool reconciled = false);
    bool installTemplate(const std::shared_ptr<const DaemonTemplateSource::Snapshot> &snapshot);
    bool onIndeterminateSubmit(int64_t id, const char *message);
    bool parseReconcileResponse(int64_t id, const rapidjson::Value &result,
                                const rapidjson::Value &error);
    bool prepareSpendKey(Job &job, const class BlockTemplate &blocktemplate, const char **error);
    bool parseSubmitResponse(int64_t id, const rapidjson::Value &result, const rapidjson::Value &error);
    void publishSubmissionRow(const char *event, const PendingSubmission &submission,
                              int64_t requestId, const char *status, const char *message = nullptr,
                              int64_t errorCode = 0, const char *blockId = nullptr,
                              bool includeBlockBlob = false) const;
    int64_t reconcileSubmission(int64_t id, const char *reason);
    int64_t retrySubmission(int64_t id, const char *reason);
    int64_t rpcSend(const rapidjson::Document &doc,
                    const std::map<std::string, std::string> &headers,
                    int userType);
    void setState(SocketState state);
    void trimContexts();

    Coin m_coin;
    bool m_destroying = false;
    std::deque<JobContext> m_contexts;
    std::shared_ptr<IHttpListener> m_httpListener;
    std::map<int64_t, PendingSubmission> m_pendingSubmissions;
    std::shared_ptr<const DaemonTemplateSource::Snapshot> m_pendingSnapshot;
    DaemonTemplateSource::Ptr m_source;
    String m_tlsFingerprint;
    String m_tlsVersion;
    WalletAddress m_walletAddress;
};


} /* namespace xmrig */


#endif /* XMRIG_DAEMONCLIENT_H */
