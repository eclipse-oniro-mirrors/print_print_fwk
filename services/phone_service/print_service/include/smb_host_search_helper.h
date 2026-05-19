/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SMB_HOST_SEARCH
#define SMB_HOST_SEARCH

#include <arpa/inet.h>
#include "print_shared_host.h"
namespace OHOS::Print {
const int32_t QUESTION_NAME_SIZE = 34;

class SmbHostSearchHelper {
public:
    SmbHostSearchHelper();
    ~SmbHostSearchHelper();
    
    std::vector<PrintSharedHost> GetSharedHosts();
    bool TestSmbHostAlive(const std::string& ip, int32_t timeoutMs = 1000);

private:
    class HighResTimer {
    public:
        HighResTimer(int32_t intervalUs);
        bool CanSend();
        void UpdateSendTime();

    private:
        void SetInterval(int32_t intervalUs);
        timespec lastSendTime_;
        int64_t sendIntervalNs_;
    };

    class NetworkIpRange {
    public:
        NetworkIpRange(const std::string& start, const std::string& end);
        static std::unique_ptr<NetworkIpRange> CreateFromLocalNetwork();
        
        bool Next(struct in_addr* nextAddr);
        
    private:
        static bool GetLocalIPAndMask(std::string& ipStr, std::string& netmaskStr);
        static std::pair<std::string, std::string> CalculateSubnetRange(const std::string& ipStr,
            const std::string& netmaskStr);
        struct in_addr start_;
        struct in_addr end_;
        struct in_addr current_;
    };

    class HostList {
    public:
        bool Contains(uint32_t ip) const;
        void Add(uint32_t ip, const std::string& name);
        std::vector<PrintSharedHost> GetPrintSharedHost() const;
    private:
        std::unordered_map<uint32_t, std::string> responsedHosts_;
    };

    class EncodingConverter {
    public:
        static bool GbkToUtf8Iconv(const std::string& gbkInput, std::string& utf8Output);
    };

    struct NbnameRequest {
        uint16_t transactionId;
        uint16_t flags;
        uint16_t questionCount;
        uint16_t answerCount;
        uint16_t nameServiceCount;
        uint16_t additionalRecordCount;
        char questionName[QUESTION_NAME_SIZE];
        uint16_t questionType;
        uint16_t questionClass;
    };

    bool InitializeSock();
    void SetTimeval(timeval &timeout, const long &tvSec, const long &tvUsec);
    bool SendQuery(const struct in_addr& destAddr);
    bool HandleSend();
    bool HandleReceive();
    void SetQuestionName(struct NbnameRequest &request);
    std::string GetFileServerName();
    
    int32_t sock_;
    std::unique_ptr<NetworkIpRange> ipRange_;
    std::unique_ptr<HighResTimer> timer_;
    std::unique_ptr<HostList> scannedHosts_;
    std::vector<char> recvBuffer_;
};
}   // namespace OHOS::Print
#endif // SMB_HOST_SEARCH