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

#include "print_shared_host.h"
namespace OHOS::Print {
class SmbHostSearchHelper {
public:
    SmbHostSearchHelper();
    ~SmbHostSearchHelper();
    
    std::vector<PrintSharedHost> GetSharedHosts();
    bool TestSmbHostAlive(const std::string& ip, int32_t timeoutMs = 1000);

private:
    class HighResTimer;
    class NetworkIpRange;
    class HostList;
    struct NbHostInfo;

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