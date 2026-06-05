/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef BASE_PRINT_SECURITY_GUARD_H
#define BASE_PRINT_SECURITY_GUARD_H

#include <map>
#include <mutex>
#include <vector>

#include "print_security_guard_info.h"
#include "print_system_data.h"

namespace OHOS::Print {
class PrintSecurityGuardManager {
public:
    void receiveBaseInfo(const std::string jobId, const std::string callerPkg,
        const std::vector<std::string> &fileList);
    void receiveJobStateUpdate(const std::string jobId, const PrinterInfo &printerInfo, const PrintJob &printJob);
    void receiveAuditInfo(const std::string jobId, const PrinterInfo &printerInfo,
        const PrintJob &printJob, const std::vector<std::string> &fileInfos);
    void clearAll();

    // Orchestration methods
    std::vector<std::string> GetFileList(const std::string &jobId) const;
    void SetFileAuditInfo(const std::string &jobId, const std::vector<std::string> &fileInfos);
    std::vector<std::string> GetFileAuditInfo(const std::string &jobId) const;
    void CalculateFileAuditInfo(const std::string &jobId);
    void SendJobAuditInfo(const std::string &jobId, const PrinterInfo &printerInfo, const PrintJob &printJob);
    void InjectFileListIntoOption(const std::string &jobId, std::string &option);

    // Resolve PrinterInfo with fallback chain: discovered -> added -> option JSON
    std::shared_ptr<PrinterInfo> ResolvePrinterInfo(
        const std::string &printerId, const std::string &option, PrintSystemData &printSystemData);

private:
    void ReportSecurityInfo(const int32_t eventId, const std::string version, const std::string content);
    void clearSecurityMap(const std::string jobId);

private:
    std::map<std::string, std::shared_ptr<PrintSecurityGuardInfo>> securityMap_;
    mutable std::mutex securityMapMutex_;
};
} // namespace OHOS::Print

#endif // BASE_PRINT_SECURITY_GUARD_H
