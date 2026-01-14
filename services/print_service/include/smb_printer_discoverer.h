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
#ifndef SMB_PRINTER_MANAGER
#define SMB_PRINTER_MANAGER

#include <string>
#include <vector>
#include <cstring>
#include "printer_info.h"
#include "print_shared_host.h"
#include "smb_library.h"

namespace OHOS::Print {
class SmbPrinterDiscoverer {
public:
    SmbPrinterDiscoverer();
    ~SmbPrinterDiscoverer();
    int32_t QuerySmbPrinters(const PrintSharedHost& sharedHost, const std::string &userName,
        char *userPasswd, std::vector<PrinterInfo> &infos);
    static std::string ParseIpFromSmbPrinterId(const std::string& printerId);
    static bool IsSmbPrinterId(const std::string& printerId);
private:
    int32_t SetCredentials(const std::string &userName, char *userPasswd);
    void ShareEnumCallback(struct smb2_context* smb2, int32_t status, void* command_data);
    int32_t SmbEventLoop();
    std::string CreatePrinterId(const std::string& ip, const std::string& name);
    void GeneratePrinterInfos(const std::string& ip, std::vector<PrinterInfo> &infos);
    std::string ReplaceSpacesInPrinterUri(const std::string& input);

    struct PrinterShareInfo;
    struct smb2_context* smbCtx_;
    std::vector<PrinterShareInfo> printers_;
    std::atomic<bool> isFinished_{ false };
    std::shared_ptr<SmbLibrary> smbLib_;
};
}  // namespace OHOS::Print
#endif  // SMB_PRINTER_MANAGER
