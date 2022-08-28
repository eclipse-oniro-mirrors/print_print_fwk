/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_SERVICE_MANAGER_H
#define PRINT_SERVICE_MANAGER_H

#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <stdint.h>
#include <functional>
#include <mutex>
#include <iosfwd>
#include <vector>
#include "print_extension_Info.h"
#include "print_cap_ability.h"
#include "print_job.h"
#include "print_info.h"

#include "constant.h"

namespace OHOS::Print {
class PrintServiceManager final {
public:
    static PrintServiceManager *GetInstance();
    int32_t Dummy();
    bool ConnectPrinter(uint32_t printerId);
    bool DisconnectPrinter(uint32_t printerId);
    bool QueryExtensionAbilityInfos(std::vector<PrinterExtensionInfo> &arrayExtensionInfo);
    bool StartDiscoverPrinter(std::vector<uint32_t> extensionList);
    bool StopDiscoverPrinter();
    bool StartPrintJob(PrintJob jobinfo);
    bool CancelPrintJob(PrintJob jobinfo);
    bool AddPrinters(std::vector<PrintInfo> arrayPrintInfo);
    bool RemovePrinters(std::vector<PrintInfo> arrayPrintInfo);
    bool UpdatePrinterState(uint32_t printerId, uint32_t state);
    bool UpdatePrinterJobState(uint32_t jobId, uint32_t state);
    bool RequestPreview(PrintJob jobinfo, std::string &previewResult);
    bool QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability);

private:
    explicit PrintServiceManager();
    ~PrintServiceManager();

private:
    static std::mutex instanceLock_;
    static PrintServiceManager* instance_;

};
} // namespace OHOS::Request::Print
#endif // PRINT_SERVICE_MANAGER_H
