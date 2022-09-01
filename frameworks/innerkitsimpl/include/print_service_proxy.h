/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_SERVICE_PROXY_H
#define PRINT_SERVICE_PROXY_H

#include "iremote_proxy.h"
#include "print_notify_interface.h"
#include "print_service_interface.h"

namespace OHOS::Print {
class PrintServiceProxy : public IRemoteProxy<PrintServiceInterface> {
public:
    explicit PrintServiceProxy(const sptr<IRemoteObject> &object);
    ~PrintServiceProxy() = default;
    DISALLOW_COPY_AND_MOVE(PrintServiceProxy);
    int32_t Dummy() override;
    bool ConnectPrinter(uint32_t printerId) override;
    bool DisconnectPrinter(uint32_t printerId) override;
    bool QueryAllExtension(std::vector<PrinterExtensionInfo> &arrayExtensionInfo) override;
    bool StartDiscoverPrinter(std::vector<uint32_t> extensionList) override;
    bool StopDiscoverPrinter() override;
    bool StartPrintJob(PrintJob jobinfo) override;
    bool CancelPrintJob(PrintJob jobinfo) override;
    bool AddPrinters(std::vector<PrintInfo> arrayPrintInfo) override;
    bool RemovePrinters(std::vector<PrintInfo> arrayPrintInfo) override;
    bool UpdatePrinterState(uint32_t printerId, uint32_t state) override;
    bool UpdatePrinterJobState(uint32_t jobId, uint32_t state) override;
    bool RequestPreview(PrintJob jobinfo, std::string &previewResult) override;
    bool QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability) override;
    bool CheckPermission() override;
    bool On(uint32_t taskId, const std::string &type, const sptr<PrintNotifyInterface> &listener) override;
    bool Off(uint32_t taskId, const std::string &type) override;

private:
    static inline BrokerDelegator<PrintServiceProxy> delegator_;
};
} // namespace OHOS::Print
#endif // PRINT_SERVICE_PROXY_H
