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

#ifndef PRINT_SERVICE_PROXY_H
#define PRINT_SERVICE_PROXY_H

#include "iprint_service.h"
#include "iremote_proxy.h"

namespace OHOS::Print {
class PrintServiceProxy : public IRemoteProxy<IPrintService> {
public:
    explicit PrintServiceProxy(const sptr<IRemoteObject> &object);
    ~PrintServiceProxy() = default;
    DISALLOW_COPY_AND_MOVE(PrintServiceProxy);
    int32_t StartPrint() override;
    bool ConnectPrinter(uint32_t printerId) override;
    bool DisconnectPrinter(uint32_t printerId) override;
    bool QueryAllExtension(std::vector<PrintExtensionInfo> &arrayExtensionInfo) override;
    bool StartDiscoverPrinter(const std::vector<uint32_t> &extensionList) override;
    bool StopDiscoverPrinter() override;
    bool StartPrintJob(const PrintJob &jobinfo) override;
    bool CancelPrintJob(const PrintJob &jobinfo) override;
    bool AddPrinters(const std::vector<PrinterInfo> &arrayPrintInfo) override;
    bool RemovePrinters(const std::vector<PrinterInfo> &arrayPrintInfo) override;
    bool UpdatePrinterState(uint32_t printerId, uint32_t state) override;
    bool UpdatePrinterJobState(uint32_t jobId, uint32_t state) override;
    bool RequestPreview(const PrintJob &jobinfo, std::string &previewResult) override;
    bool QueryPrinterCapability(uint32_t printerId, PrinterCapability &printerCapability) override;
    bool CheckPermission() override;
    bool On(const std::string &type, uint32_t &state, PrinterInfo &info, const sptr<IPrintCallback> &listener) override;
    bool Off(const std::string &type) override;
    bool RegisterExtCallback(uint32_t callbackId, const sptr<IPrintExtensionCallback> &listener) override;
    bool UnregisterAllExtCallback() override;

private:
    void BuildParcelFromPrintJob(MessageParcel &data, const PrintJob &jobinfo);
    void BuildParcelFromPrinterInfo(MessageParcel &data, const PrinterInfo &printerInfo);

private:
    static inline BrokerDelegator<PrintServiceProxy> delegator_;
};
} // namespace OHOS::Print
#endif // PRINT_SERVICE_PROXY_H
