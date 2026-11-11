/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef I_REMOTE_PRINTER_MANAGER_H
#define I_REMOTE_PRINTER_MANAGER_H

#include "i_print_feature.h"
#include "printer_info.h"
#include "print_constant.h"
#include "json/json.h"

namespace OHOS::Print {

class IRemotePrinterEventHandler {
public:
    virtual ~IRemotePrinterEventHandler() = default;

    virtual int32_t OnAddRemotePrinter(const PrinterInfo &info, const std::string &extensionId) = 0;
    virtual bool OnRemoveRemotePrinter(const std::string &uri) = 0;
};

class IRemotePrinterManager : public IPrintFeature {
public:
    ~IRemotePrinterManager() override = default;

    virtual void SetEventHandler(IRemotePrinterEventHandler *handler) = 0;

    virtual bool Destroy() = 0;
    virtual bool Disconnect() = 0;
    virtual void StartPrinterDiscovery() = 0;
    virtual bool StopPrinterDiscovery() = 0;

    virtual std::shared_ptr<PrinterInfo> GetPrinterInfo(const std::string &printerId) = 0;
    virtual bool UpdatePrinterStatus(const std::string &printerId, PrinterStatus status) = 0;
    virtual bool OnPrinterListReceived(const Json::Value &jsonArray) = 0;
    virtual bool OnPrinterStatusReceived(const Json::Value &jsonArray) = 0;
    virtual void ClearAllPrinters() = 0;
};

} // namespace OHOS::Print
#endif // I_REMOTE_PRINTER_MANAGER_H
