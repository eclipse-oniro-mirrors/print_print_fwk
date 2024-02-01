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
#ifndef MOCK_PRINT_SERVICE_H
#define MOCK_PRINT_SERVICE_H

#include <gmock/gmock.h>
#include "print_constant.h"
#include "print_service_stub.h"

namespace OHOS {
namespace Print {
class DummyPrintServiceStub : public PrintServiceStub {
public:
    int32_t StartPrint(const std::vector<std::string> &fileList,
        const std::vector<uint32_t> &fdList, std::string &taskId) override
    {
            return E_PRINT_NONE;
    }
    int32_t StartPrint(const std::vector<std::string> &fileList,
        const std::vector<uint32_t> &fdList, std::string &taskId, const sptr<IRemoteObject> &token) override
    {
            return E_PRINT_NONE;
    }
    int32_t StopPrint(const std::string &taskId) override
    {
        return E_PRINT_NONE;
    }
    int32_t ConnectPrinter(const std::string &printerId) override
    {
        return E_PRINT_NONE;
    }
    int32_t DisconnectPrinter(const std::string &printerId) override
    {
        return E_PRINT_NONE;
    }
    int32_t StartDiscoverPrinter(const std::vector<std::string> &extensionList) override
    {
        return E_PRINT_NONE;
    }
    int32_t StopDiscoverPrinter() override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos) override
    {
        return E_PRINT_NONE;
    }
    int32_t StartPrintJob(const PrintJob &jobInfo) override
    {
        return E_PRINT_NONE;
    }
    int32_t CancelPrintJob(const std::string &jobId) override
    {
        return E_PRINT_NONE;
    }
    int32_t AddPrinters(const std::vector<PrinterInfo> &printerInfos) override
    {
        return E_PRINT_NONE;
    }
    int32_t RemovePrinters(const std::vector<std::string> &printerIds) override
    {
        return E_PRINT_NONE;
    }
    int32_t UpdatePrinters(const std::vector<PrinterInfo> &printerInfos) override
    {
        return E_PRINT_NONE;
    }
    int32_t UpdatePrinterState(const std::string &printerId, uint32_t state) override
    {
        return E_PRINT_NONE;
    }
    int32_t UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState) override
    {
        return E_PRINT_NONE;
    }
    int32_t UpdateExtensionInfo(const std::string &extensionId) override
    {
        return E_PRINT_NONE;
    }
    int32_t RequestPreview(const PrintJob &jobinfo, std::string &previewResult) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryPrinterCapability(const std::string &printerId) override
    {
        return E_PRINT_NONE;
    }
    int32_t On(const std::string taskId, const std::string &type, const sptr<IPrintCallback> &listener) override
    {
        return E_PRINT_NONE;
    }
    int32_t Off(const std::string taskId, const std::string &type) override
    {
        return E_PRINT_NONE;
    }
    int32_t RegisterExtCallback(const std::string &extensionCID,
        const sptr<IPrintExtensionCallback> &listener) override
    {
        return E_PRINT_NONE;
    }
    int32_t UnregisterAllExtCallback(const std::string &extensionId) override
    {
        return E_PRINT_NONE;
    }
    int32_t LoadExtSuccess(const std::string &extensionId) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryAllPrintJob(std::vector<PrintJob> &printJobs) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryPrintJobById(std::string &printJobId, PrintJob &printjob) override
    {
        return E_PRINT_NONE;
    }
    int32_t AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
        const std::string &printerMake) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
        PrinterCapability &printerCaps) override
    {
        return E_PRINT_NONE;
    }
    int32_t PrintByAdapter(const std::string jobName, const PrintAttributes &printAttributes,
        std::string &taskId, const sptr<IRemoteObject> &token) override
    {
        return E_PRINT_NONE;
    }
    int32_t StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
        const uint32_t fd) override
    {
        return E_PRINT_NONE;
    }
    int32_t NotifyPrintService(const std::string &jobId, const std::string &type) override
    {
        return E_PRINT_NONE;
    }
};

class MockPrintService final : public DummyPrintServiceStub {
public:
    MOCK_METHOD3(StartPrint, int32_t(const std::vector<std::string>&, const std::vector<uint32_t>&, std::string &));
    MOCK_METHOD4(StartPrint, int32_t(const std::vector<std::string>&, const std::vector<uint32_t>&,
        std::string &, const sptr<IRemoteObject> &));
    MOCK_METHOD1(StopPrint, int32_t(const std::string&));
    MOCK_METHOD1(ConnectPrinter, int32_t(const std::string&));
    MOCK_METHOD1(DisconnectPrinter, int32_t(const std::string&));
    MOCK_METHOD1(StartDiscoverPrinter, int32_t(const std::vector<std::string>&));
    MOCK_METHOD0(StopDiscoverPrinter, int32_t());
    MOCK_METHOD1(QueryAllExtension, int32_t(std::vector<PrintExtensionInfo>&));
    MOCK_METHOD1(StartPrintJob, int32_t(const PrintJob &));
    MOCK_METHOD1(CancelPrintJob, int32_t(const std::string&));
    MOCK_METHOD1(AddPrinters, int32_t(const std::vector<PrinterInfo>&));
    MOCK_METHOD1(RemovePrinters, int32_t(const std::vector<std::string>&));
    MOCK_METHOD1(UpdatePrinters, int32_t(const std::vector<PrinterInfo>&));
    MOCK_METHOD2(UpdatePrinterState, int32_t(const std::string&, uint32_t));
    MOCK_METHOD3(UpdatePrintJobState, int32_t(const std::string&, uint32_t, uint32_t));
    MOCK_METHOD1(UpdateExtensionInfo, int32_t(const std::string&));
    MOCK_METHOD2(RequestPreview, int32_t(const PrintJob&, std::string&));
    MOCK_METHOD1(QueryPrinterCapability, int32_t(const std::string&));
    MOCK_METHOD3(On, int32_t(const std::string, const std::string&, const sptr<IPrintCallback>&));
    MOCK_METHOD2(Off, int32_t(const std::string, const std::string&));
    MOCK_METHOD2(RegisterExtCallback, int32_t(const std::string&, const sptr<IPrintExtensionCallback>&));
    MOCK_METHOD1(UnregisterAllExtCallback, int32_t(const std::string&));
    MOCK_METHOD1(LoadExtSuccess, int32_t(const std::string&));
    MOCK_METHOD1(QueryAllPrintJob, int32_t(std::vector<PrintJob>&));
    MOCK_METHOD2(QueryPrintJobById, int32_t(std::string&, PrintJob&));
    MOCK_METHOD3(AddPrinterToCups, int32_t(const std::string&, const std::string&, const std::string&));
    MOCK_METHOD3(QueryPrinterCapabilityByUri, int32_t(const std::string&, const std::string&, PrinterCapability&));
};
} // namespace Print
} // namespace OHOS
#endif // MOCK_PRINT_SERVICE_H