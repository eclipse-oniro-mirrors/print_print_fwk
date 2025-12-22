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
    int32_t StartPrint(
        const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList, std::string &taskId) override
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
    int32_t StartPrintJob(PrintJob &jobInfo) override
    {
        return E_PRINT_NONE;
    }
    int32_t CancelPrintJob(const std::string &jobId) override
    {
        return E_PRINT_NONE;
    }
    int32_t RestartPrintJob(const std::string &jobId) override
    {
        return E_PRINT_NONE;
    }
    int32_t AddPrinters(const std::vector<PrinterInfo> &printerInfos) override
    {
        return E_PRINT_NONE;
    }
    int32_t AddRawPrinter(PrinterInfo &printerInfo) override
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
    int32_t UpdatePrintJobStateForNormalApp(const std::string &jobId, uint32_t state, uint32_t subState) override
    {
        return E_PRINT_NONE;
    }
    int32_t UpdatePrintJobStateOnlyForSystemApp(const std::string &jobId, uint32_t state, uint32_t subState) override
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
    int32_t RegisterExtCallback(const std::string &extensionCID, const sptr<IPrintExtensionCallback> &listener) override
    {
        return E_PRINT_NONE;
    }
    int32_t LoadExtSuccess(const std::string &extensionId) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryAllActivePrintJob(std::vector<PrintJob> &printJobs) override
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
    int32_t AddPrinterToCups(
        const std::string &printerUri, const std::string &printerName, const std::string &printerMake) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryPrinterCapabilityByUri(
        const std::string &printerUri, const std::string &printerId, PrinterCapability &printerCaps) override
    {
        return E_PRINT_NONE;
    }
    int32_t PrintByAdapter(
        const std::string jobName, const PrintAttributes &printAttributes, std::string &taskId) override
    {
        return E_PRINT_NONE;
    }
    int32_t StartGetPrintFile(
        const std::string &jobId, const PrintAttributes &printAttributes, const uint32_t fd) override
    {
        return E_PRINT_NONE;
    }
    int32_t NotifyPrintService(const std::string &jobId, const std::string &type) override
    {
        return E_PRINT_NONE;
    }
    int32_t StartService() override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &info) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryAddedPrinter(std::vector<std::string> &printerNameList) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryRawAddedPrinter(std::vector<std::string> &printerNameList) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryPrinterProperties(const std::string &printerId, const std::vector<std::string> &keyList,
        std::vector<std::string> &valueList) override
    {
        return E_PRINT_NONE;
    }
    int32_t RegisterPrinterCallback(const std::string &type, const sptr<IPrintCallback> &listener) override
    {
        return E_PRINT_NONE;
    }
    int32_t UnregisterPrinterCallback(const std::string &type) override
    {
        return E_PRINT_NONE;
    }
    int32_t StartNativePrintJob(PrintJob &printJob) override
    {
        return E_PRINT_NONE;
    }
    int32_t NotifyPrintServiceEvent(std::string &jobId, uint32_t event) override
    {
        return E_PRINT_NONE;
    }
    int32_t SetPrinterPreference(const std::string &printerId, const PrinterPreferences &printerPreference) override
    {
        return E_PRINT_NONE;
    }
    int32_t SetDefaultPrinter(const std::string &printerId, uint32_t type) override
    {
        return E_PRINT_NONE;
    }
    int32_t DeletePrinterFromCups(const std::string &printerName) override
    {
        return E_PRINT_NONE;
    }
    int32_t DiscoverUsbPrinters(std::vector<PrinterInfo> &printers) override
    {
        return E_PRINT_NONE;
    }
    int32_t AddPrinterToDiscovery(const PrinterInfo &printerInfo) override
    {
        return E_PRINT_NONE;
    }
    int32_t UpdatePrinterInDiscovery(const PrinterInfo &printerInfo) override
    {
        return E_PRINT_NONE;
    }
    int32_t RemovePrinterFromDiscovery(const std::string &printerId) override
    {
        return E_PRINT_NONE;
    }
    int32_t UpdatePrinterInSystem(const PrinterInfo &printerInfo) override
    {
        return E_PRINT_NONE;
    }
    int32_t AnalyzePrintEvents(const std::string &printerId, const std::string &type, std::string &detail) override
    {
        return E_PRINT_NONE;
    }
    int32_t AuthPrintJob(const std::string &jobId, const std::string &userName, char *userPasswd) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryAllPrinterPpds(std::vector<PpdInfo> &printerPpdList) override
    {
        return E_PRINT_NONE;
    }
    int32_t QueryPrinterInfoByIp(const std::string &printerIp)
    {
        return E_PRINT_NONE;
    }
    int32_t ConnectPrinterByIpAndPpd(const std::string &printerIp, const std::string &protocol,
        const std::string &ppdName)
    {
        return E_PRINT_NONE;
    }
    int32_t QueryRecommendDriversById(const std::string &printerId, std::vector<PpdInfo> &ppds)
    {
        return E_PRINT_NONE;
    }
    int32_t ConnectPrinterByIdAndPpd(const std::string &printerId, const std::string &protocol,
        const std::string &ppdName)
    {
        return E_PRINT_NONE;
    }
    int32_t SavePdfFileJob(const std::string &jobId, uint32_t fd)
    {
        return E_PRINT_NONE;
    }
};

class MockPrintService final : public DummyPrintServiceStub {
public:
    MOCK_METHOD3(StartPrint, int32_t(const std::vector<std::string> &, const std::vector<uint32_t> &, std::string &));
    MOCK_METHOD1(ConnectPrinter, int32_t(const std::string &));
    MOCK_METHOD1(DisconnectPrinter, int32_t(const std::string &));
    MOCK_METHOD1(StartDiscoverPrinter, int32_t(const std::vector<std::string> &));
    MOCK_METHOD0(StopDiscoverPrinter, int32_t());
    MOCK_METHOD1(QueryAllExtension, int32_t(std::vector<PrintExtensionInfo> &));
    MOCK_METHOD1(StartPrintJob, int32_t(PrintJob &));
    MOCK_METHOD1(CancelPrintJob, int32_t(const std::string &));
    MOCK_METHOD1(RestartPrintJob, int32_t(const std::string &));
    MOCK_METHOD1(AddPrinters, int32_t(const std::vector<PrinterInfo> &));
    MOCK_METHOD1(AddRawPrinter, int32_t(PrinterInfo &));
    MOCK_METHOD1(QueryRawAddedPrinter, int32_t(std::vector<std::string> &));
    MOCK_METHOD1(RemovePrinters, int32_t(const std::vector<std::string> &));
    MOCK_METHOD1(UpdatePrinters, int32_t(const std::vector<PrinterInfo> &));
    MOCK_METHOD2(UpdatePrinterState, int32_t(const std::string &, uint32_t));
    MOCK_METHOD3(UpdatePrintJobStateForNormalApp, int32_t(const std::string &, uint32_t, uint32_t));
    MOCK_METHOD3(UpdatePrintJobStateOnlyForSystemApp, int32_t(const std::string &, uint32_t, uint32_t));
    MOCK_METHOD1(UpdateExtensionInfo, int32_t(const std::string &));
    MOCK_METHOD2(RequestPreview, int32_t(const PrintJob &, std::string &));
    MOCK_METHOD1(QueryPrinterCapability, int32_t(const std::string &));
    MOCK_METHOD3(On, int32_t(const std::string, const std::string &, const sptr<IPrintCallback> &));
    MOCK_METHOD2(Off, int32_t(const std::string, const std::string &));
    MOCK_METHOD2(RegisterExtCallback, int32_t(const std::string &, const sptr<IPrintExtensionCallback> &));
    MOCK_METHOD1(LoadExtSuccess, int32_t(const std::string &));
    MOCK_METHOD1(QueryAllPrintJob, int32_t(std::vector<PrintJob> &));
    MOCK_METHOD1(QueryAllActivePrintJob, int32_t(std::vector<PrintJob> &));
    MOCK_METHOD2(QueryPrintJobById, int32_t(std::string &, PrintJob &));
    MOCK_METHOD3(AddPrinterToCups, int32_t(const std::string &, const std::string &, const std::string &));
    MOCK_METHOD3(QueryPrinterCapabilityByUri, int32_t(const std::string &, const std::string &, PrinterCapability &));
    MOCK_METHOD2(NotifyPrintServiceEvent, int32_t(std::string &, uint32_t));
    MOCK_METHOD2(SetDefaultPrinter, int32_t(const std::string &, uint32_t));
    MOCK_METHOD1(DeletePrinterFromCups, int32_t(const std::string &));
    MOCK_METHOD1(DiscoverUsbPrinters, int32_t(std::vector<PrinterInfo> &));
    MOCK_METHOD1(AddPrinterToDiscovery, int32_t(const PrinterInfo &));
    MOCK_METHOD1(UpdatePrinterInDiscovery, int32_t(const PrinterInfo &));
    MOCK_METHOD1(RemovePrinterFromDiscovery, int32_t(const std::string &));
    MOCK_METHOD1(UpdatePrinterInSystem, int32_t(const PrinterInfo &));
    MOCK_METHOD3(AuthPrintJob, int32_t(const std::string &, const std::string &, char *));
    MOCK_METHOD1(QueryAllPrinterPpds, int32_t(std::vector<PpdInfo> &));
    MOCK_METHOD1(QueryPrinterInfoByIp, int32_t(const std::string &));
    MOCK_METHOD3(ConnectPrinterByIpAndPpd, int32_t(const std::string &, const std::string &, const std::string &));
    MOCK_METHOD2(SavePdfFileJob, int32_t(const std::string &, uint32_t));
    MOCK_METHOD4(CheckPreferencesConflicts, int32_t(const std::string &printerId, const std::string &changedType,
        const PrinterPreferences &printerPreference, std::vector<std::string> &conflictingOptions));
    MOCK_METHOD3(CheckPrintJobConflicts, int32_t(const std::string &changedType,
        const PrintJob &printJob, std::vector<std::string> &conflictingOptions));
    MOCK_METHOD1(GetSharedHosts, int32_t(std::vector<PrintSharedHost> &sharedHosts));
    MOCK_METHOD4(AuthSmbDevice, int32_t(const PrintSharedHost& sharedHost, const std::string &userName,
        char *userPasswd, std::vector<PrinterInfo>& printerInfos));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_PRINT_SERVICE_H