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

#ifndef PRINT_DATA_REPOSITORY_H
#define PRINT_DATA_REPOSITORY_H

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "print_constant.h"
#include "printer_capability.h"
#include "printer_info.h"
#include "printer_preferences.h"

namespace OHOS {
namespace Print {

class PrintSystemData;

class PrintDataRepository {
public:
    static PrintDataRepository &GetInstance();

    bool Init();
#ifdef UNIT_TEST
    void ResetForTest();
#endif // UNIT_TEST

    // Added printers
    void InsertAddedPrinter(const std::string &printerId, const PrinterInfo &printerInfo);
    void InsertAddedPrinter(const std::string &printerId, std::shared_ptr<PrinterInfo> printerInfo);
    void SavePrinterFile(const std::string &printerId);
    std::string QueryPrinterIdByStandardizeName(const std::string &printerName);
    bool QueryAddedPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &printer);
    bool IsPrinterAdded(const std::string &printerId);
    bool GetPrinterCapabilityFromSystemData(
        PrinterInfo &printer, std::string printerId, PrinterCapability &printerCapability);
    void DeleteAddedPrinter(const std::string &printerId, const std::string &printerName);
    void GetAddedPrinterListFromSystemData(std::vector<std::string> &printerNameList);
    void GetRawAddedPrinterListFromSystemData(std::vector<std::string> &printerNameList);
    void UpdatePrinterStatus(const std::string &printerId, PrinterStatus printerStatus);
    bool UpdatePrinterAlias(const std::string &printerId, const std::string &printerAlias);
    bool UpdatePrinterDeviceId(const std::string &printerId, const std::string &deviceId);
    void UpdatePrinterUri(const PrinterInfo &printerInfo);
    void UpdatePrinterPreferences(const std::string &printerId, const PrinterPreferences &preferences);
    void UpdatePpdHashCode(const std::string &printerId, const std::string &ppdHashCode);
    bool QueryPrinterInfoById(const std::string &printerId, PrinterInfo &printerInfo);
    bool QueryPpdHashCodeByPrinterName(const std::string &standardPrinterName, std::string &ppdHashCode);
    bool CheckPrinterBusy(const std::string &printerId);
    bool GetAllPrintUser(std::vector<int32_t> &allPrintUserList);
    void SetEnterpriseState(bool enable, bool isEnterprise);
    std::vector<std::string> QueryAddedPrinterIdList();
    std::vector<std::string> QueryAddedPrintersByOriginId(const std::string &originId);

    // Discovered printers
    std::shared_ptr<const PrinterInfo> QueryDiscoveredPrinterInfoById(const std::string &printerId);
    std::shared_ptr<const PrinterInfo> QueryDiscoveredPrinterInfoByName(const std::string &printerName);
    void AddPrinterToDiscovery(std::shared_ptr<PrinterInfo> printerInfo);
    void RemovePrinterFromDiscovery(const std::string &printerId);
    std::map<std::string, PrinterInfo> GetDiscoveredPrinterInfo();
    size_t GetDiscoveredPrinterCount();
    void ClearDiscoveredPrinterList();

    // IP printers
    void AddIpPrinterToList(std::shared_ptr<PrinterInfo> printerInfo);
    void RemoveIpPrinterFromList(const std::string &printerId);
    std::shared_ptr<const PrinterInfo> QueryIpPrinterInfoById(const std::string &printerId);

    // Explicit write paths for discovered / IP printers (M-001).
    bool SetDiscoveredPrinterState(const std::string &printerId, PrinterState state);
    bool SetDiscoveredPrinterAlias(const std::string &printerId, const std::string &alias);
    bool SetIpPrinterState(const std::string &printerId, PrinterState state);
    bool UpdateDiscoveredPrinterInfo(const std::string &printerId, const PrinterInfo &printerInfo);
    bool UpdateIpPrinterInfo(const std::string &printerId, const PrinterInfo &printerInfo);

    // Printer preferences
    int32_t BuildPrinterPreference(const PrinterCapability &cap, PrinterPreferences &printPreferences);
    bool CheckPrinterVersionFile();

    // Print events
    void AddPrintEvent(const std::string &printerId, const std::string &type, int32_t code);
    void ClearPrintEvents(const std::string &printerId, const std::string &type);
    std::string AnalyzePrintEvents(const std::string &printerId, const std::string &type);

#ifdef HAVE_SMB_PRINTER
    void SetSmbPrinterInDiscoverList(const std::string& ip, std::vector<PrinterInfo>& infos);
    std::optional<PrinterInfo> FindInfoInSmbPrinterDiscoverList(const std::string &printerId);
    void GetSmbAddedPrinterListFromSystemData(std::vector<PrinterInfo> &printerInfoList);
#endif // HAVE_SMB_PRINTER

    void GetWebPrinterListFromSystemData(std::vector<std::string> &printerIdList);

    bool IsPrinterPpdUpdateRequired(const std::string &printerName, const std::string &ppdHashCode);

private:
    PrintDataRepository();
    ~PrintDataRepository();
    PrintDataRepository(const PrintDataRepository &) = delete;
    PrintDataRepository &operator=(const PrintDataRepository &) = delete;

    std::unique_ptr<PrintSystemData> systemData_;
};

} // namespace Print
} // namespace OHOS

#endif // PRINT_DATA_REPOSITORY_H
