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

#include "print_data_repository.h"

#include "print_constant.h"
#include "print_log.h"
#include "print_system_data.h"

namespace OHOS {
namespace Print {

PrintDataRepository &PrintDataRepository::GetInstance()
{
    static PrintDataRepository instance;
    return instance;
}

PrintDataRepository::PrintDataRepository() : systemData_(std::make_unique<PrintSystemData>()) {}

PrintDataRepository::~PrintDataRepository() = default;

bool PrintDataRepository::Init()
{
    return systemData_->Init();
}

void PrintDataRepository::InsertAddedPrinter(const std::string &printerId, const PrinterInfo &printerInfo)
{
    systemData_->InsertAddedPrinter(printerId, printerInfo);
}

void PrintDataRepository::InsertAddedPrinter(const std::string &printerId, std::shared_ptr<PrinterInfo> printerInfo)
{
    if (printerInfo != nullptr) {
        systemData_->InsertAddedPrinter(printerId, *printerInfo);
    }
}

void PrintDataRepository::SavePrinterFile(const std::string &printerId)
{
    systemData_->SavePrinterFile(printerId);
}

void PrintDataRepository::SaveIppRawDataFile(const std::string &printerId, const std::string &rawData)
{
    systemData_->SaveIppRawDataFile(printerId, rawData);
}

void PrintDataRepository::CleanIppRawDataFiles()
{
    systemData_->CleanIppRawDataFiles();
}

bool PrintDataRepository::IsPrinterIpInAddedList(const std::string &printerIp)
{
    return systemData_->IsPrinterIpInAddedList(printerIp);
}

bool PrintDataRepository::HasIppRawDataFile(const std::string &printerId)
{
    return systemData_->HasIppRawDataFile(printerId);
}

void PrintDataRepository::UpdateIppRawDataFileTimestamp(const std::string &printerId)
{
    systemData_->UpdateIppRawDataFileTimestamp(printerId);
}

std::string PrintDataRepository::QueryPrinterIdByStandardizeName(const std::string &printerName)
{
    return systemData_->QueryPrinterIdByStandardizeName(printerName);
}

bool PrintDataRepository::QueryAddedPrinterInfoByPrinterId(const std::string &printerId, PrinterInfo &printer)
{
    if (systemData_->QueryAddedPrinterInfoByPrinterId(printerId, printer)) {
        return true;
    }
    if (printerId.find(P2P_PRINTER) != std::string::npos) {
        auto discoveredInfo = systemData_->QueryDiscoveredPrinterInfoById(printerId);
        if (discoveredInfo.has_value()) {
            printer = discoveredInfo.value();
            return true;
        }
    }
    return false;
}

bool PrintDataRepository::IsPrinterAdded(const std::string &printerId)
{
    return systemData_->IsPrinterAdded(printerId);
}

bool PrintDataRepository::GetPrinterCapabilityFromSystemData(
    PrinterInfo &printer, std::string printerId, PrinterCapability &printerCapability)
{
    return systemData_->GetPrinterCapabilityFromSystemData(printer, printerId, printerCapability);
}

void PrintDataRepository::DeleteAddedPrinter(const std::string &printerId, const std::string &printerName)
{
    systemData_->DeleteAddedPrinter(printerId, printerName);
}

void PrintDataRepository::GetAddedPrinterListFromSystemData(std::vector<std::string> &printerNameList)
{
    systemData_->GetAddedPrinterListFromSystemData(printerNameList);
}

void PrintDataRepository::GetRawAddedPrinterListFromSystemData(std::vector<std::string> &printerNameList)
{
    systemData_->GetRawAddedPrinterListFromSystemData(printerNameList);
}

void PrintDataRepository::UpdatePrinterStatus(const std::string &printerId, PrinterStatus printerStatus)
{
    systemData_->UpdatePrinterStatus(printerId, printerStatus);
}

bool PrintDataRepository::UpdatePrinterAlias(const std::string &printerId, const std::string &printerAlias)
{
    return systemData_->UpdatePrinterAlias(printerId, printerAlias);
}

bool PrintDataRepository::UpdatePrinterDeviceId(const std::string &printerId, const std::string &deviceId)
{
    return systemData_->UpdatePrinterDeviceId(printerId, deviceId);
}

void PrintDataRepository::UpdatePrinterUri(const PrinterInfo &printerInfo)
{
    systemData_->UpdatePrinterUri(printerInfo);
}

void PrintDataRepository::UpdatePrinterPreferences(
    const std::string &printerId, const PrinterPreferences &preferences)
{
    systemData_->UpdatePrinterPreferences(printerId, preferences);
}

void PrintDataRepository::UpdatePpdHashCode(const std::string &printerId, const std::string &ppdHashCode)
{
    systemData_->UpdatePpdHashCode(printerId, ppdHashCode);
}

void PrintDataRepository::UpdatePrinterOption(const std::string &printerId, const std::string &option)
{
    systemData_->UpdatePrinterOption(printerId, option);
}

bool PrintDataRepository::QueryPrinterInfoById(const std::string &printerId, PrinterInfo &printerInfo)
{
    return systemData_->QueryPrinterInfoById(printerId, printerInfo);
}

bool PrintDataRepository::QueryPpdHashCodeByPrinterName(
    const std::string &standardPrinterName, std::string &ppdHashCode)
{
    return systemData_->QueryPpdHashCodeByPrinterName(standardPrinterName, ppdHashCode);
}

void PrintDataRepository::GetPpdOptionMapByPrinterId(
    const std::string &printerId, std::string &ppdOptionMap)
{
    systemData_->GetPpdOptionMapByPrinterId(printerId, ppdOptionMap);
}

bool PrintDataRepository::CheckPrinterBusy(const std::string &printerId)
{
    return systemData_->CheckPrinterBusy(printerId);
}

bool PrintDataRepository::GetAllPrintUser(std::vector<int32_t> &allPrintUserList)
{
    return systemData_->GetAllPrintUser(allPrintUserList);
}

void PrintDataRepository::SetEnterpriseState(bool enable, bool isEnterprise)
{
    systemData_->SetEnterpriseState(enable, isEnterprise);
}

std::vector<std::string> PrintDataRepository::QueryAddedPrinterIdList()
{
    return systemData_->QueryAddedPrinterIdList();
}

std::vector<std::string> PrintDataRepository::QueryAddedPrintersByOriginId(const std::string &originId)
{
    return systemData_->QueryAddedPrintersByOriginId(originId);
}

std::shared_ptr<const PrinterInfo> PrintDataRepository::QueryDiscoveredPrinterInfoById(const std::string &printerId)
{
    auto info = systemData_->QueryDiscoveredPrinterInfoById(printerId);
    if (!info.has_value()) {
        return nullptr;
    }
    return std::make_shared<const PrinterInfo>(info.value());
}

std::shared_ptr<const PrinterInfo> PrintDataRepository::QueryDiscoveredPrinterInfoByName(
    const std::string &printerName)
{
    auto info = systemData_->QueryDiscoveredPrinterInfoByName(printerName);
    if (!info.has_value()) {
        return nullptr;
    }
    return std::make_shared<const PrinterInfo>(info.value());
}

void PrintDataRepository::AddPrinterToDiscovery(std::shared_ptr<PrinterInfo> printerInfo)
{
    if (printerInfo == nullptr) {
        return;
    }
    systemData_->AddPrinterToDiscovery(*printerInfo);
}

void PrintDataRepository::RemovePrinterFromDiscovery(const std::string &printerId)
{
    systemData_->RemovePrinterFromDiscovery(printerId);
}

std::map<std::string, PrinterInfo> PrintDataRepository::GetDiscoveredPrinterInfo()
{
    return systemData_->GetDiscoveredPrinterInfo();
}

size_t PrintDataRepository::GetDiscoveredPrinterCount()
{
    return systemData_->GetDiscoveredPrinterCount();
}

void PrintDataRepository::ClearDiscoveredPrinterList()
{
    systemData_->ClearDiscoveredPrinterList();
}

void PrintDataRepository::AddIpPrinterToList(std::shared_ptr<PrinterInfo> printerInfo)
{
    if (printerInfo == nullptr) {
        return;
    }
    systemData_->AddIpPrinterToList(*printerInfo);
}

void PrintDataRepository::RemoveIpPrinterFromList(const std::string &printerId)
{
    systemData_->RemoveIpPrinterFromList(printerId);
}

std::shared_ptr<const PrinterInfo> PrintDataRepository::QueryIpPrinterInfoById(const std::string &printerId)
{
    auto info = systemData_->QueryIpPrinterInfoById(printerId);
    if (!info.has_value()) {
        return nullptr;
    }
    return std::make_shared<const PrinterInfo>(info.value());
}

int32_t PrintDataRepository::BuildPrinterPreference(const PrinterCapability &cap, PrinterPreferences &printPreferences)
{
    return systemData_->BuildPrinterPreference(cap, printPreferences);
}

bool PrintDataRepository::CheckPrinterVersionFile()
{
    return systemData_->CheckPrinterVersionFile();
}

void PrintDataRepository::AddPrintEvent(const std::string &printerId, const std::string &type, int32_t code)
{
    systemData_->AddPrintEvent(printerId, type, code);
}

void PrintDataRepository::ClearPrintEvents(const std::string &printerId, const std::string &type)
{
    systemData_->ClearPrintEvents(printerId, type);
}

std::string PrintDataRepository::AnalyzePrintEvents(const std::string &printerId, const std::string &type)
{
    return systemData_->AnalyzePrintEvents(printerId, type);
}

#ifdef HAVE_SMB_PRINTER
void PrintDataRepository::SetSmbPrinterInDiscoverList(const std::string &ip, std::vector<PrinterInfo> &infos)
{
    systemData_->SetSmbPrinterInDiscoverList(ip, infos);
}

std::optional<PrinterInfo> PrintDataRepository::FindInfoInSmbPrinterDiscoverList(const std::string &printerId)
{
    return systemData_->FindInfoInSmbPrinterDiscoverList(printerId);
}

void PrintDataRepository::GetSmbAddedPrinterListFromSystemData(std::vector<PrinterInfo> &printerInfoList)
{
    systemData_->GetSmbAddedPrinterListFromSystemData(printerInfoList);
}
#endif // HAVE_SMB_PRINTER

void PrintDataRepository::GetWebPrinterListFromSystemData(std::vector<std::string> &printerIdList)
{
    systemData_->GetWebPrinterListFromSystemData(printerIdList);
}

bool PrintDataRepository::SetDiscoveredPrinterState(const std::string &printerId, PrinterState state)
{
    return systemData_->SetDiscoveredPrinterState(printerId, state);
}

bool PrintDataRepository::SetDiscoveredPrinterAlias(const std::string &printerId, const std::string &alias)
{
    return systemData_->SetDiscoveredPrinterAlias(printerId, alias);
}

bool PrintDataRepository::SetIpPrinterState(const std::string &printerId, PrinterState state)
{
    return systemData_->SetIpPrinterState(printerId, state);
}

bool PrintDataRepository::UpdateDiscoveredPrinterInfo(
    const std::string &printerId, const PrinterInfo &printerInfo)
{
    return systemData_->UpdateDiscoveredPrinterInfo(printerId, printerInfo);
}

bool PrintDataRepository::UpdateIpPrinterInfo(const std::string &printerId, const PrinterInfo &printerInfo)
{
    return systemData_->UpdateIpPrinterInfo(printerId, printerInfo);
}

bool PrintDataRepository::IsPrinterPpdUpdateRequired(
    const std::string &printerName, const std::string &ppdHashCode)
{
    std::string lastPrinterPpdHashCode;
    if (!systemData_->QueryPpdHashCodeByPrinterName(printerName, lastPrinterPpdHashCode)) {
        PRINT_HILOGD("PrintSystemData does not save printerPpdHashCode");
        return true;
    }
    return lastPrinterPpdHashCode != ppdHashCode;
}

} // namespace Print
} // namespace OHOS
