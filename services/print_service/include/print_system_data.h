/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef PRINT_SYSTEM_DATA_H
#define PRINT_SYSTEM_DATA_H

#include <string>
#include <map>
#include <vector>
#include <nlohmann/json.hpp>
#include "printer_info.h"
#include "printer_capability.h"
#include "print_constant.h"

namespace OHOS {
namespace Print {

struct CupsPrinterInfo {
    std::string name;
    std::string uri;
    std::string maker;
    PrinterCapability printerCapability;
    PrinterStatus printerStatus = PRINTER_STATUS_UNAVAILABLE;
    std::string alias;
};

class PrintSystemData {
public:
    bool Init();
    void InsertCupsPrinter(const std::string &printerId, const CupsPrinterInfo &printerInfo, bool needUpdateCaps);
    bool SaveCupsPrinterMap();
    std::string QueryPrinterIdByStandardizeName(const std::string &printerName);
    bool QueryCupsPrinterInfoByPrinterId(const std::string &printerId, CupsPrinterInfo &cupsPrinter);
    void InsertPrinterInfo(const std::string &printerId, const PrinterInfo &printerInfo);
    std::shared_ptr<PrinterInfo> QueryPrinterInfoByPrinterId(const std::string &printerId);
    bool IsPrinterAdded(const std::string &printerId);
    bool GetPrinterCapabilityFromSystemData(
        CupsPrinterInfo &cupsPrinter, std::string printerId, PrinterCapability &printerCapability);
    void DeleteCupsPrinter(const std::string &printerId);
    void GetAddedPrinterListFromSystemData(std::vector<std::string> &printerNameList);
    void UpdatePrinterStatus(const std::string &printerId, PrinterStatus printerStatus);
    bool UpdatePrinterAlias(const std::string& printerId, const std::string& printerAlias);
    void UpdatePrinterUri(const std::string& printerId, const std::string& printerUri);
    void QueryPrinterInfoById(const std::string &printerId, PrinterInfo &printerInfo);
    bool CheckPrinterBusy(const std::string &printerId);
    bool GetAllPrintUser(std::vector<int32_t> &allPrintUserList);

private:
    bool ParsePrinterListJsonV1(nlohmann::json& jsonObject);
    bool GetJsonObjectFromFile(nlohmann::json &jsonObject, const std::string &fileName);
    void ConvertPrinterCapabilityToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson);
    void ConvertPrintMarginToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson);
    void ConvertPageSizeToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson);
    void ConvertPrintResolutionToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson);
    bool ConvertJsonToPrinterCapability(nlohmann::json &capsJson, PrinterCapability &printerCapability);
    void ConvertJsonToPrintMargin(nlohmann::json &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToPageSize(nlohmann::json &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToPrintResolution(nlohmann::json &capsJson, PrinterCapability &printerCapability);
    bool GetPrinterCapabilityFromFile(std::string printerId, PrinterCapability &printerCapability);
    bool CheckPrinterInfoJson(nlohmann::json &object, std::string &printerId);
    bool GetPrinterCapabilityFromJson(
        std::string printerId, nlohmann::json &jsonObject, PrinterCapability &printerCapability);
    bool ParseUserListJsonV1(
        nlohmann::json &jsonObject, std::vector<int32_t> &allPrintUserList);

private:
    std::map<std::string, std::shared_ptr<CupsPrinterInfo>> addedPrinterMap_;
    std::map<uint32_t, std::string> addedPrinterOrderList_;
    std::map<std::string, std::shared_ptr<PrinterInfo>> addedPrinterInfoList_;
};

}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_SYSTEM_DATA_H
