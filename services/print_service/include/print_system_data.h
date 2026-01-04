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
#include <json/json.h>
#include <optional>
#include "printer_info.h"
#include "printer_capability.h"
#include "print_constant.h"
#include "print_utils.h"
#include "print_log.h"
#include "print_map_safe.h"
#include "printer_preferences.h"
#include "print_event_container.h"

namespace OHOS {
namespace Print {

class PrintSystemData {
public:
    bool Init();
    void InsertAddedPrinter(const std::string &printerId, const PrinterInfo &printerInfo);
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
    void UpdatePrinterUri(const std::shared_ptr<PrinterInfo> &printerInfo);
    void UpdatePrinterPreferences(const std::string &printerId, const PrinterPreferences &preferences);
    void UpdatePpdHashCode(const std::string &printerId, const std::string &ppdHashCode);
    bool QueryPrinterInfoById(const std::string &printerId, PrinterInfo &printerInfo);
    bool QueryPpdHashCodeByPrinterName(const std::string &standardPrinterName, std::string &ppdHashCode);
    bool CheckPrinterBusy(const std::string &printerId);
    bool GetAllPrintUser(std::vector<int32_t> &allPrintUserList);

    std::vector<std::string> QueryAddedPrinterIdList();
    std::vector<std::string> QueryAddedPrintersByIp(const std::string &printerIp);
    std::shared_ptr<PrinterInfo> QueryDiscoveredPrinterInfoById(const std::string &printerId);
    std::shared_ptr<PrinterInfo> QueryDiscoveredPrinterInfoByName(const std::string &printerName);
    void AddPrinterToDiscovery(std::shared_ptr<PrinterInfo> printerInfo);
    void RemovePrinterFromDiscovery(const std::string &printerId);
    std::map<std::string, std::shared_ptr<PrinterInfo>> GetDiscoveredPrinterInfo();
    size_t GetDiscoveredPrinterCount();
    void ClearDiscoveredPrinterList();
    void AddIpPrinterToList(std::shared_ptr<PrinterInfo> printerInfo);
    void RemoveIpPrinterFromList(const std::string &printerId);
    std::shared_ptr<PrinterInfo> QueryIpPrinterInfoById(const std::string &printerId);
    int32_t BuildPrinterPreference(const PrinterCapability &cap, PrinterPreferences &printPreferences);
    bool CheckPrinterVersionFile();

    void AddPrintEvent(const std::string &printerId, const std::string &type, int32_t code);
    void ClearPrintEvents(const std::string &printerId, const std::string &type);
    std::string AnalyzePrintEvents(const std::string &printerId, const std::string &type);
#ifdef HAVE_SMB_PRINTER
    void SetSmbPrinterInDiscoverList(const std::string& ip, std::vector<PrinterInfo>& infos);
    std::optional<PrinterInfo> FindInfoInSmbPrinterDiscoverList(const std::string &printerId);
    void GetSmbAddedPrinterListFromSystemData(std::vector<PrinterInfo> &printerInfoList);
#endif // HAVE_SMB_PRINTER

private:
    bool ParsePrinterListJsonV1(Json::Value& jsonObject);
    bool GetJsonObjectFromFile(Json::Value &jsonObject, const std::string &fileName);
    void ConvertPrinterCapabilityToJson(PrinterCapability &printerCapability, Json::Value &capsJson);
    void ConvertPrintMarginToJson(PrinterCapability &printerCapability, Json::Value &capsJson);
    void ConvertPageSizeToJson(PrinterCapability &printerCapability, Json::Value &capsJson);
    void ConvertPrintResolutionToJson(PrinterCapability &printerCapability, Json::Value &capsJson);
    void ConvertSupportedColorModeToJson(PrinterCapability &printerCapability, Json::Value &capsJson);
    void ConvertSupportedDuplexModeToJson(PrinterCapability &printerCapability, Json::Value &capsJson);
    void ConvertSupportedMediaTypeToJson(PrinterCapability &printerCapability, Json::Value &capsJson);
    void ConvertSupportedQualityToJson(PrinterCapability &printerCapability, Json::Value &capsJson);
    bool ConvertJsonToPrinterCapability(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToPrintMargin(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToPageSize(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToPrintResolution(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToSupportedColorMode(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToSupportedDuplexMode(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToSupportedMediaType(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToSupportedQuality(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool ConvertJsonToSupportedOrientation(Json::Value &capsJson, PrinterCapability &printerCapability);
    bool GetPrinterCapabilityFromFile(std::string printerId, PrinterCapability &printerCapability);
    bool CheckPrinterInfoJson(Json::Value &object, std::string &printerId);
    bool GetPrinterCapabilityFromJson(
        std::string printerId, Json::Value &jsonObject, PrinterCapability &printerCapability);
    bool ParseUserListJsonV1(
        Json::Value &jsonObject, std::vector<int32_t> &allPrintUserList);
    bool ConvertJsonToPrinterInfo(Json::Value &object);
    void ConvertInnerJsonToPrinterInfo(Json::Value &object, PrinterInfo &info);

    bool ParsePreviousPreferencesSetting(Json::Value &settingJson, PrinterPreferences &preferences);
    bool ParsePrinterPreferencesJson(Json::Value &jsonObject);
    bool ReadJsonFile(const std::filesystem::path &path);
    std::string ParseDefaultPageSizeId(const PrinterCapability &cap);
    void DeleteFile(const std::filesystem::path &path);
    void BuildPrinterPreferenceByDefault(Json::Value &capOpt, PrinterPreferences &printPreferences);
    void BuildPrinterPreferenceBySupport(const PrinterCapability &cap, PrinterPreferences &printPreferences);
    Json::Value GetCupsOptionsJson(const PrinterCapability &cap);
    void SaveJsonFile(const std::string &fileName, const std::string &jsonString);
    PrintMapSafe<PrinterInfo>& GetAddedPrinterMap();
    const std::string& GetPrintersPath();
    void ParseInfoToPrinterJson(std::shared_ptr<PrinterInfo> info, Json::Value &printerJson);

    template<typename T>
    bool ProcessJsonToCapabilityList(Json::Value &capsJson,
                                     const std::string &key,
                                     PrinterCapability &printerCapability,
                                     void (PrinterCapability::*setter)(const std::vector <T> &),
                                     std::function<bool(const Json::Value &, T &)> converter)
    {
        if (!PrintJsonUtil::IsMember(capsJson, key) || !capsJson[key].isArray()) {
            PRINT_HILOGW("Cannot find %{public}s or it's not an array", key.c_str());
            return true;
        }
        PRINT_HILOGD("find Capability %{public}s success", key.c_str());
        std::vector<T> resultList;
        for (const auto &item: capsJson[key]) {
            if (!PrintUtils::CheckJsonType<T>(item)) {
                PRINT_HILOGE("%{public}s item has incorrect type", key.c_str());
                return false;
            }
            T object;
            bool ret = converter(item, object);
            if (!ret) {
                PRINT_HILOGE("Invalid format,key is %{public}s", key.c_str());
                return false;
            }
            resultList.push_back(object);
        }
        if (!resultList.empty()) {
            (printerCapability.*setter)(resultList);
        }
        PRINT_HILOGD("processCapabilityList success, %{public}s", key.c_str());
        return true;
    }

    template <typename T>
    std::optional<T> GetPreferencesFromSupport(const std::vector<T>& vec, const T& defaultValue)
    {
        if (vec.size() == 0) {
            return std::nullopt;
        }

        for (const auto& elem : vec) {
            if (elem == defaultValue) {
                return elem;
            }
        }
        return vec[0];
    }

private:
    PrintMapSafe<PrinterInfo> addedPrinterMap_;
#ifdef ENTERPRISE_ENABLE
    PrintMapSafe<PrinterInfo> addedPrinterEnterpriseMap_;
#endif // ENTERPRISE_ENABLE
    std::map<std::string, std::shared_ptr<PrinterInfo>> discoveredPrinterInfoList_;
    std::map<std::string, std::shared_ptr<PrinterInfo>> connectingIpPrinterInfoList_;
    std::map<std::string, std::vector<PrinterInfo>> discoveredSmbPrinterInfoList_;
    std::mutex discoveredListMutex;
    std::mutex connectingIpPrinterListMutex;
    std::mutex smbPrinterListMutex;
    const uint32_t MAX_PRINTER_SIZE = 1000;
    PrintMapSafe<PrintEventContainer> printEventMap_;
};

}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_SYSTEM_DATA_H
