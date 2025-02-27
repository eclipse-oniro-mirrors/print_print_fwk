/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <streambuf>
#include <filesystem>
#include "print_system_data.h"
#include "print_log.h"
#include "print_util.h"
#include "print_constant.h"

namespace OHOS {
namespace Print {

bool PrintSystemData::ParsePrinterListJsonV1(nlohmann::json &jsonObject)
{
    if (!jsonObject.contains("printer_list") || !jsonObject["printer_list"].is_array()) {
        PRINT_HILOGW("can not find printer_list");
        return false;
    }
    for (auto &element : jsonObject["printer_list"].items()) {
        nlohmann::json object = element.value();
        if (!ConvertJsonToCupsPrinterInfo(object)) {
            PRINT_HILOGW("can not find necessary param");
            continue;
        }
    }
    return true;
}

bool PrintSystemData::ConvertJsonToCupsPrinterInfo(nlohmann::json &object)
{
    if (!object.contains("id") || !object["id"].is_string()) {
        PRINT_HILOGW("can not find id");
        return false;
    }
    std::string id = object["id"];
    if (!object.contains("name") || !object["name"].is_string()) {
        PRINT_HILOGW("can not find name");
        return false;
    }
    std::string name = object["name"];
    if (!object.contains("uri") || !object["uri"].is_string()) {
        PRINT_HILOGW("can not find uri");
        return false;
    }
    std::string uri = object["uri"];
    if (!object.contains("maker") || !object["maker"].is_string()) {
        PRINT_HILOGW("can not find maker");
        return false;
    }
    std::string maker = object["maker"];
    if (!object.contains("capability") || !object["capability"].is_object()) {
        PRINT_HILOGW("can not find capability");
        return false;
    }
    nlohmann::json capsJson = object["capability"];
    PrinterCapability printerCapability;
    if (!ConvertJsonToPrinterCapability(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to printer capability failed");
        return false;
    }
    printerCapability.Dump();
    CupsPrinterInfo info;
    info.name = name;
    info.uri = uri;
    info.maker = maker;
    info.printerCapability = printerCapability;
    ConvertInnerJsonToCupsPrinterInfo(object, info);
    InsertCupsPrinter(id, info);
    return true;
}

void PrintSystemData::ConvertInnerJsonToCupsPrinterInfo(nlohmann::json &object, CupsPrinterInfo &info)
{
    if (object.contains("alias") && object["alias"].is_string()) {
        info.alias = object["alias"];
    }
    if (object.contains("printerStatus") && object["printerStatus"].is_number()) {
        info.printerStatus = object["printerStatus"];
    }
    PrinterPreferences preferences;
    if (object.contains("preferences") && object["preferences"].is_object()) {
        ConvertJsonToPrinterPreferences(object["preferences"], info.printPreferences);
        PRINT_HILOGI("convert json to printer preferences success");
    }
}

bool PrintSystemData::Init()
{
    addedPrinterMap_.Clear();
    PRINT_HILOGI("load new printer list file");
    std::filesystem::path printersDir(PRINTER_SERVICE_PRINTERS_PATH);
    for (const auto& entry : std::filesystem::directory_iterator(printersDir)) {
        if (!entry.is_directory()) {
            ReadJsonFile(entry.path());
        }
    }

    nlohmann::json printerListJson;
    std::string printerListFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINTER_LIST_FILE;
    if (GetJsonObjectFromFile(printerListJson, printerListFilePath) && ParsePrinterListJsonV1(printerListJson)) {
        PRINT_HILOGW("previous printer list file exist");
        nlohmann::json preferencesJson;
        std::string preferencesFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINTER_PREFERENCE_FILE;
        if (GetJsonObjectFromFile(preferencesJson, preferencesFilePath) &&
            ParsePrinterPreferencesJson(preferencesJson)) {
            PRINT_HILOGI("parse previous preferences file success");
        }
        std::vector<std::string> addedPrinterList = QueryAddedPrinterIdList();
        for (auto printerId : addedPrinterList) {
            SavePrinterFile(printerId);
        }
        DeleteFile(preferencesFilePath);
        DeleteFile(printerListFilePath);
    }
    return true;
}

bool PrintSystemData::ReadJsonFile(const std::filesystem::path &path)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        PRINT_HILOGW("open printer list file fail");
        return false;
    }
    std::string line;
    std::string content;
    while (std::getline(file, line)) {
        content += line + "\n";
    }
    file.close();

    if (!nlohmann::json::accept(content)) {
        PRINT_HILOGW("json accept fail");
        return false;
    }
    nlohmann::json fileJson = nlohmann::json::parse(content);
    if (!ConvertJsonToCupsPrinterInfo(fileJson)) {
        PRINT_HILOGW("can not find necessary param");
        return false;
    }
    return true;
}

bool PrintSystemData::GetJsonObjectFromFile(nlohmann::json &jsonObject, const std::string &fileName)
{
    std::ifstream ifs(fileName.c_str(), std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        PRINT_HILOGW("open printer list file fail");
        return false;
    }
    std::string fileData((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();
    if (!nlohmann::json::accept(fileData)) {
        PRINT_HILOGW("json accept fail");
        return false;
    }
    jsonObject = nlohmann::json::parse(fileData);
    if (fileName.find(PRINTER_PREFERENCE_FILE) != std::string::npos) {
        return true;
    }
    if (!jsonObject.contains("version") || !jsonObject["version"].is_string()) {
        PRINT_HILOGW("can not find version");
        return false;
    }
    std::string version = jsonObject["version"].get<std::string>();
    PRINT_HILOGI("json version: %{public}s", version.c_str());
    std::string fileVersion = "";
    std::string printerListFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINTER_LIST_FILE;
    if (strcmp(fileName.c_str(), printerListFilePath.c_str())) {
        fileVersion = PRINTER_LIST_VERSION;
    } else {
        fileVersion = PRINT_USER_DATA_VERSION;
    }
    if (strcmp(version.c_str(), PRINTER_LIST_VERSION.c_str())) {
        PRINT_HILOGW("printer list version is error.");
        return false;
    }
    return true;
}

bool PrintSystemData::ParsePrinterPreferencesJson(nlohmann::json &jsonObject)
{
    if (!jsonObject.contains("printer_list") || !jsonObject["printer_list"].is_array()) {
        PRINT_HILOGW("can not find printer_list");
        return false;
    }
    for (auto &element : jsonObject["printer_list"].items()) {
        nlohmann::json object = element.value();
        for (auto it = object.begin(); it != object.end(); it++) {
            std::string printerId = it.key();
            auto info = addedPrinterMap_.Find(printerId);
            if (info == nullptr) {
                continue;
            }
            if (printerId.find(EPRINTER) != std::string::npos) {
                PRINT_HILOGI("ePrinter Enter");
                BuildEprintPreference(info->printerCapability, info->printPreferences);
            } else {
                BuildPrinterPreference(info->printerCapability, info->printPreferences);
            }
            UpdatePrinterPreferences(printerId, info->printPreferences);
            nlohmann::json printPreferenceJson = object[printerId];
            if (!printPreferenceJson.contains("setting") || !printPreferenceJson["setting"].is_object()) {
                PRINT_HILOGW("can not find setting");
                continue;
            }
            nlohmann::json settingJson = printPreferenceJson["setting"];
            PRINT_HILOGI("ParsePrinterPreferencesJson settingJson: %{public}s", settingJson.dump().c_str());
            PrinterPreferences preferences;
            if (ParsePreviousPreferencesSetting(settingJson, preferences)) {
                PRINT_HILOGI("need update preferences by previous settings");
                preferences.Dump();
                UpdatePrinterPreferences(printerId, preferences);
            }
        }
    }
    return true;
}

bool PrintSystemData::ParsePreviousPreferencesSetting(nlohmann::json &settingJson, PrinterPreferences &preferences)
{
    bool updatePreferences = false;
    if (settingJson.contains("pagesizeId") && settingJson["pagesizeId"].is_string() &&
        !settingJson.at("pagesizeId").get<std::string>().empty()) {
        updatePreferences = true;
        preferences.SetDefaultPageSizeId(settingJson.at("pagesizeId").get<std::string>());
    }
    if (settingJson.contains("orientation") && settingJson["orientation"].is_string() &&
        !settingJson.at("orientation").get<std::string>().empty()) {
        updatePreferences = true;
        int32_t defaultOrientation = 0;
        PrintUtil::ConvertToInt(settingJson.at("orientation").get<std::string>(), defaultOrientation);
        preferences.SetDefaultOrientation(defaultOrientation);
    }
    if (settingJson.contains("duplex") && settingJson["duplex"].is_string() &&
        !settingJson.at("duplex").get<std::string>().empty()) {
        updatePreferences = true;
        int32_t defaultDuplexMode = DUPLEX_MODE_NONE;
        PrintUtil::ConvertToInt(settingJson.at("duplex").get<std::string>(), defaultDuplexMode);
        preferences.SetDefaultDuplexMode(defaultDuplexMode);
    }
    if (settingJson.contains("quality") && settingJson["quality"].is_string() &&
        !settingJson.at("quality").get<std::string>().empty()) {
        updatePreferences = true;
        int32_t defaultPrintQuality = PRINT_QUALITY_NORMAL;
        PrintUtil::ConvertToInt(settingJson.at("quality").get<std::string>(), defaultPrintQuality);
        preferences.SetDefaultPrintQuality(defaultPrintQuality);
    }
    if (settingJson.contains("mediaType") && settingJson["mediaType"].is_string() &&
        !settingJson.at("mediaType").get<std::string>().empty()) {
        updatePreferences = true;
        preferences.SetDefaultMediaType(settingJson.at("mediaType").get<std::string>());
    }
    if (settingJson.contains("hasMargin") && settingJson["hasMargin"].is_boolean() &&
        settingJson.at("hasMargin").get<bool>() == false) {
        updatePreferences = true;
        preferences.SetBorderless(true);
    }
    return updatePreferences;
}

void PrintSystemData::InsertCupsPrinter(const std::string &printerId, const CupsPrinterInfo &printerInfo)
{
    auto info = addedPrinterMap_.Find(printerId);
    if (info == nullptr) {
        PRINT_HILOGI("insert new printer");
        addedPrinterMap_.Insert(printerId, printerInfo);
    } else {
        PRINT_HILOGI("update exist printer");
        info->name = printerInfo.name;
        info->uri = printerInfo.uri;
        info->maker = printerInfo.maker;
        info->printerStatus = printerInfo.printerStatus;
        info->printerCapability = printerInfo.printerCapability;
        info->printPreferences = printerInfo.printPreferences;
    }
}

void PrintSystemData::DeleteCupsPrinter(const std::string &printerId, const std::string &printerName)
{
    if (!printerId.empty()) {
        PRINT_HILOGI("DeleteCupsPrinter printerName: %{public}s", printerName.c_str());
        addedPrinterMap_.Remove(printerId);
        std::filesystem::path filePath =
            PRINTER_SERVICE_PRINTERS_PATH + "/" + PrintUtil::StandardizePrinterName(printerName) + ".json";
        DeleteFile(filePath);
    }
}

void PrintSystemData::DeleteFile(const std::filesystem::path &path)
{
    if (std::filesystem::remove(path)) {
        PRINT_HILOGI("file deleted successfully");
    } else {
        PRINT_HILOGE("failed to delete file");
    }
}

void PrintSystemData::SavePrinterFile(const std::string &printerId)
{
    auto info = addedPrinterMap_.Find(printerId);
    if (info == nullptr) {
        return;
    }
    std::string printerListFilePath =
        PRINTER_SERVICE_PRINTERS_PATH + "/" + PrintUtil::StandardizePrinterName(info->name) + ".json";
    char realPidFile[PATH_MAX] = {};
    if (realpath(printerListFilePath.c_str(), realPidFile) == nullptr) {
        PRINT_HILOGE("The realPidFile is null, errno:%{public}s", std::to_string(errno).c_str());
        return;
    }
    FILE *file = fopen(realPidFile, "w+");
    if (file == nullptr) {
        PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        return;
    }
    nlohmann::json printerJson = nlohmann::json::object();
    printerJson["id"] = printerId;
    printerJson["name"] = info->name;
    printerJson["uri"] = info->uri;
    printerJson["maker"] = info->maker;
    printerJson["alias"] = info->alias;
    if (QueryIpPrinterInfoById(printerId) != nullptr) {
        printerJson["printerStatus"] = info->printerStatus;
    }
    nlohmann::json capsJson;
    ConvertPrinterCapabilityToJson(info->printerCapability, capsJson);
    printerJson["capability"] = capsJson;
    printerJson["preferences"] = info->printPreferences.ConvertToJson();
    std::string jsonString = printerJson.dump();
    size_t jsonLength = jsonString.length();
    size_t writeLength = fwrite(jsonString.c_str(), strlen(jsonString.c_str()), 1, file);
    int fcloseResult = fclose(file);
    if (fcloseResult != 0) {
        PRINT_HILOGE("Close File Failure.");
        return;
    }
    PRINT_HILOGI("SavePrinterFile finished");
    if (writeLength < 0 || (size_t)writeLength != jsonLength) {
        PRINT_HILOGE("SavePrinterFile error");
    }
}

std::string PrintSystemData::QueryPrinterIdByStandardizeName(const std::string &printerName)
{
    std::string stardardizeName = PrintUtil::StandardizePrinterName(printerName);
    return addedPrinterMap_.FindKey([this, stardardizeName](const CupsPrinterInfo &cupsPrinter) -> bool {
        return PrintUtil::StandardizePrinterName(cupsPrinter.name) == stardardizeName;
    });
}

bool PrintSystemData::QueryCupsPrinterInfoByPrinterId(const std::string &printerId, CupsPrinterInfo &cupsPrinter)
{
    auto info = addedPrinterMap_.Find(printerId);
    if (info == nullptr) {
        return false;
    }
    cupsPrinter.name = info->name;
    cupsPrinter.uri = info->uri;
    cupsPrinter.maker = info->maker;
    cupsPrinter.printerCapability = info->printerCapability;
    cupsPrinter.printerStatus = info->printerStatus;
    cupsPrinter.alias = info->alias;
    cupsPrinter.printPreferences = info->printPreferences;
    return true;
}

void PrintSystemData::QueryPrinterInfoById(const std::string &printerId, PrinterInfo &printerInfo)
{
    CupsPrinterInfo cupsPrinter;
    if (QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinter)) {
        printerInfo.SetPrinterId(printerId);
        printerInfo.SetPrinterName(PrintUtil::RemoveUnderlineFromPrinterName(cupsPrinter.name));
        printerInfo.SetCapability(cupsPrinter.printerCapability);
        printerInfo.SetPrinterStatus(cupsPrinter.printerStatus);
        nlohmann::json option;
        option["printerName"] = cupsPrinter.name;
        option["printerUri"] = cupsPrinter.uri;
        option["make"] = cupsPrinter.maker;
        option["alias"] = cupsPrinter.alias;
        printerInfo.SetOption(option.dump());
        printerInfo.Dump();
    } else {
        PRINT_HILOGE("query printer info failed.");
    }
}

void PrintSystemData::UpdatePrinterStatus(const std::string& printerId, PrinterStatus printerStatus)
{
    auto info = addedPrinterMap_.Find(printerId);
    if (info != nullptr) {
        info->printerStatus = printerStatus;
        PRINT_HILOGI("UpdatePrinterStatus success, status: %{public}d", info->printerStatus);
    }
}

bool PrintSystemData::UpdatePrinterAlias(const std::string& printerId, const std::string& printerAlias)
{
    auto info = addedPrinterMap_.Find(printerId);
    if (info != nullptr) {
        if (info->alias != printerAlias) {
            info->alias = printerAlias;
            PRINT_HILOGI("UpdatePrinterAlias success, alias: %{public}s", info->alias.c_str());
            return true;
        }
        PRINT_HILOGW("Alias is the same, no update needed.");
        return false;
    }
    PRINT_HILOGE("Unable to find the corresponding printId.");
    return false;
}

void PrintSystemData::UpdatePrinterUri(const std::shared_ptr<PrinterInfo> &printerInfo)
{
    auto info = addedPrinterMap_.Find(printerInfo->GetPrinterId());
    if (info != nullptr) {
        info->uri = printerInfo->GetUri();
        PRINT_HILOGI("UpdatePrinterUri success");
    }
}

void PrintSystemData::UpdatePrinterPreferences(const std::string &printerId, PrinterPreferences &preferences)
{
    auto info = addedPrinterMap_.Find(printerId);
    if (info != nullptr) {
        info->printPreferences = preferences;
        PRINT_HILOGI("UpdatePrinterPreferences success");
        preferences.Dump();
    }
}

void PrintSystemData::InsertPrinterInfo(const std::string &printerId, const PrinterInfo &printerInfo)
{
    auto iter = addedPrinterInfoList_.find(printerId);
    if (iter == addedPrinterInfoList_.end() || iter->second == nullptr) {
        PRINT_HILOGI("insert new printerInfo");
        addedPrinterInfoList_[printerId] = std::make_shared<PrinterInfo>(printerInfo);
    }
}

std::shared_ptr<PrinterInfo> PrintSystemData::QueryPrinterInfoByPrinterId(const std::string &printerId)
{
    auto iter = addedPrinterInfoList_.find(printerId);
    if (iter != addedPrinterInfoList_.end()) {
        return iter->second;
    }
    return nullptr;
}

void PrintSystemData::GetAddedPrinterListFromSystemData(std::vector<std::string> &printerNameList)
{
    std::vector<std::string> addedPrinterList = QueryAddedPrinterIdList();
    for (auto printerId : addedPrinterList) {
        auto info = addedPrinterMap_.Find(printerId);
        if (info == nullptr) {
            continue;
        }
        PRINT_HILOGD("GetAddedPrinterListFromSystemData info->name: %{public}s", info->name.c_str());
        printerNameList.push_back(info->name);
    }
}

bool PrintSystemData::IsPrinterAdded(const std::string &printerId)
{
    auto info = addedPrinterMap_.Find(printerId);
    if (info == nullptr) {
        return false;
    }
    return true;
}

void PrintSystemData::ConvertPrinterCapabilityToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    capsJson["colorMode"] = printerCapability.GetColorMode();
    capsJson["duplexMode"] = printerCapability.GetDuplexMode();
    ConvertPageSizeToJson(printerCapability, capsJson);

    if (printerCapability.HasMargin()) {
        ConvertPrintMarginToJson(printerCapability, capsJson);
    }

    if (printerCapability.HasResolution()) {
        ConvertPrintResolutionToJson(printerCapability, capsJson);
    }

    if (printerCapability.HasSupportedColorMode()) {
        ConvertSupportedColorModeToJson(printerCapability, capsJson);
    }

    if (printerCapability.HasSupportedDuplexMode()) {
        ConvertSupportedDuplexModeToJson(printerCapability, capsJson);
    }

    if (printerCapability.HasSupportedMediaType()) {
        ConvertSupportedMediaTypeToJson(printerCapability, capsJson);
    }

    if (printerCapability.HasSupportedQuality()) {
        ConvertSupportedQualityToJson(printerCapability, capsJson);
    }

    if (printerCapability.HasOption()) {
        std::string options = printerCapability.GetOption();
        if (!nlohmann::json::accept(options)) {
            PRINT_HILOGE("json accept capability options fail");
            return;
        }
        capsJson["options"] = nlohmann::json::parse(options);
    }
}

void PrintSystemData::ConvertPrintResolutionToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    nlohmann::json resolutionListJson = nlohmann::json::array();
    std::vector<PrintResolution> resolutionList;
    printerCapability.GetResolution(resolutionList);
    for (auto iter : resolutionList) {
        nlohmann::json resolutionJson = nlohmann::json::object();
        resolutionJson["id"] = iter.GetId();
        resolutionJson["horizontalDpi"] = iter.GetHorizontalDpi();
        resolutionJson["verticalDpi"] = iter.GetVerticalDpi();
        resolutionListJson.push_back(resolutionJson);
    }
    capsJson["resolution"] = resolutionListJson;
}

void PrintSystemData::ConvertSupportedColorModeToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    nlohmann::json SupportedColorModeListJson = nlohmann::json::array();
    std::vector<uint32_t> SupportedColorModeList;
    printerCapability.GetSupportedColorMode(SupportedColorModeList);
    for (auto iter : SupportedColorModeList) {
        SupportedColorModeListJson.push_back(iter);
    }
    capsJson["supportedColorMode"] = SupportedColorModeListJson;
}

void PrintSystemData::ConvertSupportedDuplexModeToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    nlohmann::json supportedDuplexModeListJson = nlohmann::json::array();
    std::vector<uint32_t> supportedDuplexModeList;
    printerCapability.GetSupportedDuplexMode(supportedDuplexModeList);
    for (auto iter : supportedDuplexModeList) {
        supportedDuplexModeListJson.push_back(iter);
    }
    capsJson["supportedDuplexMode"] = supportedDuplexModeListJson;
}

void PrintSystemData::ConvertSupportedMediaTypeToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    nlohmann::json supportedMediaTypeListJson = nlohmann::json::array();
    std::vector<std::string> supportedMediaTypeList;
    printerCapability.GetSupportedMediaType(supportedMediaTypeList);
    for (auto iter : supportedMediaTypeList) {
        supportedMediaTypeListJson.push_back(iter);
    }
    capsJson["supportedMediaType"] = supportedMediaTypeListJson;
}

void PrintSystemData::ConvertSupportedQualityToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    nlohmann::json supportedQualityListJson = nlohmann::json::array();
    std::vector<uint32_t> supportedQualityList;
    printerCapability.GetSupportedQuality(supportedQualityList);
    for (auto iter : supportedQualityList) {
        supportedQualityListJson.push_back(iter);
    }
    capsJson["supportedQuality"] = supportedQualityListJson;
}

void PrintSystemData::ConvertPageSizeToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    nlohmann::json pageSizeListJson = nlohmann::json::array();
    std::vector<PrintPageSize> pageSizeList;
    printerCapability.GetSupportedPageSize(pageSizeList);
    for (auto iter : pageSizeList) {
        nlohmann::json pageSizeJson = nlohmann::json::object();
        pageSizeJson["id"] = iter.GetId();
        pageSizeJson["name"] = iter.GetName();
        pageSizeJson["width"] = iter.GetWidth();
        pageSizeJson["height"] = iter.GetHeight();
        pageSizeListJson.push_back(pageSizeJson);
    }
    capsJson["pageSize"] = pageSizeListJson;
}

void PrintSystemData::ConvertPrintMarginToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    nlohmann::json marginJson;
    PrintMargin minMargin;
    printerCapability.GetMinMargin(minMargin);
    if (minMargin.HasTop()) {
        marginJson["top"] = minMargin.GetTop();
    }
    if (minMargin.HasBottom()) {
        marginJson["bottom"] = minMargin.GetBottom();
    }
    if (minMargin.HasLeft()) {
        marginJson["left"] = minMargin.GetLeft();
    }
    if (minMargin.HasRight()) {
        marginJson["right"] = minMargin.GetRight();
    }
    capsJson["minMargin"] = marginJson;
}

bool PrintSystemData::ConvertJsonToPrinterCapability(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    if (!capsJson.contains("colorMode") || !capsJson["colorMode"].is_number()) {
        PRINT_HILOGW("can not find colorMode");
        return false;
    }
    if (!capsJson.contains("duplexMode") || !capsJson["duplexMode"].is_number()) {
        PRINT_HILOGW("can not find duplexMode");
        return false;
    }

    printerCapability.SetColorMode(capsJson["colorMode"].get<uint32_t>());

    printerCapability.SetDuplexMode(capsJson["duplexMode"].get<uint32_t>());

    if (capsJson.contains("minMargin") && capsJson["minMargin"].is_object()) {
        PRINT_HILOGD("find minMargin");
        ConvertJsonToPrintMargin(capsJson, printerCapability);
    }

    if (!ConvertJsonToPrintResolution(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to print resolution failed");
        return false;
    }

    if (!ConvertJsonToPageSize(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to pageSize failed");
        return false;
    }

    if (!ConvertJsonToSupportedColorMode(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to supportedColorMode failed.");
        return false;
    }

    if (!ConvertJsonToSupportedDuplexMode(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to supportedDuplexMode failed.");
        return false;
    }

    if (!ConvertJsonToSupportedMediaType(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to supportedMediaType failed.");
        return false;
    }

    if (!ConvertJsonToSupportedQuality(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to supportedQuality failed.");
        return false;
    }

    if (!ConvertJsonToSupportedOrientation(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to supportedOrientation failed.");
        return false;
    }

    if (capsJson.contains("options") && capsJson["options"].is_object()) {
        PRINT_HILOGD("find options");
        printerCapability.SetOption(capsJson["options"].dump());
    }
    return true;
}

bool PrintSystemData::ConvertJsonToPageSize(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<PrintPageSize>(
        capsJson, "pageSize", printerCapability, &PrinterCapability::SetSupportedPageSize,
        [](const nlohmann::json &item, PrintPageSize &pageSize) -> bool {
            if (!item.is_object() ||
                !item.contains("id") ||!PrintUtils::CheckJsonType<std::string>(item["id"]) ||
                !item.contains("name") ||!PrintUtils::CheckJsonType<std::string>(item["name"]) ||
                !item.contains("width") ||!PrintUtils::CheckJsonType<uint32_t>(item["width"]) ||
                !item.contains("height") ||!PrintUtils::CheckJsonType<uint32_t>(item["height"])) {
                return false;
            }
            pageSize.SetId(item["id"].get<std::string>());
            pageSize.SetName(item["name"].get<std::string>());
            pageSize.SetWidth(item["width"].get<uint32_t>());
            pageSize.SetHeight(item["height"].get<uint32_t>());
            return true;
        }
    );
}

bool PrintSystemData::ConvertJsonToPrintResolution(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<PrintResolution>(capsJson, "resolution", printerCapability,
        &PrinterCapability::SetResolution,
        [](const nlohmann::json &item, PrintResolution &resolution) -> bool {
            if (!item.is_object() ||
                !item.contains("id") || !PrintUtils::CheckJsonType<std::string>(item["id"]) ||
                !item.contains("horizontalDpi") || !PrintUtils::CheckJsonType<uint32_t>(item["horizontalDpi"]) ||
                !item.contains("verticalDpi") || !PrintUtils::CheckJsonType<uint32_t>(item["verticalDpi"])) {
                return false;
            }
            resolution.SetId(item["id"].get<std::string>());
            resolution.SetHorizontalDpi(item["horizontalDpi"].get<uint32_t>());
            resolution.SetVerticalDpi(item["verticalDpi"].get<uint32_t>());
            return true;
        }
    );
}

bool PrintSystemData::ConvertJsonToSupportedColorMode(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedColorMode", printerCapability,
        &PrinterCapability::SetSupportedColorMode,
        [](const nlohmann::json &item, uint32_t &colorMode) -> bool {
            colorMode = item.get<uint32_t>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedDuplexMode(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedDuplexMode", printerCapability,
        &PrinterCapability::SetSupportedDuplexMode,
        [](const nlohmann::json &item, uint32_t &duplexMode) -> bool {
            duplexMode = item.get<uint32_t>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedMediaType(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<std::string>(capsJson, "supportedMediaType", printerCapability,
        &PrinterCapability::SetSupportedMediaType,
        [](const nlohmann::json &item, std::string &mediaType) -> bool {
            mediaType = item.get<std::string>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedQuality(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedQuality", printerCapability,
        &PrinterCapability::SetSupportedQuality,
        [](const nlohmann::json &item, uint32_t &quality) -> bool {
            quality = item.get<uint32_t>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedOrientation(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedOrientation", printerCapability,
        &PrinterCapability::SetSupportedOrientation,
        [](const nlohmann::json &item, uint32_t &orientation) -> bool {
            orientation = item.get<uint32_t>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToPrintMargin(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    nlohmann::json marginJson = capsJson["minMargin"];
    PrintMargin minMargin;
    if (!marginJson.is_object() ||
        !marginJson.contains("top") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["top"]) ||
        !marginJson.contains("bottom") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["bottom"]) ||
        !marginJson.contains("left") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["left"]) ||
        !marginJson.contains("right") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["right"])) {
        PRINT_HILOGE("Invalid format,key is minMargin");
        return false;
    }
    minMargin.SetTop(marginJson["top"].get<uint32_t>());
    minMargin.SetBottom(marginJson["bottom"].get<uint32_t>());
    minMargin.SetLeft(marginJson["left"].get<uint32_t>());
    minMargin.SetRight(marginJson["right"].get<uint32_t>());
    printerCapability.SetMinMargin(minMargin);
    PRINT_HILOGD("ProcessJsonToCapabilityList success, key is minMargin");
    return true;
}

void PrintSystemData::ConvertJsonToPrinterPreferences(nlohmann::json &preferencesJson, PrinterPreferences &preferences)
{
    if (preferencesJson.contains("defaultDuplexMode") && preferencesJson["defaultDuplexMode"].is_number()) {
        preferences.SetDefaultDuplexMode(preferencesJson["defaultDuplexMode"].get<uint32_t>());
    }

    if (preferencesJson.contains("defaultPrintQuality") && preferencesJson["defaultPrintQuality"].is_number()) {
        preferences.SetDefaultPrintQuality(preferencesJson["defaultPrintQuality"].get<uint32_t>());
    }

    if (preferencesJson.contains("defaultMediaType") && preferencesJson["defaultMediaType"].is_string()) {
        preferences.SetDefaultMediaType(preferencesJson["defaultMediaType"].get<std::string>());
    }

    if (preferencesJson.contains("defaultPageSizeId") && preferencesJson["defaultPageSizeId"].is_string()) {
        preferences.SetDefaultPageSizeId(preferencesJson["defaultPageSizeId"].get<std::string>());
    }

    if (preferencesJson.contains("defaultOrientation") && preferencesJson["defaultOrientation"].is_number()) {
        preferences.SetDefaultOrientation(preferencesJson["defaultOrientation"].get<uint32_t>());
    }

    if (preferencesJson.contains("borderless") && preferencesJson["borderless"].is_boolean()) {
        preferences.SetBorderless(preferencesJson["borderless"].get<bool>());
    }

    if (preferencesJson.contains("options") && preferencesJson["options"].is_object()) {
        PRINT_HILOGD("find options");
        preferences.SetOption(preferencesJson["options"].dump());
    }
    preferences.Dump();
}

bool PrintSystemData::GetPrinterCapabilityFromSystemData(CupsPrinterInfo &cupsPrinter,
    std::string printerId, PrinterCapability &printerCapability)
{
    PrinterCapability cupsPrinterCaps = cupsPrinter.printerCapability;
    std::vector<PrintPageSize> pageSizeList;
    cupsPrinterCaps.GetPageSize(pageSizeList);
    if (!pageSizeList.empty()) {
        PRINT_HILOGI("find printer capability in system data");
        printerCapability = cupsPrinterCaps;
        return true;
    } else if (GetPrinterCapabilityFromFile(printerId, printerCapability)) {
        return true;
    }
    return false;
}

bool PrintSystemData::GetPrinterCapabilityFromFile(std::string printerId, PrinterCapability &printerCapability)
{
    PRINT_HILOGI("GetPrinterCapabilityFromFile printerId: %{public}s", printerId.c_str());
    nlohmann::json jsonObject;
    std::string printerListFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINTER_LIST_FILE;
    if (!GetJsonObjectFromFile(jsonObject, printerListFilePath)) {
        PRINT_HILOGW("get json from file fail");
        return false;
    }

    if (!GetPrinterCapabilityFromJson(printerId, jsonObject, printerCapability)) {
        PRINT_HILOGW("get caps from file json fail");
        return false;
    }
    return true;
}

bool PrintSystemData::GetPrinterCapabilityFromJson(
    std::string printerId, nlohmann::json &jsonObject, PrinterCapability &printerCapability)
{
    if (!jsonObject.contains("printer_list") || !jsonObject["printer_list"].is_array()) {
        PRINT_HILOGW("can not find printer_list");
        return false;
    }
    nlohmann::json printerMapJson = jsonObject["printer_list"];
    if (printerMapJson.empty()) {
        PRINT_HILOGW("printer map is empty");
        return false;
    }

    for (auto &element : jsonObject["printer_list"].items()) {
        nlohmann::json object = element.value();
        if (!CheckPrinterInfoJson(object, printerId)) {
            continue;
        }
        if (!object.contains("capability")) {
            PRINT_HILOGE("json does not contain the key as capability");
            continue;
        }
        nlohmann::json capsJson = object["capability"];
        PrinterCapability caps;
        if (!ConvertJsonToPrinterCapability(capsJson, caps)) {
            PRINT_HILOGW("convert json to printer capability failed");
            continue;
        }
        std::vector<PrintPageSize> pageSizeList;
        caps.GetPageSize(pageSizeList);
        if (pageSizeList.size() != 0) {
            PRINT_HILOGI("find printer capability in file");
            caps.Dump();
            printerCapability = caps;
            return true;
        }
    }
    return false;
}

bool PrintSystemData::CheckPrinterInfoJson(nlohmann::json &object, std::string &printerId)
{
    if (!object.contains("id") || !object["id"].is_string()) {
        PRINT_HILOGW("can not find id");
        return false;
    }
    std::string id = object["id"];
    if (id != printerId) {
        return false;
    }
    if (!object.contains("name") || !object["name"].is_string()) {
        PRINT_HILOGW("can not find name");
        return false;
    }
    if (!object.contains("uri") || !object["uri"].is_string()) {
        PRINT_HILOGW("can not find uri");
        return false;
    }
    if (!object.contains("maker") || !object["maker"].is_string()) {
        PRINT_HILOGW("can not find maker");
        return false;
    }
    if (!object.contains("capability") || !object["capability"].is_object()) {
        PRINT_HILOGW("can not find capability");
        return false;
    }
    return true;
}

bool PrintSystemData::CheckPrinterBusy(const std::string &printerId)
{
    CupsPrinterInfo cupsPrinter;
    QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinter);
    if (cupsPrinter.printerStatus == PRINTER_STATUS_BUSY) {
        PRINT_HILOGI("printer is busy");
        return true;
    }
    return false;
}

bool PrintSystemData::GetAllPrintUser(std::vector<int32_t> &allPrintUserList)
{
    nlohmann::json jsonObject;
    std::string userDataFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINT_USER_DATA_FILE;
    if (!GetJsonObjectFromFile(jsonObject, userDataFilePath)) {
        PRINT_HILOGW("get json from file fail");
        return false;
    }
    return ParseUserListJsonV1(jsonObject, allPrintUserList);
}

bool PrintSystemData::ParseUserListJsonV1(nlohmann::json &jsonObject, std::vector<int32_t> &allPrintUserList)
{
    if (!jsonObject.contains("print_user_data") || !jsonObject["print_user_data"].is_object()) {
        PRINT_HILOGE("can not find print_user_data");
        return false;
    }
    for (auto &element : jsonObject["print_user_data"].items()) {
        std::string userIdStr = element.key();
        if (userIdStr.empty()) {
            continue;
        }
        int32_t userId = 0;
        if (!PrintUtil::ConvertToInt(userIdStr, userId)) {
            PRINT_HILOGE("userIdStr [%{public}s] can not parse to number.", userIdStr.c_str());
            return false;
        }
        PRINT_HILOGI("ParseUserListJsonV1 userId: %{public}d", userId);
        allPrintUserList.push_back(userId);
    }
    if (!allPrintUserList.size()) {
        PRINT_HILOGE("allPrintUserList is empty.");
        return false;
    }
    return true;
}

std::vector<std::string> PrintSystemData::QueryAddedPrinterIdList()
{
    return addedPrinterMap_.GetKeyList();
}

std::shared_ptr<PrinterInfo> PrintSystemData::QueryDiscoveredPrinterInfoById(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(discoveredListMutex);
    auto printerIt = discoveredPrinterInfoList_.find(printerId);
    if (printerIt != discoveredPrinterInfoList_.end()) {
        return printerIt ->second;
    }
    return nullptr;
}
std::shared_ptr<PrinterInfo> PrintSystemData::QueryDiscoveredPrinterInfoByName(const std::string &printerName)
{
    std::lock_guard<std::mutex> lock(discoveredListMutex);
    std::string name = PrintUtil::StandardizePrinterName(printerName);
    for (auto iter = discoveredPrinterInfoList_.begin(); iter != discoveredPrinterInfoList_.end(); ++iter) {
        auto printerInfoPtr = iter->second;
        if (printerInfoPtr == nullptr) {
            continue;
        }
        if (PrintUtil::StandardizePrinterName(printerInfoPtr->GetPrinterName()) != name) {
            continue;
        }
        return printerInfoPtr;
    }
    return nullptr;
}

void PrintSystemData::AddPrinterToDiscovery(std::shared_ptr<PrinterInfo> printerInfo)
{
    std::lock_guard<std::mutex> lock(discoveredListMutex);
    if (printerInfo != nullptr) {
        discoveredPrinterInfoList_[printerInfo->GetPrinterId()] = printerInfo;
    }
}

void PrintSystemData::RemovePrinterFromDiscovery(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(discoveredListMutex);
    discoveredPrinterInfoList_.erase(printerId);
}

size_t PrintSystemData::GetDiscoveredPrinterCount()
{
    std::lock_guard<std::mutex> lock(discoveredListMutex);
    return discoveredPrinterInfoList_.size();
}

void PrintSystemData::ClearDiscoveredPrinterList()
{
    std::lock_guard<std::mutex> lock(discoveredListMutex);
    discoveredPrinterInfoList_.clear();
}

std::map<std::string, std::shared_ptr<PrinterInfo>> PrintSystemData::GetDiscoveredPrinterInfo()
{
    std::lock_guard<std::mutex> lock(discoveredListMutex);
    return discoveredPrinterInfoList_;
}

void PrintSystemData::AddIpPrinterToList(std::shared_ptr<PrinterInfo> printerInfo)
{
    std::lock_guard<std::mutex> lock(connectingIpPrinterListMutex);
    if (printerInfo != nullptr) {
        connectingIpPrinterInfoList_[printerInfo->GetPrinterId()] = printerInfo;
    }
}

void PrintSystemData::RemoveIpPrinterFromList(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(connectingIpPrinterListMutex);
    connectingIpPrinterInfoList_.erase(printerId);
}

std::shared_ptr<PrinterInfo> PrintSystemData::QueryIpPrinterInfoById(const std::string &printerId)
{
    std::lock_guard<std::mutex> lock(connectingIpPrinterListMutex);
    auto printerIt = connectingIpPrinterInfoList_.find(printerId);
    if (printerIt != connectingIpPrinterInfoList_.end()) {
        return printerIt ->second;
    }
    return nullptr;
}

void PrintSystemData::BuildEprintPreference(const PrinterCapability &cap, PrinterPreferences &printPreferences)
{
    nlohmann::json capOpt;
    printPreferences.SetDefaultPageSizeId(ParseDefaultPageSizeId(cap, capOpt));
    printPreferences.SetDefaultOrientation(ParseDefaultOrientation(cap, capOpt));
    printPreferences.SetDefaultDuplexMode(ParseDefaultDuplexMode(cap, capOpt));
    printPreferences.SetDefaultPrintQuality(ParseDefaultPrintQuality(cap, capOpt));
    printPreferences.SetDefaultMediaType(ParseDefaultMediaType(cap, capOpt));
    printPreferences.SetBorderless(false);
    printPreferences.Dump();
    return;
}

int32_t PrintSystemData::BuildPrinterPreference(const PrinterCapability &cap, PrinterPreferences &printPreferences)
{
    PRINT_HILOGI("BuildPrinterPreference enter");
    if (!cap.HasOption()) {
        PRINT_HILOGE("capability does not have a cupsOptions attribute");
        return E_PRINT_INVALID_PRINTER;
    }
    std::string capOption = cap.GetOption();
    PRINT_HILOGI("printer capOption %{public}s", capOption.c_str());
    if (!nlohmann::json::accept(capOption)) {
        PRINT_HILOGW("capOption can not parse to json object");
        return E_PRINT_INVALID_PARAMETER;
    }
    nlohmann::json capJson = nlohmann::json::parse(capOption);
    if (!capJson.contains("cupsOptions")) {
        PRINT_HILOGW("The capJson does not have a cupsOptions attribute.");
        return E_PRINT_INVALID_PARAMETER;
    }
    nlohmann::json capOpt = capJson["cupsOptions"];

    printPreferences.SetDefaultPageSizeId(ParseDefaultPageSizeId(cap, capOpt));
    printPreferences.SetDefaultOrientation(ParseDefaultOrientation(cap, capOpt));
    printPreferences.SetDefaultDuplexMode(ParseDefaultDuplexMode(cap, capOpt));
    printPreferences.SetDefaultPrintQuality(ParseDefaultPrintQuality(cap, capOpt));
    printPreferences.SetDefaultMediaType(ParseDefaultMediaType(cap, capOpt));
    printPreferences.SetBorderless(false);
    printPreferences.Dump();
    return E_PRINT_NONE;
}

std::string PrintSystemData::ParseDefaultPageSizeId(const PrinterCapability &cap, nlohmann::json &capOpt)
{
    if (capOpt.contains("defaultPageSizeId") && capOpt["defaultPageSizeId"].is_string()) {
        return capOpt["defaultPageSizeId"].get<std::string>();
    }
    std::vector<PrintPageSize> supportedPageSize;
    cap.GetSupportedPageSize(supportedPageSize);
    if (supportedPageSize.size() == 0) {
        return "";
    }
    for (auto pageSize : supportedPageSize) {
        if (pageSize.GetId() == DEFAULT_PAGESIZE_ID) {
            return DEFAULT_PAGESIZE_ID;
        }
    }
    return supportedPageSize[0].GetId();
}

int32_t PrintSystemData::ParseDefaultOrientation(const PrinterCapability &cap, nlohmann::json &capOpt)
{
    int32_t defaultOrientation = 0;
    if (capOpt.contains("orientation-requested-default") && capOpt["orientation-requested-default"].is_string()) {
        PrintUtil::ConvertToInt(capOpt["orientation-requested-default"].get<std::string>(), defaultOrientation);
    }
    return defaultOrientation;
}

int32_t PrintSystemData::ParseDefaultDuplexMode(const PrinterCapability &cap, nlohmann::json &capOpt)
{
    if (capOpt.contains("sides-default") && capOpt["sides-default"].is_string()) {
        int32_t defaultDuplexMode = DUPLEX_MODE_NONE;
        PrintUtil::ConvertToInt(capOpt["sides-default"].get<std::string>(), defaultDuplexMode);
        return defaultDuplexMode;
    }
    std::vector<uint32_t> supportedDuplexModeList;
    cap.GetSupportedDuplexMode(supportedDuplexModeList);
    if (supportedDuplexModeList.size() == 0) {
        return 0;
    }
    for (auto duplexMode : supportedDuplexModeList) {
        if (duplexMode == DUPLEX_MODE_NONE) {
            return DUPLEX_MODE_NONE;
        }
    }
    return supportedDuplexModeList[0];
}

int32_t PrintSystemData::ParseDefaultPrintQuality(const PrinterCapability &cap, nlohmann::json &capOpt)
{
    if (capOpt.contains("print-quality-default") && capOpt["print-quality-default"].is_string()) {
        int32_t defaultPrintQuality = PRINT_QUALITY_NORMAL;
        PrintUtil::ConvertToInt(capOpt["print-quality-default"].get<std::string>(), defaultPrintQuality);
        return defaultPrintQuality;
    }
    std::vector<uint32_t> supportedQualityList;
    cap.GetSupportedQuality(supportedQualityList);
    if (supportedQualityList.size() == 0) {
        return 0;
    }
    for (auto quality : supportedQualityList) {
        if (quality == PRINT_QUALITY_NORMAL) {
            return PRINT_QUALITY_NORMAL;
        }
    }
    return supportedQualityList[0];
}

std::string PrintSystemData::ParseDefaultMediaType(const PrinterCapability &cap, nlohmann::json &capOpt)
{
    if (capOpt.contains("media-type-default") && capOpt["media-type-default"].is_string()) {
        return capOpt["media-type-default"].get<std::string>();
    }
    std::vector<std::string> supportedMediaTypeList;
    cap.GetSupportedMediaType(supportedMediaTypeList);
    if (supportedMediaTypeList.size() == 0) {
        return "";
    }
    for (auto mediaType : supportedMediaTypeList) {
        if (mediaType == DEFAULT_MEDIA_TYPE) {
            return DEFAULT_MEDIA_TYPE;
        }
    }
    return supportedMediaTypeList[0];
}
}  // namespace Print
}  // namespace OHOS