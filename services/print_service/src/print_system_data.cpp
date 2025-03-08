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

bool PrintSystemData::ParsePrinterListJsonV1(Json::Value &jsonObject)
{
    if (!jsonObject.isMember("printer_list") || !jsonObject["printer_list"].isArray()) {
        PRINT_HILOGW("can not find printer_list");
        return false;
    }
    for (int i = 0; i < jsonObject["printer_list"].size(); i++) {
        Json::Value object = jsonObject["printer_list"][i];
        if (!ConvertJsonToCupsPrinterInfo(object)) {
            PRINT_HILOGW("can not find necessary param");
            continue;
        }
    }
    return true;
}

bool PrintSystemData::ConvertJsonToCupsPrinterInfo(Json::Value &object)
{
    if (!object.isMember("id") || !object["id"].isString()) {
        PRINT_HILOGW("can not find id");
        return false;
    }
    std::string id = object["id"].asString();
    if (!object.isMember("name") || !object["name"].isString()) {
        PRINT_HILOGW("can not find name");
        return false;
    }
    std::string name = object["name"].asString();
    if (!object.isMember("uri") || !object["uri"].isString()) {
        PRINT_HILOGW("can not find uri");
        return false;
    }
    std::string uri = object["uri"].asString();
    if (!object.isMember("maker") || !object["maker"].isString()) {
        PRINT_HILOGW("can not find maker");
        return false;
    }
    std::string maker = object["maker"].asString();
    if (!object.isMember("capability") || !object["capability"].isObject()) {
        PRINT_HILOGW("can not find capability");
        return false;
    }
    PrinterCapability printerCapability;
    Json::Value capsJson;
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

void PrintSystemData::ConvertInnerJsonToCupsPrinterInfo(Json::Value &object, CupsPrinterInfo &info)
{
    if (object.isMember("alias") && object["alias"].isString()) {
        info.alias = object["alias"].asString();
    }
    if (object.isMember("printerStatus") && object["printerStatus"].isInt()) {
        info.printerStatus = static_cast<PrinterStatus>(object["printerStatus"].asInt());
    }
    if (object.isMember("preferences") && object["preferences"].isObject()) {
        info.printPreferences.ConvertJsonToPrinterPreferences(object["preferences"]);
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

    Json::Value printerListJson;
    std::string printerListFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINTER_LIST_FILE;
    if (GetJsonObjectFromFile(printerListJson, printerListFilePath) && ParsePrinterListJsonV1(printerListJson)) {
        PRINT_HILOGW("previous printer list file exist");
        Json::Value preferencesJson;
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
    Json::Value fileJson;
    if (!PrintJsonUtil::ParseFromStream(file, fileJson)) {
        PRINT_HILOGW("json accept fail");
        return false;
    }
    file.close();

    if (!ConvertJsonToCupsPrinterInfo(fileJson)) {
        PRINT_HILOGW("can not find necessary param");
        return false;
    }
    return true;
}

bool PrintSystemData::GetJsonObjectFromFile(Json::Value &jsonObject, const std::string &fileName)
{
    std::ifstream ifs(fileName.c_str(), std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        PRINT_HILOGW("open printer list file fail");
        return false;
    }
    if (!PrintJsonUtil::ParseFromStream(ifs, jsonObject)) {
        PRINT_HILOGW("json accept fail");
        return false;
    }
    ifs.close();
    if (fileName.find(PRINTER_PREFERENCE_FILE) != std::string::npos) {
        return true;
    }
    if (!jsonObject.isMember("version") || !jsonObject["version"].isString()) {
        PRINT_HILOGW("can not find version");
        return false;
    }
    std::string version = jsonObject["version"].asString();
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

bool PrintSystemData::ParsePrinterPreferencesJson(Json::Value &jsonObject)
{
    if (!jsonObject.isMember("printer_list") || !jsonObject["printer_list"].isArray()) {
        PRINT_HILOGW("can not find printer_list");
        return false;
    }
    for (int i = 0; i < jsonObject["printer_list"].size(); i++) {
        Json::Value object = jsonObject["printer_list"][i];
        Json::Value::Members keys = object.getMemberNames();
        for (auto it = keys.begin(); it != keys.end(); it++) {
            std::string printerId = *it;
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
            Json::Value printPreferenceJson = object[printerId];
            if (!printPreferenceJson.isMember("setting") || !printPreferenceJson["setting"].isObject()) {
                PRINT_HILOGW("can not find setting");
                continue;
            }
            Json::Value settingJson = printPreferenceJson["setting"];
            PRINT_HILOGD("ParsePrinterPreferencesJson settingJson: %{public}s",
                (PrintJsonUtil::WriteString(settingJson)).c_str());
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

bool PrintSystemData::ParsePreviousPreferencesSetting(Json::Value &settingJson, PrinterPreferences &preferences)
{
    bool updatePreferences = false;
    if (settingJson.isMember("pagesizeId") && settingJson["pagesizeId"].isString() &&
        !settingJson["pagesizeId"].asString().empty()) {
        updatePreferences = true;
        preferences.SetDefaultPageSizeId(settingJson["pagesizeId"].asString());
    }
    if (settingJson.isMember("orientation") && settingJson["orientation"].isString() &&
        !settingJson["orientation"].asString().empty()) {
        updatePreferences = true;
        int32_t defaultOrientation = 0;
        PrintUtil::ConvertToInt(settingJson["orientation"].asString(), defaultOrientation);
        preferences.SetDefaultOrientation(defaultOrientation);
    }
    if (settingJson.isMember("duplex") && settingJson["duplex"].isString() &&
        !settingJson["duplex"].asString().empty()) {
        updatePreferences = true;
        int32_t defaultDuplexMode = DUPLEX_MODE_NONE;
        PrintUtil::ConvertToInt(settingJson["duplex"].asString(), defaultDuplexMode);
        preferences.SetDefaultDuplexMode(defaultDuplexMode);
    }
    if (settingJson.isMember("quality") && settingJson["quality"].isString() &&
        !settingJson["quality"].asString().empty()) {
        updatePreferences = true;
        int32_t defaultPrintQuality = PRINT_QUALITY_NORMAL;
        PrintUtil::ConvertToInt(settingJson["quality"].asString(), defaultPrintQuality);
        preferences.SetDefaultPrintQuality(defaultPrintQuality);
    }
    if (settingJson.isMember("mediaType") && settingJson["mediaType"].isString() &&
        !settingJson["mediaType"].asString().empty()) {
        updatePreferences = true;
        preferences.SetDefaultMediaType(settingJson["mediaType"].asString());
    }
    if (settingJson.isMember("hasMargin") && settingJson["hasMargin"].isBool() &&
        settingJson["hasMargin"].asBool() == false) {
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
        if (!printerInfo.alias.empty()) {
            info->alias = printerInfo.alias;
        }
        info->printPreferences = printerInfo.printPreferences;
    }
}

void PrintSystemData::DeleteCupsPrinter(const std::string &printerId, const std::string &printerName)
{
    if (!printerId.empty()) {
        PRINT_HILOGI("DeleteCupsPrinter printerName: %{private}s", printerName.c_str());
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
    if (realpath(PRINTER_SERVICE_FILE_PATH.c_str(), realPidFile) == nullptr) {
        PRINT_HILOGE("The realPidFile is null, errno:%{public}s", std::to_string(errno).c_str());
        return;
    }
    FILE *file = fopen(printerListFilePath.c_str(), "w+");
    if (file == nullptr) {
        PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        return;
    }
    Json::Value printerJson;
    printerJson["id"] = printerId;
    printerJson["name"] = info->name;
    printerJson["uri"] = info->uri;
    printerJson["maker"] = info->maker;
    printerJson["alias"] = info->alias;
    if (QueryIpPrinterInfoById(printerId) != nullptr) {
        printerJson["printerStatus"] = info->printerStatus;
    }
    Json::Value capsJson;
    ConvertPrinterCapabilityToJson(info->printerCapability, capsJson);
    printerJson["capability"] = capsJson;
    printerJson["preferences"] = info->printPreferences.ConvertToJson();
    std::string jsonString = PrintJsonUtil::WriteString(printerJson);
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
        Json::Value option;
        option["printerName"] = cupsPrinter.name;
        option["printerUri"] = cupsPrinter.uri;
        option["make"] = cupsPrinter.maker;
        option["alias"] = cupsPrinter.alias;
        printerInfo.SetOption(PrintJsonUtil::WriteString(option));
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

void PrintSystemData::UpdatePrinterPreferences(const std::string &printerId, const PrinterPreferences &preferences)
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

void PrintSystemData::ConvertPrinterCapabilityToJson(PrinterCapability &printerCapability, Json::Value &capsJson)
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
        std::istringstream iss(options);
        if (!PrintJsonUtil::ParseFromStream(iss, capsJson["options"])) {
            PRINT_HILOGE("json accept capability options fail");
            return;
        }
    }
}

void PrintSystemData::ConvertPrintResolutionToJson(PrinterCapability &printerCapability, Json::Value &capsJson)
{
    Json::Value resolutionListJson;
    std::vector<PrintResolution> resolutionList;
    printerCapability.GetResolution(resolutionList);
    for (auto iter : resolutionList) {
        Json::Value resolutionJson;
        resolutionJson["id"] = iter.GetId();
        resolutionJson["horizontalDpi"] = iter.GetHorizontalDpi();
        resolutionJson["verticalDpi"] = iter.GetVerticalDpi();
        resolutionListJson.append(resolutionJson);
    }
    capsJson["resolution"] = resolutionListJson;
}

void PrintSystemData::ConvertSupportedColorModeToJson(PrinterCapability &printerCapability, Json::Value &capsJson)
{
    Json::Value SupportedColorModeListJson;
    std::vector<uint32_t> SupportedColorModeList;
    printerCapability.GetSupportedColorMode(SupportedColorModeList);
    for (auto iter : SupportedColorModeList) {
        SupportedColorModeListJson.append(iter);
    }
    capsJson["supportedColorMode"] = SupportedColorModeListJson;
}

void PrintSystemData::ConvertSupportedDuplexModeToJson(PrinterCapability &printerCapability, Json::Value &capsJson)
{
    Json::Value supportedDuplexModeListJson;
    std::vector<uint32_t> supportedDuplexModeList;
    printerCapability.GetSupportedDuplexMode(supportedDuplexModeList);
    for (auto iter : supportedDuplexModeList) {
        supportedDuplexModeListJson.append(iter);
    }
    capsJson["supportedDuplexMode"] = supportedDuplexModeListJson;
}

void PrintSystemData::ConvertSupportedMediaTypeToJson(PrinterCapability &printerCapability, Json::Value &capsJson)
{
    Json::Value supportedMediaTypeListJson;
    std::vector<std::string> supportedMediaTypeList;
    printerCapability.GetSupportedMediaType(supportedMediaTypeList);
    for (auto iter : supportedMediaTypeList) {
        supportedMediaTypeListJson.append(iter);
    }
    capsJson["supportedMediaType"] = supportedMediaTypeListJson;
}

void PrintSystemData::ConvertSupportedQualityToJson(PrinterCapability &printerCapability, Json::Value &capsJson)
{
    Json::Value supportedQualityListJson;
    std::vector<uint32_t> supportedQualityList;
    printerCapability.GetSupportedQuality(supportedQualityList);
    for (auto iter : supportedQualityList) {
        supportedQualityListJson.append(iter);
    }
    capsJson["supportedQuality"] = supportedQualityListJson;
}

void PrintSystemData::ConvertPageSizeToJson(PrinterCapability &printerCapability, Json::Value &capsJson)
{
    Json::Value pageSizeListJson;
    std::vector<PrintPageSize> pageSizeList;
    printerCapability.GetSupportedPageSize(pageSizeList);
    for (auto iter : pageSizeList) {
        Json::Value pageSizeJson;
        pageSizeJson["id"] = iter.GetId();
        pageSizeJson["name"] = iter.GetName();
        pageSizeJson["width"] = iter.GetWidth();
        pageSizeJson["height"] = iter.GetHeight();
        pageSizeListJson.append(pageSizeJson);
    }
    capsJson["pageSize"] = pageSizeListJson;
}

void PrintSystemData::ConvertPrintMarginToJson(PrinterCapability &printerCapability, Json::Value &capsJson)
{
    Json::Value marginJson;
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

bool PrintSystemData::ConvertJsonToPrinterCapability(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    if (!capsJson.isMember("colorMode") || !capsJson["colorMode"].isInt()) {
        PRINT_HILOGW("can not find colorMode");
        return false;
    }
    if (!capsJson.isMember("duplexMode") || !capsJson["duplexMode"].isInt()) {
        PRINT_HILOGW("can not find duplexMode");
        return false;
    }

    printerCapability.SetColorMode(capsJson["colorMode"].asInt());

    printerCapability.SetDuplexMode(capsJson["duplexMode"].asInt());

    if (capsJson.isMember("minMargin") && capsJson["minMargin"].isObject()) {
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

    if (capsJson.isMember("options") && capsJson["options"].isObject()) {
        PRINT_HILOGD("find options");
        printerCapability.SetOption(PrintJsonUtil::WriteString(capsJson["options"]));
    }
    return true;
}

bool PrintSystemData::ConvertJsonToPageSize(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<PrintPageSize>(
        capsJson, "pageSize", printerCapability, &PrinterCapability::SetSupportedPageSize,
        [](const Json::Value &item, PrintPageSize &pageSize) -> bool {
            if (!item.isObject() ||
                !item.isMember("id") ||!PrintUtils::CheckJsonType<std::string>(item["id"]) ||
                !item.isMember("name") ||!PrintUtils::CheckJsonType<std::string>(item["name"]) ||
                !item.isMember("width") ||!PrintUtils::CheckJsonType<uint32_t>(item["width"]) ||
                !item.isMember("height") ||!PrintUtils::CheckJsonType<uint32_t>(item["height"])) {
                return false;
            }
            pageSize.SetId(item["id"].asString());
            pageSize.SetName(item["name"].asString());
            pageSize.SetWidth(item["width"].asInt());
            pageSize.SetHeight(item["height"].asInt());
            return true;
        }
    );
}

bool PrintSystemData::ConvertJsonToPrintResolution(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<PrintResolution>(capsJson, "resolution", printerCapability,
        &PrinterCapability::SetResolution,
        [](const Json::Value &item, PrintResolution &resolution) -> bool {
            if (!item.isObject() ||
                !item.isMember("id") || !PrintUtils::CheckJsonType<std::string>(item["id"]) ||
                !item.isMember("horizontalDpi") || !PrintUtils::CheckJsonType<uint32_t>(item["horizontalDpi"]) ||
                !item.isMember("verticalDpi") || !PrintUtils::CheckJsonType<uint32_t>(item["verticalDpi"])) {
                return false;
            }
            resolution.SetId(item["id"].asString());
            resolution.SetHorizontalDpi(item["horizontalDpi"].asInt());
            resolution.SetVerticalDpi(item["verticalDpi"].asInt());
            return true;
        }
    );
}

bool PrintSystemData::ConvertJsonToSupportedColorMode(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedColorMode", printerCapability,
        &PrinterCapability::SetSupportedColorMode,
        [](const Json::Value &item, uint32_t &colorMode) -> bool {
            colorMode = item.asInt();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedDuplexMode(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedDuplexMode", printerCapability,
        &PrinterCapability::SetSupportedDuplexMode,
        [](const Json::Value &item, uint32_t &duplexMode) -> bool {
            duplexMode = item.asInt();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedMediaType(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<std::string>(capsJson, "supportedMediaType", printerCapability,
        &PrinterCapability::SetSupportedMediaType,
        [](const Json::Value &item, std::string &mediaType) -> bool {
            mediaType = item.asString();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedQuality(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedQuality", printerCapability,
        &PrinterCapability::SetSupportedQuality,
        [](const Json::Value &item, uint32_t &quality) -> bool {
            quality = item.asInt();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedOrientation(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedOrientation", printerCapability,
        &PrinterCapability::SetSupportedOrientation,
        [](const Json::Value &item, uint32_t &orientation) -> bool {
            orientation = item.asInt();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToPrintMargin(Json::Value &capsJson, PrinterCapability &printerCapability)
{
    Json::Value marginJson = capsJson["minMargin"];
    PrintMargin minMargin;
    if (!marginJson.isObject() ||
        !marginJson.isMember("top") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["top"]) ||
        !marginJson.isMember("bottom") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["bottom"]) ||
        !marginJson.isMember("left") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["left"]) ||
        !marginJson.isMember("right") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["right"])) {
        PRINT_HILOGE("Invalid format,key is minMargin");
        return false;
    }
    minMargin.SetTop(marginJson["top"].asInt());
    minMargin.SetBottom(marginJson["bottom"].asInt());
    minMargin.SetLeft(marginJson["left"].asInt());
    minMargin.SetRight(marginJson["right"].asInt());
    printerCapability.SetMinMargin(minMargin);
    PRINT_HILOGD("ProcessJsonToCapabilityList success, key is minMargin");
    return true;
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
    PRINT_HILOGI("GetPrinterCapabilityFromFile printerId: %{private}s", printerId.c_str());
    Json::Value jsonObject;
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
    std::string printerId, Json::Value &jsonObject, PrinterCapability &printerCapability)
{
    if (!jsonObject.isMember("printer_list") || !jsonObject["printer_list"].isArray()) {
        PRINT_HILOGW("can not find printer_list");
        return false;
    }
    Json::Value printerMapJson = jsonObject["printer_list"];
    if (printerMapJson.empty()) {
        PRINT_HILOGW("printer map is empty");
        return false;
    }

    for (int i = 0; i < jsonObject["printer_list"].size(); i++) {
        Json::Value object = jsonObject["printer_list"][i];
        if (!CheckPrinterInfoJson(object, printerId)) {
            continue;
        }
        if (!object.isMember("capability")) {
            PRINT_HILOGE("json does not contain the key as capability");
            continue;
        }
        Json::Value capsJson = object["capability"];
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

bool PrintSystemData::CheckPrinterInfoJson(Json::Value &object, std::string &printerId)
{
    if (!object.isMember("id") || !object["id"].isString()) {
        PRINT_HILOGW("can not find id");
        return false;
    }
    std::string id = object["id"].asString();
    if (id != printerId) {
        return false;
    }
    if (!object.isMember("name") || !object["name"].isString()) {
        PRINT_HILOGW("can not find name");
        return false;
    }
    if (!object.isMember("uri") || !object["uri"].isString()) {
        PRINT_HILOGW("can not find uri");
        return false;
    }
    if (!object.isMember("maker") || !object["maker"].isString()) {
        PRINT_HILOGW("can not find maker");
        return false;
    }
    if (!object.isMember("capability") || !object["capability"].isObject()) {
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
    Json::Value jsonObject;
    std::string userDataFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINT_USER_DATA_FILE;
    if (!GetJsonObjectFromFile(jsonObject, userDataFilePath)) {
        PRINT_HILOGW("get json from file fail");
        return false;
    }
    return ParseUserListJsonV1(jsonObject, allPrintUserList);
}

bool PrintSystemData::ParseUserListJsonV1(Json::Value &jsonObject, std::vector<int32_t> &allPrintUserList)
{
    if (!jsonObject.isMember("print_user_data") || !jsonObject["print_user_data"].isObject()) {
        PRINT_HILOGE("can not find print_user_data");
        return false;
    }
    Json::Value::Members keys = jsonObject["print_user_data"].getMemberNames();
    for (auto key = keys.begin(); key != keys.end(); key++) {
        std::string userIdStr = *key;
        if (userIdStr.empty()) {
            continue;
        }
        int32_t userId = 0;
        if (!PrintUtil::ConvertToInt(userIdStr, userId)) {
            PRINT_HILOGE("userIdStr [%{private}s] can not parse to number.", userIdStr.c_str());
            return false;
        }
        PRINT_HILOGI("ParseUserListJsonV1 userId: %{private}d", userId);
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
    Json::Value capOpt;
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
    Json::Value capJson;
    std::istringstream iss(capOption);
    if (!PrintJsonUtil::ParseFromStream(iss, capJson)) {
        PRINT_HILOGW("capOption can not parse to json object");
        return E_PRINT_INVALID_PARAMETER;
    }
    if (!capJson.isMember("cupsOptions")) {
        PRINT_HILOGW("The capJson does not have a cupsOptions attribute.");
        return E_PRINT_INVALID_PARAMETER;
    }
    Json::Value capOpt = capJson["cupsOptions"];

    printPreferences.SetDefaultPageSizeId(ParseDefaultPageSizeId(cap, capOpt));
    printPreferences.SetDefaultOrientation(ParseDefaultOrientation(cap, capOpt));
    printPreferences.SetDefaultDuplexMode(ParseDefaultDuplexMode(cap, capOpt));
    printPreferences.SetDefaultPrintQuality(ParseDefaultPrintQuality(cap, capOpt));
    printPreferences.SetDefaultMediaType(ParseDefaultMediaType(cap, capOpt));
    printPreferences.SetBorderless(false);
    printPreferences.Dump();
    return E_PRINT_NONE;
}

std::string PrintSystemData::ParseDefaultPageSizeId(const PrinterCapability &cap, Json::Value &capOpt)
{
    if (capOpt.isMember("defaultPageSizeId") && capOpt["defaultPageSizeId"].isString()) {
        return capOpt["defaultPageSizeId"].asString();
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

int32_t PrintSystemData::ParseDefaultOrientation(const PrinterCapability &cap, Json::Value &capOpt)
{
    int32_t defaultOrientation = 0;
    if (capOpt.isMember("orientation-requested-default") && capOpt["orientation-requested-default"].isString()) {
        PrintUtil::ConvertToInt(capOpt["orientation-requested-default"].asString(), defaultOrientation);
    }
    return defaultOrientation;
}

int32_t PrintSystemData::ParseDefaultDuplexMode(const PrinterCapability &cap, Json::Value &capOpt)
{
    if (capOpt.isMember("sides-default") && capOpt["sides-default"].isString()) {
        int32_t defaultDuplexMode = DUPLEX_MODE_NONE;
        PrintUtil::ConvertToInt(capOpt["sides-default"].asString(), defaultDuplexMode);
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

int32_t PrintSystemData::ParseDefaultPrintQuality(const PrinterCapability &cap, Json::Value &capOpt)
{
    if (capOpt.isMember("print-quality-default") && capOpt["print-quality-default"].isString()) {
        int32_t defaultPrintQuality = PRINT_QUALITY_NORMAL;
        PrintUtil::ConvertToInt(capOpt["print-quality-default"].asString(), defaultPrintQuality);
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

std::string PrintSystemData::ParseDefaultMediaType(const PrinterCapability &cap, Json::Value &capOpt)
{
    if (capOpt.isMember("media-type-default") && capOpt["media-type-default"].isString()) {
        return capOpt["media-type-default"].asString();
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