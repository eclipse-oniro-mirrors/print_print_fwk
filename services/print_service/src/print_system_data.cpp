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
#include "print_system_data.h"
#include "print_log.h"
#include "print_util.h"
#include "print_constant.h"

namespace {
const std::string PRINTER_LIST_FILE = "/data/service/el2/public/print_service/printer_list.json";
const std::string PRINTER_LIST_VERSION = "v1";
const std::string PRINT_USER_DATA_FILE = "/data/service/el2/public/print_service/print_user_data.json";
const std::string PRINT_USER_DATA_VERSION = "v1";
}  // namespace

namespace OHOS {
namespace Print {

using namespace std;

bool PrintSystemData::ParsePrinterListJsonV1(nlohmann::json &jsonObject)
{
    if (!jsonObject.contains("printer_list") || !jsonObject["printer_list"].is_array()) {
        PRINT_HILOGW("can not find printer_list");
        return false;
    }
    for (auto &element : jsonObject["printer_list"].items()) {
        nlohmann::json object = element.value();
        if (!object.contains("id") || !object["id"].is_string()) {
            PRINT_HILOGW("can not find id");
            continue;
        }
        std::string id = object["id"];
        if (!object.contains("name") || !object["name"].is_string()) {
            PRINT_HILOGW("can not find name");
            continue;
        }
        std::string name = object["name"];
        if (!object.contains("uri") || !object["uri"].is_string()) {
            PRINT_HILOGW("can not find uri");
            continue;
        }
        std::string uri = object["uri"];
        if (!object.contains("maker") || !object["maker"].is_string()) {
            PRINT_HILOGW("can not find maker");
            continue;
        }
        std::string maker = object["maker"];
        if (!object.contains("capability") || !object["capability"].is_object()) {
            PRINT_HILOGW("can not find capability");
            continue;
        }
        nlohmann::json capsJson = object["capability"];
        PrinterCapability printerCapability;
        if (!ConvertJsonToPrinterCapability(capsJson, printerCapability)) {
            PRINT_HILOGW("convert json to printer capability failed");
            continue;
        }
        printerCapability.Dump();
        CupsPrinterInfo info;
        info.name = name;
        info.uri = uri;
        info.maker = maker;
        info.printerCapability = printerCapability;
        if (object.contains("alias") && object["alias"].is_string()) {
            info.alias = object["alias"];
        }
        InsertCupsPrinter(id, info, true);
    }
    return true;
}

bool PrintSystemData::Init()
{
    addedPrinterMap_.Clear();
    nlohmann::json jsonObject;
    if (!GetJsonObjectFromFile(jsonObject, PRINTER_LIST_FILE)) {
        PRINT_HILOGW("get json from file fail");
        return false;
    }
    return ParsePrinterListJsonV1(jsonObject);
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
    if (!jsonObject.contains("version") || !jsonObject["version"].is_string()) {
        PRINT_HILOGW("can not find version");
        return false;
    }
    std::string version = jsonObject["version"].get<std::string>();
    PRINT_HILOGI("json version: %{public}s", version.c_str());
    std::string fileVersion = "";
    if (strcmp(fileName.c_str(), PRINTER_LIST_FILE.c_str())) {
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

void PrintSystemData::InsertCupsPrinter(
    const std::string &printerId, const CupsPrinterInfo &printerInfo, bool needUpdateCaps)
{
    auto orderId = 0;
    if (addedPrinterOrderList_.size()) {
        orderId = addedPrinterOrderList_.rbegin()->first;
    }
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
        info->alias = printerInfo.alias;
        if (needUpdateCaps) {
            info->printerCapability = printerInfo.printerCapability;
        }
    }
    if (needUpdateCaps) {
        auto addedPrinterOrderListIter = std::find_if(addedPrinterOrderList_.begin(),
            addedPrinterOrderList_.end(),
            [&printerId](
                const std::pair<uint32_t, std::string> &addedPrinter) { return addedPrinter.second == printerId; });
        if (addedPrinterOrderListIter != addedPrinterOrderList_.end()) {
            PRINT_HILOGW("value found");
        } else {
            addedPrinterOrderList_.insert(std::make_pair(orderId + 1, printerId));
            PRINT_HILOGI("printerId: %{public}s, orderId: %{public}d", printerId.c_str(), orderId + 1);
        }
    }
}

void PrintSystemData::DeleteCupsPrinter(const std::string &printerId)
{
    if (!printerId.empty()) {
        PRINT_HILOGI("DeleteCupsPrinter printerId: %{public}s", printerId.c_str());
        addedPrinterMap_.Remove(printerId);
        for (auto printer: addedPrinterOrderList_) {
            if (!strcmp(printerId.c_str(), printer.second.c_str())) {
                addedPrinterOrderList_.erase(printer.first);
                PRINT_HILOGI("erase printer order success");
                break;
            }
        }
        SaveCupsPrinterMap();
    }
}

bool PrintSystemData::SaveCupsPrinterMap()
{
    char realPidFile[PATH_MAX] = {};
    if (realpath(PRINTER_LIST_FILE.c_str(), realPidFile) == nullptr) {
        PRINT_HILOGE("The realPidFile is null.");
        return E_PRINT_SERVER_FAILURE;
    }
    int32_t fd = open(realPidFile, O_CREAT | O_TRUNC | O_RDWR, 0640);
    PRINT_HILOGD("SaveCupsPrinterMap fd: %{public}d", fd);
    if (fd < 0) {
        PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        return false;
    }
    nlohmann::json printerMapJson = nlohmann::json::array();
    for (auto printer : addedPrinterOrderList_) {
        auto info = addedPrinterMap_.Find(printer.second);
        if (info == nullptr) {
            continue;
        }
        nlohmann::json printerJson = nlohmann::json::object();
        printerJson["id"] = printer.second;
        printerJson["name"] = info->name;
        printerJson["uri"] = info->uri;
        printerJson["maker"] = info->maker;
        printerJson["alias"] = info->alias;
        nlohmann::json capsJson;
        ConvertPrinterCapabilityToJson(info->printerCapability, capsJson);
        printerJson["capability"] = capsJson;
        printerMapJson.push_back(printerJson);
    }
    nlohmann::json jsonObject;
    jsonObject["version"] = PRINTER_LIST_VERSION;
    jsonObject["printer_list"] = printerMapJson;
    std::string jsonString = jsonObject.dump();
    size_t jsonLength = jsonString.length();
    auto writeLength = write(fd, jsonString.c_str(), jsonLength);
    close(fd);
    PRINT_HILOGI("SaveCupsPrinterMap finished");
    if (writeLength < 0) {
        return false;
    }
    return (size_t)writeLength == jsonLength;
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
    for (auto it = addedPrinterOrderList_.rbegin(); it != addedPrinterOrderList_.rend(); ++it) {
        auto info = addedPrinterMap_.Find(it->second);
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

    ConvertPageSizeToJson(printerCapability, capsJson);

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
        &PrinterCapability::SetSupportedColorMode,
        [](const nlohmann::json &item, uint32_t &colorMode) -> bool {
            colorMode = item.get<uint32_t>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedMediaType(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<std::string>(capsJson, "supportedMediaType", printerCapability,
        &PrinterCapability::SetSupportedMediaType,
        [](const nlohmann::json &item, std::string &colorMode) -> bool {
            colorMode = item.get<std::string>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedQuality(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedQuality", printerCapability,
        &PrinterCapability::SetSupportedQuality,
        [](const nlohmann::json &item, uint32_t &colorMode) -> bool {
            colorMode = item.get<uint32_t>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToSupportedOrientation(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    return ProcessJsonToCapabilityList<uint32_t>(capsJson, "supportedOrientation", printerCapability,
        &PrinterCapability::SetSupportedOrientation,
        [](const nlohmann::json &item, uint32_t &colorMode) -> bool {
            colorMode = item.get<uint32_t>();
            return true;
        });
}

bool PrintSystemData::ConvertJsonToPrintMargin(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    nlohmann::json marginJson = capsJson["minMargin"];
    PrintMargin minMargin;
    if (!marginJson.is_object() ||
        !marginJson.contains("top") || !PrintUtils::CheckJsonType<std::string>(marginJson["top"]) ||
        !marginJson.contains("bottom") || !PrintUtils::CheckJsonType<std::string>(marginJson["bottom"]) ||
        !marginJson.contains("left") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["left"]) ||
        !marginJson.contains("right") || !PrintUtils::CheckJsonType<uint32_t>(marginJson["right"])) {
        PRINT_HILOGE("Invalid format,key is minMargin");
        return false;
    }
    minMargin.SetTop(marginJson["top"].get<uint32_t>());
    minMargin.SetTop(marginJson["bottom"].get<uint32_t>());
    minMargin.SetLeft(marginJson["left"].get<uint32_t>());
    minMargin.SetRight(marginJson["right"].get<uint32_t>());
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
    PRINT_HILOGI("GetPrinterCapabilityFromFile printerId: %{public}s", printerId.c_str());
    nlohmann::json jsonObject;
    if (!GetJsonObjectFromFile(jsonObject, PRINTER_LIST_FILE)) {
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
    if (!GetJsonObjectFromFile(jsonObject, PRINT_USER_DATA_FILE)) {
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
        int32_t userId = std::atoi(userIdStr.c_str());
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
        discoveredPrinterInfoList_.insert(std::make_pair(printerInfo->GetPrinterId(), printerInfo));
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
}  // namespace Print
}  // namespace OHOS