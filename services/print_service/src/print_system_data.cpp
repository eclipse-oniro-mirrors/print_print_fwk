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
const std::string PRINTER_LIST_FILE = "/data/service/el1/public/print_service/printer_list.json";
const std::string PRINTER_LIST_VERSION = "v1";
}  // namespace

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
        InsertCupsPrinter(id, info, true);
    }
    return true;
}

bool PrintSystemData::Init()
{
    addedPrinterMap_.clear();
    nlohmann::json jsonObject;
    if (!GetJsonObjectFromFile(jsonObject)) {
        PRINT_HILOGW("get json from file fail");
        return false;
    }
    if (!jsonObject.contains("version") || !jsonObject["version"].is_string()) {
        PRINT_HILOGW("can not find version");
        return false;
    }
    std::string version = jsonObject["version"].get<std::string>();
    PRINT_HILOGI("json version: %{public}s", version.c_str());
    if (version == PRINTER_LIST_VERSION) {
        return ParsePrinterListJsonV1(jsonObject);
    }
    return false;
}

bool PrintSystemData::GetJsonObjectFromFile(nlohmann::json &jsonObject)
{
    std::ifstream ifs(PRINTER_LIST_FILE.c_str(), std::ios::in | std::ios::binary);
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
    return true;
}

void PrintSystemData::InsertCupsPrinter(
    const std::string &printerId, const CupsPrinterInfo &printerInfo, bool needUpdateCaps)
{
    PRINT_HILOGI("InsertCupsPrinter printerId: %{public}s", printerId.c_str());
    auto iter = addedPrinterMap_.find(printerId);
    if (iter == addedPrinterMap_.end() || iter->second == nullptr) {
        PRINT_HILOGI("insert new printer");
        addedPrinterMap_[printerId] = std::make_shared<CupsPrinterInfo>(printerInfo);
    } else {
        PRINT_HILOGI("update exist printer");
        iter->second->name = printerInfo.name;
        iter->second->uri = printerInfo.uri;
        iter->second->maker = printerInfo.maker;
        if (needUpdateCaps) {
            iter->second->printerCapability = printerInfo.printerCapability;
        }
    }
}

void PrintSystemData::DeleteCupsPrinter(const std::string &printerId)
{
    PRINT_HILOGI("DeleteCupsPrinter printerId: %{public}s", printerId.c_str());
    addedPrinterMap_.erase(printerId);
    SaveCupsPrinterMap();
}

bool PrintSystemData::SaveCupsPrinterMap()
{
    int32_t fd = open(PRINTER_LIST_FILE.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0740);
    PRINT_HILOGD("SaveCupsPrinterMap fd: %{public}d", fd);
    if (fd < 0) {
        PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        close(fd);
        return false;
    }
    nlohmann::json printerMapJson = nlohmann::json::array();
    for (auto iter = addedPrinterMap_.begin(); iter != addedPrinterMap_.end(); ++iter) {
        auto info = iter->second;
        if (info == nullptr) {
            continue;
        }
        nlohmann::json printerJson = nlohmann::json::object();
        printerJson["id"] = iter->first;
        printerJson["name"] = info->name;
        printerJson["uri"] = info->uri;
        printerJson["maker"] = info->maker;
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
    for (auto iter = addedPrinterMap_.begin(); iter != addedPrinterMap_.end(); ++iter) {
        auto info = iter->second;
        if (info == nullptr) {
            continue;
        }
        std::string name = PrintUtil::StandardizePrinterName(info->name);
        if (name == printerName) {
            return iter->first;
        }
    }
    return "";
}

bool PrintSystemData::QueryCupsPrinterInfoByPrinterId(const std::string &printerId, CupsPrinterInfo &cupsPrinter)
{
    for (auto iter = addedPrinterMap_.begin(); iter != addedPrinterMap_.end(); ++iter) {
        auto info = iter->second;
        if (info == nullptr) {
            continue;
        }
        if (printerId == iter->first) {
            cupsPrinter.name = info->name;
            cupsPrinter.uri = info->uri;
            cupsPrinter.maker = info->maker;
            cupsPrinter.printerCapability = info->printerCapability;
            cupsPrinter.printerStatus = info->printerStatus;
            return true;
        }
    }
    return false;
}

void PrintSystemData::QueryPrinterInfoById(const std::string &printerId, PrinterInfo &printerInfo)
{
    CupsPrinterInfo cupsPrinter;
    if (QueryCupsPrinterInfoByPrinterId(printerId, cupsPrinter)) {
        printerInfo.SetPrinterId(printerId);
        printerInfo.SetPrinterName(cupsPrinter.name);
        printerInfo.SetCapability(cupsPrinter.printerCapability);
        nlohmann::json option;
        option["printerName"] = cupsPrinter.name;
        option["printerUri"] = cupsPrinter.uri;
        option["make"] = cupsPrinter.maker;
        printerInfo.SetOption(option.dump());
        printerInfo.Dump();
    } else {
        PRINT_HILOGE("query printer info failed.");
    }
}

void PrintSystemData::UpdatePrinterStatus(const std::string &printerId, PrinterStatus printerStatus)
{
    for (auto iter = addedPrinterMap_.begin(); iter != addedPrinterMap_.end(); ++iter) {
        auto info = iter->second;
        if (info == nullptr) {
            continue;
        }
        if (printerId == iter->first) {
            info->printerStatus = printerStatus;
            PRINT_HILOGI("UpdatePrinterStatus success, status: %{public}d", info->printerStatus);
            return;
        }
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
    for (auto iter = addedPrinterInfoList_.begin(); iter != addedPrinterInfoList_.end(); ++iter) {
        if (printerId == iter->first) {
            return iter->second;
        }
    }
    return nullptr;
}

void PrintSystemData::GetAddedPrinterListFromSystemData(std::vector<std::string> &printerNameList)
{
    for (auto iter = addedPrinterMap_.begin(); iter != addedPrinterMap_.end(); ++iter) {
        auto info = iter->second;
        if (info == nullptr) {
            continue;
        }
        PRINT_HILOGI("GetAddedPrinterListFromSystemData info->name: %{public}s", info->name.c_str());
        printerNameList.emplace_back(info->name);
    }
}

bool PrintSystemData::IsPrinterAdded(const std::string &printerId)
{
    auto iter = addedPrinterMap_.find(printerId);
    if (iter == addedPrinterMap_.end() || iter->second == nullptr) {
        return false;
    }
    return true;
}

void PrintSystemData::ConvertPrinterCapabilityToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    capsJson["colorMode"] = printerCapability.GetColorMode();
    capsJson["duplexMode"] = printerCapability.GetDuplexMode();
    if (printerCapability.HasMargin()) {
        ConvertPrintMarginToJson(printerCapability, capsJson);
    }
    ConvertPageSizeToJson(printerCapability, capsJson);
    if (printerCapability.HasResolution()) {
        ConvertPrintResolutionToJson(printerCapability, capsJson);
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

void PrintSystemData::ConvertPageSizeToJson(PrinterCapability &printerCapability, nlohmann::json &capsJson)
{
    nlohmann::json pageSizeListJson = nlohmann::json::array();
    std::vector<PrintPageSize> pageSizeList;
    printerCapability.GetPageSize(pageSizeList);
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
    printerCapability.SetColorMode(capsJson["colorMode"].get<uint32_t>());

    if (!capsJson.contains("duplexMode") || !capsJson["duplexMode"].is_number()) {
        PRINT_HILOGW("can not find duplexMode");
        return false;
    }
    printerCapability.SetDuplexMode(capsJson["duplexMode"].get<uint32_t>());

    if (capsJson.contains("minMargin") && capsJson["minMargin"].is_object()) {
        PRINT_HILOGD("find minMargin");
        ConvertJsonToPrintMargin(capsJson, printerCapability);
    }

    if (!capsJson.contains("pageSize") || !capsJson["pageSize"].is_array()) {
        PRINT_HILOGW("can not find pageSize");
        return false;
    }
    if (!ConvertJsonToPageSize(capsJson, printerCapability)) {
        PRINT_HILOGW("convert json to pageSize failed");
        return false;
    }

    if (capsJson.contains("resolution") && capsJson["resolution"].is_array()) {
        PRINT_HILOGD("find resolution");
        if (!ConvertJsonToPrintResolution(capsJson, printerCapability)) {
            PRINT_HILOGW("convert json to print resolution failed");
            return false;
        }
    }

    if (capsJson.contains("options") && capsJson["options"].is_object()) {
        PRINT_HILOGD("find options");
        printerCapability.SetOption(capsJson["options"].dump());
    }

    return true;
}

bool PrintSystemData::ConvertJsonToPrintResolution(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    nlohmann::json resolutionListJson = capsJson["resolution"];
    std::vector<PrintResolution> resolutionList;
    for (auto &item : resolutionListJson.items()) {
        if (!item.value().is_object()) {
            PRINT_HILOGW("resolutionList item is not object");
            return false;
        }
        nlohmann::json resolutionJson = item.value();
        PrintResolution printResolution;
        if (!resolutionJson.contains("id") || !resolutionJson["id"].is_string()) {
            PRINT_HILOGW("can not find id");
            return false;
        }
        printResolution.SetId(resolutionJson["id"]);
        if (!resolutionJson.contains("horizontalDpi") || !resolutionJson["horizontalDpi"].is_number()) {
            PRINT_HILOGW("can not find horizontalDpi");
            return false;
        }
        printResolution.SetHorizontalDpi(resolutionJson["horizontalDpi"].get<uint32_t>());
        if (!resolutionJson.contains("verticalDpi") || !resolutionJson["verticalDpi"].is_number()) {
            PRINT_HILOGW("can not find verticalDpi");
            return false;
        }
        printResolution.SetVerticalDpi(resolutionJson["verticalDpi"].get<uint32_t>());
        resolutionList.emplace_back(printResolution);
    }
    if (resolutionList.size()) {
        printerCapability.SetResolution(resolutionList);
    }

    return true;
}

bool PrintSystemData::ConvertJsonToPageSize(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    nlohmann::json pageSizeListJson = capsJson["pageSize"];
    std::vector<PrintPageSize> pageSizeList;
    for (auto &item : pageSizeListJson.items()) {
        if (!item.value().is_object()) {
            PRINT_HILOGW("pageSizeListJson item is not object");
            return false;
        }
        nlohmann::json pageSizeJson = item.value();
        PrintPageSize pageSize;
        if (!pageSizeJson.contains("id") || !pageSizeJson["id"].is_string()) {
            PRINT_HILOGW("can not find id");
            return false;
        }
        pageSize.SetId(pageSizeJson["id"]);
        if (!pageSizeJson.contains("name") || !pageSizeJson["name"].is_string()) {
            PRINT_HILOGW("can not find name");
            return false;
        }
        pageSize.SetName(pageSizeJson["name"]);
        if (!pageSizeJson.contains("width") || !pageSizeJson["width"].is_number()) {
            PRINT_HILOGW("can not find width");
            return false;
        }
        pageSize.SetWidth(pageSizeJson["width"].get<uint32_t>());
        if (!pageSizeJson.contains("height") || !pageSizeJson["height"].is_number()) {
            PRINT_HILOGW("can not find height");
            return false;
        }
        pageSize.SetHeight(pageSizeJson["height"].get<uint32_t>());
        pageSizeList.emplace_back(pageSize);
    }
    if (pageSizeList.size()) {
        printerCapability.SetPageSize(pageSizeList);
    }

    return true;
}

void PrintSystemData::ConvertJsonToPrintMargin(nlohmann::json &capsJson, PrinterCapability &printerCapability)
{
    nlohmann::json marginJson = capsJson["minMargin"];
    PrintMargin minMargin;
    uint32_t marginCount = 0;

    if (marginJson.contains("top") && marginJson["top"].is_number()) {
        minMargin.SetTop(marginJson["top"].get<uint32_t>());
        marginCount++;
    }
    if (marginJson.contains("bottom") && marginJson["bottom"].is_number()) {
        minMargin.SetTop(marginJson["bottom"].get<uint32_t>());
        marginCount++;
    }
    if (marginJson.contains("left") && marginJson["left"].is_number()) {
        minMargin.SetLeft(marginJson["left"].get<uint32_t>());
        marginCount++;
    }
    if (marginJson.contains("right") && marginJson["right"].is_number()) {
        minMargin.SetRight(marginJson["right"].get<uint32_t>());
        marginCount++;
    }
    if (marginCount) {
        printerCapability.SetMinMargin(minMargin);
    }
}

bool PrintSystemData::GetPrinterCapabilityFromSystemData(
    CupsPrinterInfo &cupsPrinter, std::string printerId, PrinterCapability &printerCapability)
{
    PrinterCapability cupsPrinterCaps = cupsPrinter.printerCapability;
    std::vector<PrintPageSize> pageSizeList;
    cupsPrinterCaps.GetPageSize(pageSizeList);
    if (pageSizeList.size() != 0 && cupsPrinterCaps.HasOption()) {
        PRINT_HILOGI("find printer capability in ststem data");
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
    if (!GetJsonObjectFromFile(jsonObject)) {
        PRINT_HILOGW("get json from file fail");
        return false;
    }
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
        if (pageSizeList.size() != 0 && caps.HasOption()) {
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
}  // namespace Print
}  // namespace OHOS