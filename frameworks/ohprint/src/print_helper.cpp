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

#include <vector>
#include <nlohmann/json.hpp>

#include "print_helper.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_util.h"
#include "ability_manager_client.h"
#include "print_converter.h"
#include "print_manager_client.h"

using json = nlohmann::json;

namespace OHOS::Print {

const std::string DUPLEX_STRING = "duplex";
const std::string ORIENTATION_STRING = "orientation";
const std::string PAGESIZEID_STRING = "pagesizeId";
const std::string QUALITY_STRING = "quality";
const std::string DEFAULT_QUALITY_PREFERENCE = "4";

char *CopyString(const std::string &source)
{
    auto len = source.length();
    char *dest = new (std::nothrow) char[len + 1];
    if (dest == nullptr) {
        PRINT_HILOGW("allocate failed");
        return nullptr;
    }
    if (strcpy_s(dest, len + 1, source.c_str()) != 0) {
        PRINT_HILOGW("CopyString strcpy_s failed");
    }
    dest[len] = '\0';
    return dest;
}

void AddJsonFieldStringToJsonObject(const nlohmann::json &cupsOpt, const std::string &keyword,
    nlohmann::json &advancedCapJson)
{
    PRINT_HILOGD("AddJsonFieldStringToJsonObject %{public}s", keyword.c_str());
    if (!cupsOpt.contains(keyword)) {
        PRINT_HILOGW("missing keyword");
        return;
    }
    if (!cupsOpt[keyword].is_string()) {
        PRINT_HILOGW("not string type");
        return;
    }
    std::string optionString = cupsOpt[keyword].get<std::string>();
    PRINT_HILOGD("AddJsonFieldStringToJsonObject %{public}s", optionString.c_str());
    advancedCapJson[keyword] = optionString;
}

void ParseJsonFieldAsArrayOpt(const nlohmann::json &cupsOpt, const std::string &key,
    Print_PrinterInfo &nativePrinterInfo, void (*arrayOpteration)(const nlohmann::json &, Print_PrinterInfo &))
{
    PRINT_HILOGD("ParseJsonFieldAsArrayOpt: %{public}s", key.c_str());
    if (arrayOpteration == nullptr) {
        PRINT_HILOGW("arrayOpteration is null");
        return;
    }
    if (!cupsOpt.contains(key)) {
        PRINT_HILOGW("key missing");
        return;
    }
    if (!cupsOpt[key].is_string()) {
        PRINT_HILOGW("not string");
        return;
    }
    std::string arrayJson = cupsOpt[key].get<std::string>();
    if (!nlohmann::json::accept(arrayJson)) {
        PRINT_HILOGW("accept fail");
        return;
    }
    nlohmann::json arrayOpt = nlohmann::json::parse(arrayJson);
    if (!arrayOpt.is_array()) {
        PRINT_HILOGW("not array");
        return;
    }
    arrayOpteration(arrayOpt, nativePrinterInfo);
}

bool ParseJsonFieldAsInt(const nlohmann::json &cupsOpt, const std::string &key, int &value)
{
    if (!cupsOpt.contains(key)) {
        PRINT_HILOGW("key missing");
        return false;
    }
    if (cupsOpt[key].is_number()) {
        value = cupsOpt[key];
        return true;
    }
    if (!cupsOpt[key].is_string()) {
        PRINT_HILOGW("incorrect type");
        return false;
    }
    std::string jsonString = cupsOpt[key].get<std::string>();
    if (ConvertStringToInt(jsonString.c_str(), value)) {
        return true;
    }
    return false;
}

void ConvertJsonArrayToIntList(const nlohmann::json &jsonArray, const std::string &key, std::vector<uint32_t> &list)
{
    PRINT_HILOGD("ConvertJsonArrayToIntList %{public}s, %{public}zu", key.c_str(), jsonArray.size());
    for (auto &item : jsonArray) {
        int value = 0;
        if (!ParseJsonFieldAsInt(item, key, value)) {
            continue;
        }
        list.push_back(static_cast<uint32_t>(value));
    }
}

void ReleaseCapabilityPageSizes(Print_PrinterCapability &capability)
{
    if (capability.supportedPageSizes != nullptr) {
        for (uint32_t i = 0; i < capability.supportedPageSizesCount; i++) {
            SAFE_DELETE_ARRAY(capability.supportedPageSizes[i].id);
            SAFE_DELETE_ARRAY(capability.supportedPageSizes[i].name);
        }
        SAFE_DELETE_ARRAY(capability.supportedPageSizes);
    }
    capability.supportedPageSizesCount = 0;
}

void ReleaseCapability(Print_PrinterCapability &capability)
{
    ReleaseCapabilityPageSizes(capability);
    SAFE_DELETE_ARRAY(capability.supportedColorModes);
    capability.supportedColorModesCount = 0;
    SAFE_DELETE_ARRAY(capability.supportedDuplexModes);
    capability.supportedDuplexModesCount = 0;
    SAFE_DELETE_ARRAY(capability.supportedMediaTypes);
    SAFE_DELETE_ARRAY(capability.supportedQualities);
    capability.supportedQualitiesCount = 0;
    SAFE_DELETE_ARRAY(capability.supportedPaperSources);
    SAFE_DELETE_ARRAY(capability.supportedResolutions);
    capability.supportedResolutionsCount = 0;
    SAFE_DELETE_ARRAY(capability.supportedOrientations);
    capability.supportedOrientationsCount = 0;
    SAFE_DELETE_ARRAY(capability.advancedCapability);
}

void ReleaseDefaultValue(Print_DefaultValue &defaultValue)
{
    SAFE_DELETE_ARRAY(defaultValue.defaultPageSizeId);
    SAFE_DELETE_ARRAY(defaultValue.defaultMediaType);
    SAFE_DELETE_ARRAY(defaultValue.defaultPaperSource);
    SAFE_DELETE_ARRAY(defaultValue.otherDefaultValues);
}

void ReleasePrinterInfo(Print_PrinterInfo &printerInfo)
{
    SAFE_DELETE_ARRAY(printerInfo.printerId);
    SAFE_DELETE_ARRAY(printerInfo.printerName);
    SAFE_DELETE_ARRAY(printerInfo.description);
    SAFE_DELETE_ARRAY(printerInfo.location);
    SAFE_DELETE_ARRAY(printerInfo.makeAndModel);
    SAFE_DELETE_ARRAY(printerInfo.printerUri);
    SAFE_DELETE_ARRAY(printerInfo.detailInfo);
    ReleaseCapability(printerInfo.capability);
    ReleaseDefaultValue(printerInfo.defaultValue);
}

void PageSizeArrayConvert(const nlohmann::json &pageSizeJsonArray, Print_PrinterInfo &nativePrinterInfo)
{
    ReleaseCapabilityPageSizes(nativePrinterInfo.capability);
    PRINT_HILOGI("pageSizeJsonArray size = %{public}zu", pageSizeJsonArray.size());
    std::vector<Print_PageSize> pageSizeVector;
    for (auto &item : pageSizeJsonArray) {
        Print_PageSize pageSize = {0};
        if (!item.contains("id") || !item.contains("name") || !item.contains("width") || !item.contains("height")) {
            PRINT_HILOGW("field missing");
            continue;
        }
        if (!item["id"].is_string() || !item["name"].is_string() || !item["width"].is_number() ||
            !item["height"].is_number()) {
            PRINT_HILOGW("incorrect type");
            continue;
        }
        pageSize.id = CopyString(item["id"].get<std::string>());
        pageSize.name = CopyString(item["name"].get<std::string>());
        pageSize.width = item["width"];
        pageSize.height = item["height"];
        pageSizeVector.push_back(pageSize);
    }
    nativePrinterInfo.capability.supportedPageSizes = CopyArray<Print_PageSize>(pageSizeVector,
        nativePrinterInfo.capability.supportedPageSizesCount);
}

void ParseDefaultPageMargin(const nlohmann::json &cupsOpt, Print_Margin &defaultMargin)
{
    int leftMargin = 0;
    int topMargin = 0;
    int rightMargin = 0;
    int bottomMargin = 0;
    if (cupsOpt.contains("media-left-margin-supported") && cupsOpt["media-left-margin-supported"].is_string()) {
        std::string mediaLeftMargin = cupsOpt["media-left-margin-supported"].get<std::string>();
        ConvertStringToInt(mediaLeftMargin.c_str(), leftMargin);
    }
    if (cupsOpt.contains("media-top-margin-supported") && cupsOpt["media-top-margin-supported"].is_string()) {
        std::string mediaTopMargin = cupsOpt["media-top-margin-supported"].get<std::string>();
        ConvertStringToInt(mediaTopMargin.c_str(), topMargin);
    }
    if (cupsOpt.contains("media-right-margin-supported") && cupsOpt["media-right-margin-supported"].is_string()) {
        std::string mediaRightMargin = cupsOpt["media-right-margin-supported"].get<std::string>();
        ConvertStringToInt(mediaRightMargin.c_str(), rightMargin);
    }
    if (cupsOpt.contains("media-bottom-margin-supported") && cupsOpt["media-bottom-margin-supported"].is_string()) {
        std::string mediaBottomMargin = cupsOpt["media-bottom-margin-supported"].get<std::string>();
        ConvertStringToInt(mediaBottomMargin.c_str(), bottomMargin);
    }
    defaultMargin.leftMargin = static_cast<uint32_t>(leftMargin);
    defaultMargin.topMargin = static_cast<uint32_t>(topMargin);
    defaultMargin.rightMargin = static_cast<uint32_t>(rightMargin);
    defaultMargin.bottomMargin = static_cast<uint32_t>(bottomMargin);
}

void ParseMediaOpt(const nlohmann::json &cupsOpt, Print_PrinterInfo &nativePrinterInfo)
{
    if (cupsOpt.contains("defaultPageSizeId")) {
        std::string defaultPageSizeId = cupsOpt["defaultPageSizeId"].get<std::string>();
        PRINT_HILOGD("defaultPageSizeId %{public}s", defaultPageSizeId.c_str());
        nativePrinterInfo.defaultValue.defaultPageSizeId = CopyString(defaultPageSizeId);
    }
    if (cupsOpt.contains("media-type-supported")) {
        std::string mediaTypeSupported = cupsOpt["media-type-supported"].get<std::string>();
        PRINT_HILOGD("cupsOptionsStr media-type-supported %{public}s", mediaTypeSupported.c_str());
        nativePrinterInfo.capability.supportedMediaTypes = CopyString(mediaTypeSupported);
    }
    if (cupsOpt.contains("media-type-default")) {
        std::string mediaTypeDefault = cupsOpt["media-type-default"].get<std::string>();
        PRINT_HILOGD("cupsOptionsStr media-type-default %{public}s", mediaTypeDefault.c_str());
        nativePrinterInfo.defaultValue.defaultMediaType = CopyString(mediaTypeDefault);
    }
    if (cupsOpt.contains("media-source-default")) {
        std::string mediaSourceDefault = cupsOpt["media-source-default"].get<std::string>();
        PRINT_HILOGD("cupsOptionsStr media-source-default %{public}s", mediaSourceDefault.c_str());
        nativePrinterInfo.defaultValue.defaultPaperSource = CopyString(mediaSourceDefault);
    }
    if (cupsOpt.contains("media-source-supported")) {
        std::string mediaSourceSupported = cupsOpt["media-source-supported"].get<std::string>();
        PRINT_HILOGD("cupsOptionsStr media-source-supported %{public}s", mediaSourceSupported.c_str());
        nativePrinterInfo.capability.supportedPaperSources = CopyString(mediaSourceSupported);
    }
}

void ParseColorModeArray(const nlohmann::json &arrayObject, Print_PrinterInfo &nativePrinterInfo)
{
    std::vector<uint32_t> list;
    std::string key = "color";
    ConvertJsonArrayToIntList(arrayObject, key, list);
    nativePrinterInfo.capability.supportedColorModes = CopyArray<uint32_t, Print_ColorMode>(
        list, nativePrinterInfo.capability.supportedColorModesCount, ConvertColorMode);
}

void ParseDuplexModeArray(const nlohmann::json &arrayObject, Print_PrinterInfo &nativePrinterInfo)
{
    std::vector<uint32_t> list;
    std::string key = "duplex";
    ConvertJsonArrayToIntList(arrayObject, key, list);
    nativePrinterInfo.capability.supportedDuplexModes = CopyArray<uint32_t, Print_DuplexMode>(
        list, nativePrinterInfo.capability.supportedDuplexModesCount, ConvertDuplexMode);
}

void ParseQualityArray(const nlohmann::json &arrayObject, Print_PrinterInfo &nativePrinterInfo)
{
    std::vector<uint32_t> list;
    std::string key = "quality";
    ConvertJsonArrayToIntList(arrayObject, key, list);
    nativePrinterInfo.capability.supportedQualities =
        CopyArray<uint32_t, Print_Quality>(list, nativePrinterInfo.capability.supportedQualitiesCount, ConvertQuality);
}

bool ParseResolutionObject(const nlohmann::json &jsonObject, Print_Resolution &resolution)
{
    if (!jsonObject.contains("horizontalDpi")) {
        PRINT_HILOGW("horizontalDpi missing");
        return false;
    }
    if (!jsonObject["horizontalDpi"].is_number()) {
        PRINT_HILOGW("horizontalDpi is not string");
        return false;
    }
    int xDpi = jsonObject["horizontalDpi"];
    if (!jsonObject.contains("verticalDpi")) {
        PRINT_HILOGW("verticalDpi missing");
        return false;
    }
    if (!jsonObject["verticalDpi"].is_number()) {
        PRINT_HILOGW("verticalDpi is not string");
        return false;
    }
    int yDpi = jsonObject["verticalDpi"];
    resolution.horizontalDpi = static_cast<uint32_t>(xDpi);
    resolution.verticalDpi = static_cast<uint32_t>(yDpi);
    return true;
}

void ParseResolutionArray(const nlohmann::json &arrayObject, Print_PrinterInfo &nativePrinterInfo)
{
    std::vector<Print_Resolution> list;
    PRINT_HILOGI("ParseResolutionArray arrayObject size = %{public}zu", arrayObject.size());
    for (auto &item : arrayObject) {
        Print_Resolution resolution;
        if (!ParseResolutionObject(item, resolution)) {
            PRINT_HILOGW("ParseResolutionObject fail");
            continue;
        }
        list.push_back(resolution);
    }
    nativePrinterInfo.capability.supportedResolutions =
        CopyArray<Print_Resolution>(list, nativePrinterInfo.capability.supportedResolutionsCount);
}

void ParsePrinterOpt(const nlohmann::json &cupsOpt, Print_PrinterInfo &nativePrinterInfo)
{
    if (cupsOpt.contains("printer-location") && cupsOpt["printer-location"].is_string()) {
        std::string pLocation = cupsOpt["printer-location"].get<std::string>();
        PRINT_HILOGD("printer-location: %{public}s", pLocation.c_str());
        nativePrinterInfo.location = CopyString(pLocation);
    }
    std::string keyword = "orientation-requested-supported";
    if (cupsOpt.contains(keyword) && cupsOpt[keyword].is_string()) {
        std::string orientationArray = cupsOpt[keyword].get<std::string>();
        PRINT_HILOGD("supported orientations: %{public}s", orientationArray.c_str());
        std::vector<uint32_t> orientationVector = PrintUtil::Str2Vec(orientationArray);
        nativePrinterInfo.capability.supportedOrientations = CopyArray<uint32_t, Print_OrientationMode>(
            orientationVector, nativePrinterInfo.capability.supportedOrientationsCount, ConvertOrientationMode);
    }
    keyword = "orientation-requested-default";
    if (cupsOpt.contains(keyword) && cupsOpt[keyword].is_string()) {
        std::string orientationString = cupsOpt[keyword].get<std::string>();
        PRINT_HILOGD("default orientation: %{public}s", orientationString.c_str());
        int orientationValue = 0;
        if (ConvertStringToInt(orientationString.c_str(), orientationValue)) {
            uint32_t defaultOrientation = static_cast<uint32_t>(orientationValue);
            ConvertOrientationMode(defaultOrientation, nativePrinterInfo.defaultValue.defaultOrientation);
        }
    }
    keyword = "printer-resolution-supported";
    ParseJsonFieldAsArrayOpt(cupsOpt, keyword, nativePrinterInfo, ParseResolutionArray);
    keyword = "printer-resolution-default";
    if (cupsOpt.contains(keyword) && cupsOpt[keyword].is_string()) {
        std::string resolutionString = cupsOpt[keyword].get<std::string>();
        if (json::accept(resolutionString)) {
            nlohmann::json resolutionJson = json::parse(resolutionString);
            if (!ParseResolutionObject(resolutionJson, nativePrinterInfo.defaultValue.defaultResolution)) {
                PRINT_HILOGW("ParseResolutionObject fail");
            }
        }
    }
    keyword = "print-color-mode-supported";
    ParseJsonFieldAsArrayOpt(cupsOpt, keyword, nativePrinterInfo, ParseColorModeArray);
}

void ParseCupsCopyOpt(const nlohmann::json &cupsOpt, Print_PrinterInfo &nativePrinterInfo)
{
    std::string keyword = "sides-supported";
    ParseJsonFieldAsArrayOpt(cupsOpt, keyword, nativePrinterInfo, ParseDuplexModeArray);

    keyword = "print-quality-supported";
    ParseJsonFieldAsArrayOpt(cupsOpt, keyword, nativePrinterInfo, ParseQualityArray);
    if (cupsOpt.contains("copies-default") && cupsOpt["copies-default"].is_string()) {
        std::string defaultCopies = cupsOpt["copies-default"].get<std::string>();
        nativePrinterInfo.defaultValue.defaultCopies = std::stoul(defaultCopies);
        PRINT_HILOGD("ParseCupsCopyOpt copies-default: %{public}s", defaultCopies.c_str());
    }
    if (cupsOpt.contains("copies-supported") && cupsOpt["copies-supported"].is_string()) {
        std::string copySupport = cupsOpt["copies-supported"].get<std::string>();
        nativePrinterInfo.capability.supportedCopies = std::stoul(copySupport);
        PRINT_HILOGD("ParseCupsCopyOpt copies-supported: %{public}s", copySupport.c_str());
    }
}

void ParseCupsOptions(const nlohmann::json &cupsOpt, Print_PrinterInfo &nativePrinterInfo)
{
    ParsePrinterOpt(cupsOpt, nativePrinterInfo);
    ParseDefaultPageMargin(cupsOpt, nativePrinterInfo.defaultValue.defaultMargin);
    ParseCupsCopyOpt(cupsOpt, nativePrinterInfo);
    ParseMediaOpt(cupsOpt, nativePrinterInfo);
    std::string keyword = "supportedPageSizeArray";
    ParseJsonFieldAsArrayOpt(cupsOpt, keyword, nativePrinterInfo, PageSizeArrayConvert);
    nlohmann::json advancedCapJson;
    keyword = "multiple-document-handling-supported";
    AddJsonFieldStringToJsonObject(cupsOpt, keyword, advancedCapJson);
    nativePrinterInfo.capability.advancedCapability = CopyString(advancedCapJson.dump().c_str());
}

int32_t ParseInfoOption(const std::string &infoOption, Print_PrinterInfo &nativePrinterInfo)
{
    if (!json::accept(infoOption)) {
        PRINT_HILOGW("infoOption can not parse to json object");
        return E_PRINT_INVALID_PARAMETER;
    }
    nlohmann::json infoJson = json::parse(infoOption);
    if (!infoJson.contains("printerUri") || !infoJson.contains("make")) {
        PRINT_HILOGW("The infoJson does not have a necessary attribute.");
        return E_PRINT_INVALID_PARAMETER;
    }
    nativePrinterInfo.makeAndModel = CopyString(infoJson["make"].get<std::string>());
    nativePrinterInfo.printerUri = CopyString(infoJson["printerUri"].get<std::string>());
    if (!infoJson.contains("cupsOptions")) {
        PRINT_HILOGW("The infoJson does not have a cupsOptions attribute.");
        return E_PRINT_NONE;
    }
    nlohmann::json cupsOpt = infoJson["cupsOptions"];
    ParseCupsOptions(cupsOpt, nativePrinterInfo);
    return E_PRINT_NONE;
}

std::string GetSettingItemString(const std::string key, json defaultSetting, json setting)
{
    if (setting.contains(key) && setting[key].is_string() && !setting[key].get<std::string>().empty()) {
        return setting[key].get<std::string>();
    } else if (defaultSetting.contains(key) && defaultSetting[key].is_string() &&
                !defaultSetting[key].get<std::string>().empty()) {
        return defaultSetting[key].get<std::string>();
    }
    if (key == QUALITY_STRING) {
        return DEFAULT_QUALITY_PREFERENCE;
    }
    return "";
}

void ParsePrinterPreference(const std::string &printerPreference, Print_PrinterInfo &nativePrinterInfo)
{
    if (!json::accept(printerPreference)) {
        PRINT_HILOGW("printerPreference can not parse to json object");
        return;
    }
    nlohmann::json preferenceJson = json::parse(printerPreference);
    if (!preferenceJson.contains("defaultSetting") || !preferenceJson["defaultSetting"].is_object() ||
        !preferenceJson.contains("setting") || !preferenceJson["setting"].is_object()) {
        PRINT_HILOGW("The infoJson does not have a necessary attribute.");
        return;
    }
    json defaultSetting = preferenceJson["defaultSetting"];
    json setting = preferenceJson["setting"];

    std::string defaultDuplex = GetSettingItemString(DUPLEX_STRING, defaultSetting, setting);
    if (!defaultDuplex.empty()) {
        ConvertDuplexMode(std::atoi(defaultDuplex.c_str()), nativePrinterInfo.defaultValue.defaultDuplexMode);
    }

    std::string defaultOrientation = GetSettingItemString(ORIENTATION_STRING, defaultSetting, setting);
    if (!defaultOrientation.empty()) {
        ConvertOrientationMode(
            std::atoi(defaultOrientation.c_str()), nativePrinterInfo.defaultValue.defaultOrientation);
    }

    nativePrinterInfo.defaultValue.defaultPageSizeId =
        CopyString(GetSettingItemString(PAGESIZEID_STRING, defaultSetting, setting));

    std::string defaultQuality = GetSettingItemString(QUALITY_STRING, defaultSetting, setting);
    if (!defaultQuality.empty()) {
        ConvertQuality(std::atoi(defaultQuality.c_str()), nativePrinterInfo.defaultValue.defaultPrintQuality);
    }
}

Print_PrinterInfo *ConvertToNativePrinterInfo(const PrinterInfo &info)
{
    Print_PrinterInfo *nativePrinterInfo = new (std::nothrow) Print_PrinterInfo;
    if (nativePrinterInfo == nullptr) {
        PRINT_HILOGW("Print_PrinterInfo allocate fail.");
        return nullptr;
    }
    if (memset_s(nativePrinterInfo, sizeof(Print_PrinterInfo), 0, sizeof(Print_PrinterInfo)) != 0) {
        PRINT_HILOGW("Print_PrinterInfo memset_s fail.");
        delete nativePrinterInfo;
        nativePrinterInfo = nullptr;
        return nullptr;
    }
    nativePrinterInfo->printerId = CopyString(info.GetPrinterId());
    nativePrinterInfo->printerName = CopyString(info.GetPrinterName());
    nativePrinterInfo->description = CopyString(info.GetDescription());
    nativePrinterInfo->detailInfo = nullptr;
    nativePrinterInfo->printerState = static_cast<Print_PrinterState>(info.GetPrinterStatus());
    if (info.HasIsDefaultPrinter() && info.GetIsDefaultPrinter() == true) {
        nativePrinterInfo->isDefaultPrinter = true;
    }
    OHOS::Print::PrinterCapability cap;
    info.GetCapability(cap);
    if (cap.HasOption() && json::accept(cap.GetOption())) {
        nlohmann::json capJson = json::parse(cap.GetOption());
        if (capJson.contains("cupsOptions") && capJson["cupsOptions"].is_object()) {
            nlohmann::json cupsJson = capJson["cupsOptions"];
            ParseCupsOptions(cupsJson, *nativePrinterInfo);
        }
    }
    ConvertColorMode(cap.GetColorMode(), nativePrinterInfo->defaultValue.defaultColorMode);
    ConvertDuplexMode(cap.GetDuplexMode(), nativePrinterInfo->defaultValue.defaultDuplexMode);

    std::string printerPreference = "";
    int32_t ret = PrintManagerClient::GetInstance()->GetPrinterPreference(info.GetPrinterId(), printerPreference);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGW("Print_PrinterInfo GetPrinterPreference fail.");
    } else {
        ParsePrinterPreference(printerPreference, *nativePrinterInfo);
    }
    if (info.HasOption()) {
        std::string infoOpt = info.GetOption();
        PRINT_HILOGW("infoOpt json object: %{public}s", infoOpt.c_str());
        ParseInfoOption(infoOpt, *nativePrinterInfo);
    }
    return nativePrinterInfo;
}

void SetPrintOrientationInPrintJob(const Print_PrintJob &nativePrintJob, PrintJob &printJob)
{
    uint32_t ori = static_cast<uint32_t>(nativePrintJob.orientationMode);
    if (ori == ORIENTATION_MODE_PORTRAIT || ori == ORIENTATION_MODE_REVERSE_PORTRAIT) {
        printJob.SetIsLandscape(false);
        printJob.SetIsSequential(true);
    } else if (ori == ORIENTATION_MODE_LANDSCAPE || ori == ORIENTATION_MODE_REVERSE_LANDSCAPE) {
        printJob.SetIsLandscape(true);
        printJob.SetIsSequential(false);
    }
}

void SetPrintMarginInPrintJob(const Print_PrintJob &nativePrintJob, PrintJob &printJob)
{
    PrintMargin margin;
    if (nativePrintJob.printMargin.topMargin > 0) {
        margin.SetTop(nativePrintJob.printMargin.topMargin);
    } else {
        margin.SetTop(0);
    }
    if (nativePrintJob.printMargin.rightMargin > 0) {
        margin.SetRight(nativePrintJob.printMargin.rightMargin);
    } else {
        margin.SetRight(0);
    }
    if (nativePrintJob.printMargin.bottomMargin > 0) {
        margin.SetBottom(nativePrintJob.printMargin.bottomMargin);
    } else {
        margin.SetBottom(0);
    }
    if (nativePrintJob.printMargin.leftMargin > 0) {
        margin.SetLeft(nativePrintJob.printMargin.leftMargin);
    } else {
        margin.SetLeft(0);
    }
    printJob.SetMargin(margin);
}

bool SetPrintPageSizeInPrintJob(const Print_PrintJob &nativePrintJob, PrintJob &printJob)
{
    PRINT_HILOGI("SetPrintPageSizeInPrintJob in.");
    if (nativePrintJob.pageSizeId == nullptr) {
        PRINT_HILOGW("page size is null.");
        return false;
    }
    std::string pageSizeId(nativePrintJob.pageSizeId);
    PrintPageSize pageSize;
    if (!PrintPageSize::FindPageSizeById(pageSizeId, pageSize)) {
        PRINT_HILOGW("cannot find page size: %{public}s.", pageSizeId.c_str());
        return false;
    }
    printJob.SetPageSize(pageSize);
    PRINT_HILOGI("SetPrintPageSizeInPrintJob out.");
    return true;
}

void SetOptionInPrintJob(const Print_PrintJob &nativePrintJob, PrintJob &printJob)
{
    PRINT_HILOGI("SetOptionInPrintJob in.");
    nlohmann::json jsonOptions;
    if (nativePrintJob.jobName != nullptr) {
        jsonOptions["jobName"] = std::string(nativePrintJob.jobName);
    }
    if (nativePrintJob.mediaType != nullptr) {
        jsonOptions["mediaType"] = std::string(nativePrintJob.mediaType);
    }
    jsonOptions["borderless"] = nativePrintJob.borderless ? "true" : "false";
    jsonOptions["printQuality"] = nativePrintJob.printQuality;
    jsonOptions["documentFormat"] = GetDocumentFormatString(nativePrintJob.documentFormat);
    if (nativePrintJob.advancedOptions != nullptr) {
        jsonOptions["cupsOptions"] = std::string(nativePrintJob.advancedOptions);
    }
    std::string option = jsonOptions.dump();
    PRINT_HILOGD("SetOptionInPrintJob %{public}s", option.c_str());
    printJob.SetOption(option);
    PRINT_HILOGI("SetOptionInPrintJob out.");
}

int32_t ConvertNativeJobToPrintJob(const Print_PrintJob &nativePrintJob, PrintJob &printJob)
{
    if (nativePrintJob.fdList == nullptr || nativePrintJob.copyNumber <= 0) {
        PRINT_HILOGW("ConvertNativeJobToPrintJob invalid param error.");
        return E_PRINT_INVALID_PARAMETER;
    }
    if (!IsValidString(nativePrintJob.printerId)) {
        PRINT_HILOGW("ConvertNativeJobToPrintJob string empty error.");
        return E_PRINT_INVALID_PARAMETER;
    }
    std::vector<uint32_t> fdList;
    for (uint32_t i = 0; i < nativePrintJob.fdListCount; i++) {
        fdList.emplace_back(nativePrintJob.fdList[i]);
    }
    printJob.SetFdList(fdList);
    printJob.SetPrinterId(std::string(nativePrintJob.printerId));
    printJob.SetCopyNumber(nativePrintJob.copyNumber);
    printJob.SetDuplexMode(static_cast<uint32_t>(nativePrintJob.duplexMode));
    printJob.SetColorMode(static_cast<uint32_t>(nativePrintJob.colorMode));

    SetPrintOrientationInPrintJob(nativePrintJob, printJob);
    SetPrintMarginInPrintJob(nativePrintJob, printJob);
    SetPrintPageSizeInPrintJob(nativePrintJob, printJob);
    SetOptionInPrintJob(nativePrintJob, printJob);
    return E_PRINT_NONE;
}

Print_ErrorCode ConvertStringVectorToPropertyList(const std::vector<std::string> &valueList,
    Print_PropertyList *propertyList)
{
    if (valueList.size() == 0) {
        PRINT_HILOGW("empty valueList");
        return PRINT_ERROR_INVALID_PRINTER;
    }
    propertyList->list = new (std::nothrow) Print_Property[valueList.size()];
    if (propertyList->list == nullptr) {
        PRINT_HILOGW("propertyList->list is null");
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    if (memset_s(propertyList->list, valueList.size() * sizeof(Print_Property), 0,
        valueList.size() * sizeof(Print_Property)) != 0) {
        PRINT_HILOGW("memset_s fail");
        delete[] propertyList->list;
        propertyList->list = nullptr;
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    uint32_t count = 0;
    for (size_t i = 0; i < valueList.size(); i++) {
        std::string keyVal = valueList[i];
        auto index = keyVal.find('&');
        if (index == keyVal.npos) {
            continue;
        }
        propertyList->list[count].key = CopyString(keyVal.substr(0, index));
        propertyList->list[count].value = CopyString(keyVal.substr(index + 1));
        count++;
    }
    propertyList->count = count;
    return PRINT_ERROR_NONE;
}
}  // namespace OHOS::Print
