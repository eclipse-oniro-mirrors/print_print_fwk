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

#include <securec.h>
#include "vendor_helper.h"
#include "print_service_converter.h"
#include "print_log.h"
#include <json/json.h>
#include "print_json_util.h"
#include "print_cups_client.h"

namespace {
const std::string VENDOR_MANAGER_PREFIX = "fwk.";
const std::string GLOBAL_ID_DELIMITER = ":";
const uint32_t ORIENTATION_OFFSET = 3;
const int NUMBER_BASE = 10;
const size_t MAX_STRING_COUNT = 1000;
const uint32_t MAX_MEDIA_TYPE_SIZE = 200;
}  // namespace

namespace OHOS::Print {

char *CopyString(const std::string &source)
{
    auto len = source.length();
    char *dest = new (std::nothrow) char[len + 1];
    if (dest == nullptr) {
        PRINT_HILOGE("allocate failed");
        return nullptr;
    }
    if (strcpy_s(dest, len + 1, source.c_str()) != 0) {
        PRINT_HILOGE("CopyString strcpy_s failed");
    }
    dest[len] = '\0';
    return dest;
}

template <typename T1, typename T2>
bool ConvertArrayToList(const T1 *array, uint32_t count, std::vector<T2> &list, bool (*convertType)(const T1 &, T2 &))
{
    if (convertType == nullptr) {
        PRINT_HILOGE("convertType is null");
        return false;
    }
    if (count == 0) {
        return true;
    }
    if (array == nullptr) {
        PRINT_HILOGE("array is null");
        return false;
    }
    for (uint32_t i = 0; i < count; ++i) {
        T2 data;
        if (convertType(array[i], data)) {
            if (std::find(list.begin(), list.end(), data) != list.end()) {
                PRINT_HILOGW("ignore the same item");
                continue;
            }
            list.push_back(data);
        }
    }
    return true;
}

template <typename T>
std::string ConvertArrayToJson(const T *array, uint32_t count, bool (*convertToJson)(const T &, Json::Value &))
{
    if (array == nullptr || convertToJson == nullptr) {
        PRINT_HILOGE("invalid params");
        return "";
    }
    std::vector<T> list;
    for (uint32_t i = 0; i < count; ++i) {
        AddToUniqueList<T>(list, array[i]);
    }
    return ConvertListToJson<T>(list, convertToJson);
}

bool ConvertJsonToStringList(const std::string &jsonString, std::vector<std::string> &list)
{
    Json::Value jsonObject;
    if (!PrintJsonUtil::Parse(jsonString, jsonObject)) {
        PRINT_HILOGW("invalid jsonString");
        return false;
    }
    if (!jsonObject.isArray()) {
        PRINT_HILOGW("jsonObject is not array");
        return false;
    }
    uint32_t jsonSize = jsonObject.size();
    if (jsonSize > MAX_MEDIA_TYPE_SIZE) {
        PRINT_HILOGW("jsonObject size is illegal.");
        return false;
    }
    for (uint32_t i = 0; i < jsonSize; i++) {
        if (jsonObject[i].isString()) {
            list.push_back(jsonObject[i].asString());
        }
    }
    return true;
}

std::string GetStringValueFromJson(const Json::Value &jsonObject, const std::string &key)
{
    if (!PrintJsonUtil::IsMember(jsonObject, key) || !jsonObject[key].isString()) {
        PRINT_HILOGW("can not find %{public}s", key.c_str());
        return "";
    }
    return jsonObject[key].asString();
}

bool ConvertStringToLong(const char *src, long &dst)
{
    if (src == nullptr) {
        return false;
    }
    errno = 0;
    char *endPtr = nullptr;
    dst = strtol(src, &endPtr, NUMBER_BASE);
    if (errno == ERANGE || endPtr == src) {
        PRINT_HILOGE("ConvertStringToLong fail: %{public}s", src);
        return false;
    }
    return true;
}

bool ConvertColorMode(const Print_ColorMode &code, uint32_t &dst)
{
    dst = static_cast<uint32_t>(code);
    if (dst > static_cast<uint32_t>(COLOR_MODE_AUTO)) {
        return false;
    }
    return true;
}
bool ConvertColorModeToJson(const Print_ColorMode &code, Json::Value &jsonObject)
{
    jsonObject["color"] = std::to_string(static_cast<int>(code));
    return true;
}

bool ConvertDuplexMode(const Print_DuplexMode &code, uint32_t &dst)
{
    dst = static_cast<uint32_t>(code);
    if (dst > static_cast<uint32_t>(DUPLEX_MODE_TWO_SIDED_SHORT_EDGE)) {
        return false;
    }
    return true;
}
bool ConvertDuplexModeToJson(const Print_DuplexMode &code, Json::Value &jsonObject)
{
    jsonObject["duplex"] = std::to_string(static_cast<int>(code));
    return true;
}

bool ConvertQuality(const Print_Quality &code, uint32_t &dst)
{
    dst = static_cast<uint32_t>(code);
    if (dst < static_cast<uint32_t>(PRINT_QUALITY_DRAFT) || dst > static_cast<uint32_t>(PRINT_QUALITY_HIGH)) {
        return false;
    }
    return true;
}
bool ConvertQualityToJson(const Print_Quality &code, Json::Value &jsonObject)
{
    jsonObject["quality"] = std::to_string(static_cast<int>(code));
    return true;
}

bool ConvertStringToPrinterState(const std::string &stateData, Print_PrinterState &state)
{
    long result = 0;
    Json::Value jsonObject;
    if (!PrintJsonUtil::Parse(stateData, jsonObject)) {
        PRINT_HILOGE("invalid stateData");
        return false;
    }
    // 参数处理
    std::string stateValue = GetStringValueFromJson(jsonObject, "state");
    if (!ConvertStringToLong(stateValue.c_str(), result)) {
        return false;
    }
    std::string reasonValue = GetStringValueFromJson(jsonObject, "reason");
    if (reasonValue == "shutdown") {
        PRINT_HILOGD("printer shutdown");
        state = PRINTER_UNAVAILABLE;
        return true;
    }
    if (result < 0 || result > PRINTER_UNAVAILABLE + 1) {
        PRINT_HILOGE("invalid state");
        return false;
    }
    if (result == PRINTER_UNAVAILABLE + 1) {
        state = PRINTER_UNAVAILABLE;
    } else if (result == 1) {
        state = PRINTER_BUSY;
    } else {
        state = PRINTER_IDLE;
    }
    return true;
}

void LogDiscoveryItem(const Print_DiscoveryItem *discoveryItem)
{
    if (discoveryItem == nullptr) {
        PRINT_HILOGE("discoveryItem is null");
        return;
    }
    if (discoveryItem->printerId != nullptr) {
        PRINT_HILOGD("printerId: %{public}s", discoveryItem->printerId);
    } else {
        PRINT_HILOGW("printerId is null");
    }
    if (discoveryItem->printerName != nullptr) {
        PRINT_HILOGD("printerName: %{public}s", discoveryItem->printerName);
    } else {
        PRINT_HILOGW("printerName is null");
    }
    if (discoveryItem->description != nullptr) {
        PRINT_HILOGD("description: %{public}s", discoveryItem->description);
    }
    if (discoveryItem->location != nullptr) {
        PRINT_HILOGD("location: %{public}s", discoveryItem->location);
    }
    if (discoveryItem->makeAndModel != nullptr) {
        PRINT_HILOGD("makeAndModel: %{public}s", discoveryItem->makeAndModel);
    } else {
        PRINT_HILOGW("makeAndModel is null");
    }
    if (discoveryItem->printerUri != nullptr) {
        PRINT_HILOGD("printerUri: %{public}s", discoveryItem->printerUri);
    } else {
        PRINT_HILOGW("printerUri is null");
    }
    if (discoveryItem->printerUuid != nullptr) {
        PRINT_HILOGD("printerUuid: %{public}s", discoveryItem->printerUuid);
    }
}

void LogPageCapability(const Print_PrinterCapability *capability)
{
    if (capability == nullptr) {
        PRINT_HILOGE("capability is null");
        return;
    }
    if (capability->supportedPageSizes != nullptr && capability->supportedPageSizesCount > 0) {
        for (uint32_t i = 0; i < capability->supportedPageSizesCount; ++i) {
            if (capability->supportedPageSizes[i].id != nullptr) {
                PRINT_HILOGD("page id = %{public}s", capability->supportedPageSizes[i].id);
            }
            if (capability->supportedPageSizes[i].name != nullptr) {
                PRINT_HILOGD("page name = %{public}s", capability->supportedPageSizes[i].name);
            }
            PRINT_HILOGD("page size = %{public}u x %{public}u",
                capability->supportedPageSizes[i].width,
                capability->supportedPageSizes[i].height);
        }
    }
    if (capability->supportedMediaTypes != nullptr) {
        PRINT_HILOGD("media types = %{public}s", capability->supportedMediaTypes);
    }
    if (capability->supportedPaperSources != nullptr) {
        PRINT_HILOGD("Paper Sources = %{public}s", capability->supportedPaperSources);
    }
}

void LogOtherCapability(const Print_PrinterCapability *capability)
{
    if (capability == nullptr) {
        PRINT_HILOGE("capability is null");
        return;
    }
    if (capability->supportedColorModes != nullptr && capability->supportedColorModesCount > 0) {
        for (uint32_t i = 0; i < capability->supportedColorModesCount; ++i) {
            PRINT_HILOGD("color mode = %{public}u", static_cast<uint32_t>(capability->supportedColorModes[i]));
        }
    }
    if (capability->supportedDuplexModes != nullptr && capability->supportedDuplexModesCount > 0) {
        for (uint32_t i = 0; i < capability->supportedDuplexModesCount; ++i) {
            PRINT_HILOGD("duplex mode = %{public}u", static_cast<uint32_t>(capability->supportedDuplexModes[i]));
        }
    }
    if (capability->supportedQualities != nullptr && capability->supportedQualitiesCount > 0) {
        for (uint32_t i = 0; i < capability->supportedQualitiesCount; ++i) {
            PRINT_HILOGD("quality mode = %{public}u", static_cast<uint32_t>(capability->supportedQualities[i]));
        }
    }
    PRINT_HILOGD("copy count = %{public}u", capability->supportedCopies);
    if (capability->supportedResolutions != nullptr && capability->supportedResolutionsCount > 0) {
        for (uint32_t i = 0; i < capability->supportedResolutionsCount; ++i) {
            PRINT_HILOGD("dpi = %{public}u x %{public}u",
                capability->supportedResolutions[i].horizontalDpi,
                capability->supportedResolutions[i].verticalDpi);
        }
    }
    if (capability->supportedOrientations != nullptr && capability->supportedOrientationsCount > 0) {
        for (uint32_t i = 0; i < capability->supportedOrientationsCount; ++i) {
            PRINT_HILOGD("Orientation = %{public}u", static_cast<uint32_t>(capability->supportedOrientations[i]));
        }
    }
    if (capability->advancedCapability != nullptr) {
        PRINT_HILOGD("advancedCapability = %{public}s", capability->advancedCapability);
    }
}

void LogDefaultValue(const Print_DefaultValue *defaultValue)
{
    if (defaultValue == nullptr) {
        PRINT_HILOGE("defaultValue is null");
        return;
    }
    PRINT_HILOGD("default color mode = %{public}u", static_cast<uint32_t>(defaultValue->defaultColorMode));
    PRINT_HILOGD("default duplex mode = %{public}u", static_cast<uint32_t>(defaultValue->defaultDuplexMode));
    if (defaultValue->defaultMediaType != nullptr) {
        PRINT_HILOGD("defaultMediaType = %{public}s", defaultValue->defaultMediaType);
    }
    if (defaultValue->defaultPageSizeId != nullptr) {
        PRINT_HILOGD("defaultPageSizeId = %{public}s", defaultValue->defaultPageSizeId);
    }
    PRINT_HILOGD("defaultMargin = [%{public}u, %{public}u, %{public}u, %{public}u]",
        defaultValue->defaultMargin.leftMargin,
        defaultValue->defaultMargin.topMargin,
        defaultValue->defaultMargin.rightMargin,
        defaultValue->defaultMargin.bottomMargin);
    if (defaultValue->defaultPaperSource != nullptr) {
        PRINT_HILOGD("defaultPaperSource = %{public}s", defaultValue->defaultPaperSource);
    }
    PRINT_HILOGD("defaultPrintQuality = %{public}u", static_cast<uint32_t>(defaultValue->defaultPrintQuality));
    PRINT_HILOGD("defaultCopies = %{public}u", defaultValue->defaultCopies);
    PRINT_HILOGD("defaultResolution = %{public}u x %{public}u",
        defaultValue->defaultResolution.horizontalDpi,
        defaultValue->defaultResolution.verticalDpi);
    PRINT_HILOGD("defaultOrientation = %{public}u", static_cast<uint32_t>(defaultValue->defaultOrientation));
    if (defaultValue->otherDefaultValues != nullptr) {
        PRINT_HILOGD("otherDefaultValues = %{public}s", defaultValue->otherDefaultValues);
    }
}

void LogProperties(const Print_PropertyList *propertyList)
{
    if (propertyList == nullptr) {
        PRINT_HILOGE("propertyList is null");
        return;
    }
    if (propertyList->count == 0 || propertyList->list == nullptr) {
        PRINT_HILOGE("propertyList empty");
        return;
    }
    for (uint32_t i = 0; i < propertyList->count; ++i) {
        if (propertyList->list[i].key == nullptr) {
            PRINT_HILOGW("propertyList item empty: %{public}u", i);
            continue;
        }
        PRINT_HILOGD("LogProperties key: %{public}s", propertyList->list[i].key);
        if (propertyList->list[i].value == nullptr) {
            PRINT_HILOGW("propertyList value empty: %{public}u", i);
            continue;
        }
        PRINT_HILOGD("LogProperties value: %{public}s", propertyList->list[i].value);
    }
}

std::shared_ptr<std::string> FindPropertyFromPropertyList(
    const Print_PropertyList *propertyList, const std::string &keyName)
{
    if (propertyList == nullptr) {
        PRINT_HILOGE("propertyList is null");
        return nullptr;
    }
    if (propertyList->count == 0 || propertyList->list == nullptr) {
        PRINT_HILOGE("propertyList empty");
        return nullptr;
    }
    for (uint32_t i = 0; i < propertyList->count; ++i) {
        if (propertyList->list[i].key == nullptr) {
            PRINT_HILOGW("propertyList key empty: %{public}u", i);
            continue;
        }
        PRINT_HILOGD("FindPropertyFromPropertyList key: %{public}s", propertyList->list[i].key);
        if (strcmp(keyName.c_str(), propertyList->list[i].key) != 0) {
            continue;
        }
        if (propertyList->list[i].value == nullptr) {
            PRINT_HILOGW("propertyList value empty, key: %{public}s", keyName.c_str());
            break;
        }
        PRINT_HILOGD("FindPropertyFromPropertyList value: %{public}s", propertyList->list[i].value);
        return std::make_shared<std::string>(propertyList->list[i].value);
    }
    return nullptr;
}

bool UpdatePrinterDetailInfoToJson(Json::Value &option, const std::string &detailInfo)
{
    Json::Value detailInfoJson;
    std::istringstream iss(detailInfo);
    if (!PrintJsonUtil::ParseFromStream(iss, detailInfoJson) || detailInfoJson.isNull()) {
        PRINT_HILOGW("failed to parse detailInfo to json");
        return false;
    }
    if (PrintJsonUtil::IsMember(detailInfoJson, "bsunidriver_support") &&
        detailInfoJson["bsunidriver_support"].isString()) {
        option["bsunidriverSupport"] = detailInfoJson["bsunidriver_support"].asString();
    }
    if (PrintJsonUtil::IsMember(detailInfoJson, "printer_protocols")) {
        if (detailInfoJson["printer_protocols"].isObject()) {
            Json::Value protocols = detailInfoJson["printer_protocols"];
            Json::Value protocolJson(Json::arrayValue);
            if (PrintJsonUtil::IsMember(protocols, "ipp") && protocols["ipp"].isString()) {
                option["ipp"] = protocols["ipp"].asString();
                protocolJson.append("ipp");
            }
            if (PrintJsonUtil::IsMember(protocols, "ipps") && protocols["ipps"].isString()) {
                option["ipps"] = protocols["ipps"].asString();
                protocolJson.append("ipps");
            }
            if (PrintJsonUtil::IsMember(protocols, "lpd") && protocols["lpd"].isString()) {
                option["lpd"] = protocols["lpd"].asString();
                protocolJson.append("lpd");
            }
            if (PrintJsonUtil::IsMember(protocols, "socket") && protocols["socket"].isString()) {
                option["socket"] = protocols["socket"].asString();
                protocolJson.append("socket");
            }
            option["protocol"] = protocolJson;
        }
    }
    if (PrintJsonUtil::IsMember(detailInfoJson, "modelName") &&
        detailInfoJson["modelName"].isString()) {
        option["model_Name"] = detailInfoJson["modelName"].asString();
    }
    return true;
}

std::string getScheme(std::string &printerUri)
{
    char scheme[HTTP_MAX_URI] = {0}; /* Method portion of URI */
    char username[HTTP_MAX_URI] = {0}; /* Username portion of URI */
    char host[HTTP_MAX_URI] = {0}; /* Host portion of URI */
    char resource[HTTP_MAX_URI] = {0}; /* Resource portion of URI */
    int port = 0; /* Port portion of URI */
    httpSeparateURI(HTTP_URI_CODING_ALL, printerUri.c_str(), scheme, sizeof(scheme), username, sizeof(username),
        host, sizeof(host), &port, resource, sizeof(resource));
    std::string infoScheme;
    infoScheme.assign(scheme);
    return infoScheme;
}

bool UpdatePrinterInfoWithDiscovery(PrinterInfo &info, const Print_DiscoveryItem *discoveryItem)
{
    if (discoveryItem == nullptr) {
        PRINT_HILOGE("discoveryItem is null");
        return false;
    }
    if (discoveryItem->printerId == nullptr || discoveryItem->printerName == nullptr) {
        PRINT_HILOGE("invalid discoveryItem");
        return false;
    }
    info.SetPrinterId(std::string(discoveryItem->printerId));
    std::string name(discoveryItem->printerName);
    info.SetPrinterName(name);
    if (discoveryItem->description != nullptr) {
        info.SetDescription(std::string(discoveryItem->description));
    }
    if (discoveryItem->printerUri != nullptr) {
        info.SetUri(std::string(discoveryItem->printerUri));
    }
    if (discoveryItem->makeAndModel != nullptr) {
        info.SetPrinterMake(std::string(discoveryItem->makeAndModel));
    }
    if (discoveryItem->printerUuid != nullptr) {
        info.SetPrinterUuid(std::string(discoveryItem->printerUuid));
    }
    if (discoveryItem->printerUri != nullptr && discoveryItem->makeAndModel != nullptr) {
        PRINT_HILOGD("printerUri: %{private}s", discoveryItem->printerUri);
        Json::Value option;
        option["printerName"] = name;
        std::string uri = std::string(discoveryItem->printerUri);
        option["printerUri"] = uri;
        option["recommendProtocol"] = getScheme(uri);
        option["make"] = std::string(discoveryItem->makeAndModel);
        if (discoveryItem->printerUuid != nullptr) {
            option["printer-uuid"] = std::string(discoveryItem->printerUuid);
        }
        if (discoveryItem->detailInfo != nullptr) {
            if (!UpdatePrinterDetailInfoToJson(option, std::string(discoveryItem->detailInfo))) {
                return false;
            }
        } else {
            PRINT_HILOGW("DetailInfo is null");
        }
        info.SetOption(PrintJsonUtil::WriteString(option));
    }
    return true;
}

void AddUniquePageSize(std::vector<PrintPageSize> &pageSizeList, const PrintPageSize &printPageSize)
{
    for (auto const &item : pageSizeList) {
        if (item.GetId() == printPageSize.GetId()) {
            return;
        }
    }
    pageSizeList.push_back(printPageSize);
}

bool UpdateDefaultPageSizeId(PrinterCapability &printerCap, const std::string &defaultPageId, const std::string &pageId,
    const Print_PageSize &page)
{
    if (page.id != nullptr && defaultPageId == std::string(page.id)) {
        printerCap.SetPrinterAttrNameAndValue("defaultPageSizeId", pageId.c_str());
        return true;
    }
    return false;
}

bool UpdatePageSizeCapability(
    PrinterCapability &printerCap, const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue)
{
    if (capability == nullptr || capability->supportedPageSizes == nullptr) {
        PRINT_HILOGW("supportedPageSizes is null");
        return false;
    }
    std::string defaultPageId;
    if (defaultValue != nullptr && defaultValue->defaultPageSizeId != nullptr) {
        defaultPageId = defaultValue->defaultPageSizeId;
    }
    std::vector<PrintPageSize> pageSizeList;
    for (uint32_t i = 0; i < capability->supportedPageSizesCount; ++i) {
        PrintPageSize printPageSize;
        if (capability->supportedPageSizes[i].name != nullptr) {
            std::string pageSizeName(capability->supportedPageSizes[i].name);
            PAGE_SIZE_ID id = PrintPageSize::MatchPageSize(pageSizeName);
            if (!id.empty() && PrintPageSize::FindPageSizeById(id, printPageSize)) {
                AddUniquePageSize(pageSizeList, printPageSize);
                UpdateDefaultPageSizeId(printerCap, defaultPageId, id, capability->supportedPageSizes[i]);
                PRINT_HILOGD("page size matched = %{public}s", id.c_str());
                continue;
            }
        }
        if (capability->supportedPageSizes[i].id != nullptr) {
            PAGE_SIZE_ID id = std::string(capability->supportedPageSizes[i].id);
            if (!id.empty() && PrintPageSize::FindPageSizeById(id, printPageSize)) {
                AddUniquePageSize(pageSizeList, printPageSize);
                UpdateDefaultPageSizeId(printerCap, defaultPageId, id, capability->supportedPageSizes[i]);
                PRINT_HILOGD("page size matched = %{public}s", id.c_str());
                continue;
            }
        }
        if (capability->supportedPageSizes[i].name != nullptr && capability->supportedPageSizes[i].id != nullptr) {
            if (strstr(capability->supportedPageSizes[i].id, "CUSTOM_MIN") ||
                strstr(capability->supportedPageSizes[i].id, "CUSTOM_MAX")) {
                PRINT_HILOGW("skip pageSize: %{public}s", capability->supportedPageSizes[i].name);
                continue;
            }
            printPageSize.SetWidth(capability->supportedPageSizes[i].width);
            printPageSize.SetHeight(capability->supportedPageSizes[i].height);
            if (printPageSize.ConvertToPwgStyle()) {
                AddUniquePageSize(pageSizeList, printPageSize);
                PRINT_HILOGD("custom page size matched = %{public}s", printPageSize.GetId().c_str());
                continue;
            }
        }
    }
    printerCap.SetSupportedPageSize(pageSizeList);
    return true;
}

bool UpdateQualityCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability)
{
    if (capability == nullptr || capability->supportedQualities == nullptr) {
        PRINT_HILOGW("supportedQualities is null");
        return false;
    }
    std::vector<uint32_t> supportedQualityList;
    if (ConvertArrayToList<Print_Quality, uint32_t>(
        capability->supportedQualities,
        capability->supportedQualitiesCount,
        supportedQualityList,
        ConvertQuality)) {
        printerCap.SetSupportedQuality(supportedQualityList);
    }
    std::string supportedQualities = ConvertArrayToJson<Print_Quality>(
        capability->supportedQualities, capability->supportedQualitiesCount, ConvertQualityToJson);
    PRINT_HILOGD("quality: %{public}s", supportedQualities.c_str());
    if (!supportedQualities.empty()) {
        printerCap.SetPrinterAttrNameAndValue("print-quality-supported", supportedQualities.c_str());
    }
    return true;
}

bool UpdateColorCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability)
{
    if (capability == nullptr || capability->supportedColorModes == nullptr) {
        PRINT_HILOGW("supportedColorModes is null");
        return false;
    }
    std::vector<uint32_t> supportedColorModes;
    if (ConvertArrayToList<Print_ColorMode, uint32_t>(
        capability->supportedColorModes,
        capability->supportedColorModesCount,
        supportedColorModes,
        ConvertColorMode)) {
        printerCap.SetSupportedColorMode(supportedColorModes);
    }
    std::string colorModeJson = ConvertArrayToJson<Print_ColorMode>(
        capability->supportedColorModes, capability->supportedColorModesCount, ConvertColorModeToJson);
    if (!colorModeJson.empty()) {
        printerCap.SetPrinterAttrNameAndValue("print-color-mode-supported", colorModeJson.c_str());
    }
    for (uint32_t i = 0; i < capability->supportedColorModesCount; ++i) {
        if (capability->supportedColorModes[i] == Print_ColorMode::COLOR_MODE_COLOR) {
            printerCap.SetColorMode(ColorModeCode::COLOR_MODE_COLOR);
            break;
        }
    }
    return true;
}

bool UpdateDuplexCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability)
{
    if (capability == nullptr || capability->supportedDuplexModes == nullptr) {
        PRINT_HILOGW("supportedDuplexModes is null");
        return false;
    }
    std::vector<uint32_t> supportedDuplexModes;
    if (ConvertArrayToList<Print_DuplexMode, uint32_t>(
        capability->supportedDuplexModes,
        capability->supportedDuplexModesCount,
        supportedDuplexModes,
        ConvertDuplexMode)) {
        printerCap.SetSupportedDuplexMode(supportedDuplexModes);
    }
    std::string duplexModeJson = ConvertArrayToJson<Print_DuplexMode>(
        capability->supportedDuplexModes, capability->supportedDuplexModesCount, ConvertDuplexModeToJson);
    if (!duplexModeJson.empty()) {
        printerCap.SetPrinterAttrNameAndValue("sides-supported", duplexModeJson.c_str());
    }
    if (capability->supportedDuplexModesCount > 1) {
        printerCap.SetDuplexMode(static_cast<uint32_t>(Print_DuplexMode::DUPLEX_MODE_TWO_SIDED_LONG_EDGE));
    }
    return true;
}
bool UpdateResolutionCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability)
{
    if (capability == nullptr || capability->supportedResolutions == nullptr) {
        PRINT_HILOGW("supportedResolutions is null");
        return false;
    }
    std::vector<PrintResolution> resolutionList;
    Json::Value resolutionArray;
    for (uint32_t i = 0; i < capability->supportedResolutionsCount; ++i) {
        PrintResolution printResolution;
        uint32_t xRes = capability->supportedResolutions[i].horizontalDpi;
        uint32_t yRes = capability->supportedResolutions[i].verticalDpi;
        printResolution.SetHorizontalDpi(xRes);
        printResolution.SetVerticalDpi(yRes);
        PRINT_HILOGD("resolution = %{public}u x %{public}u", xRes, yRes);
        resolutionList.push_back(printResolution);
        Json::Value object;
        object["horizontalDpi"] = xRes;
        object["verticalDpi"] = yRes;
        resolutionArray.append(object);
    }
    printerCap.SetResolution(resolutionList);
    printerCap.SetPrinterAttrNameAndValue(
        "printer-resolution-supported", (PrintJsonUtil::WriteString(resolutionArray)).c_str());
    return true;
}

bool UpdateResolutionDefaultValue(PrinterCapability &printerCap, const Print_DefaultValue *defaultValue)
{
    if (defaultValue == nullptr) {
        PRINT_HILOGW("defaultValue is null");
        return false;
    }
    Json::Value object;
    object["horizontalDpi"] = defaultValue->defaultResolution.horizontalDpi;
    object["verticalDpi"] = defaultValue->defaultResolution.verticalDpi;
    printerCap.SetPrinterAttrNameAndValue("printer-resolution-default", (PrintJsonUtil::WriteString(object)).c_str());
    return true;
}

bool UpdateCopiesCapability(
    PrinterCapability &printerCap, const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue)
{
    if (capability == nullptr || defaultValue == nullptr) {
        PRINT_HILOGW("capability or defaultValue is null");
        return false;
    }
    printerCap.SetPrinterAttrNameAndValue("copies-supported", std::to_string(capability->supportedCopies).c_str());
    printerCap.SetPrinterAttrNameAndValue("copies-default", std::to_string(defaultValue->defaultCopies).c_str());
    return true;
}

bool UpdateOrientationCapability(
    PrinterCapability &printerCap, const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue)
{
    if (capability == nullptr || defaultValue == nullptr) {
        PRINT_HILOGW("capability or defaultValue is null");
        return false;
    }
    printerCap.SetPrinterAttrNameAndValue(
        "orientation-requested-default", std::to_string(defaultValue->defaultOrientation).c_str());
    if (capability->supportedOrientations != nullptr) {
        Json::Value supportedOrientationArray;
        std::vector<uint32_t> supportedOrientations;
        for (uint32_t i = 0; i < capability->supportedOrientationsCount; ++i) {
            int orientationEnum = static_cast<int>(capability->supportedOrientations[i]) + ORIENTATION_OFFSET;
            supportedOrientationArray.append(orientationEnum);
            supportedOrientations.push_back(static_cast<uint32_t>(orientationEnum));
        }
        printerCap.SetSupportedOrientation(supportedOrientations);
        printerCap.SetPrinterAttrNameAndValue(
            "orientation-requested-supported", (PrintJsonUtil::WriteString(supportedOrientationArray)).c_str());
    }
    return true;
}

bool UpdateMediaCapability(
    PrinterCapability &printerCap, const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue)
{
    if (capability == nullptr || defaultValue == nullptr) {
        PRINT_HILOGW("capability or defaultValue is null");
        return false;
    }
    if (capability->supportedMediaTypes != nullptr) {
        printerCap.SetPrinterAttrNameAndValue("media-type-supported", capability->supportedMediaTypes);
        std::string mediaTypeJson(capability->supportedMediaTypes);
        std::vector<std::string> mediaTypeList;
        if (ConvertJsonToStringList(mediaTypeJson, mediaTypeList)) {
            printerCap.SetSupportedMediaType(mediaTypeList);
        } else {
            PRINT_HILOGW("invalid media types");
        }
    }
    if (defaultValue->defaultMediaType != nullptr) {
        printerCap.SetPrinterAttrNameAndValue("media-type-default", defaultValue->defaultMediaType);
    }
    if (capability->supportedPaperSources != nullptr) {
        printerCap.SetPrinterAttrNameAndValue("media-source-supported", capability->supportedPaperSources);
    }
    if (defaultValue->defaultPaperSource != nullptr) {
        printerCap.SetPrinterAttrNameAndValue("media-source-default", defaultValue->defaultPaperSource);
    }
    return true;
}
bool UpdateMarginCapability(PrinterCapability &printerCap, const Print_DefaultValue *defaultValue)
{
    if (defaultValue == nullptr) {
        PRINT_HILOGW("defaultValue is null");
        return false;
    }
    PrintMargin printMargin;
    printMargin.SetLeft(defaultValue->defaultMargin.leftMargin);
    printMargin.SetTop(defaultValue->defaultMargin.topMargin);
    printMargin.SetRight(defaultValue->defaultMargin.rightMargin);
    printMargin.SetBottom(defaultValue->defaultMargin.bottomMargin);
    PRINT_HILOGD("margin left = %{public}u, top =  %{public}u, right = %{public}u, bottom =  %{public}u",
        defaultValue->defaultMargin.leftMargin,
        defaultValue->defaultMargin.topMargin,
        defaultValue->defaultMargin.rightMargin,
        defaultValue->defaultMargin.bottomMargin);
    printerCap.SetMinMargin(printMargin);
    return true;
}
bool UpdatePrinterCapability(
    PrinterCapability &printerCap, const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue)
{
    if (capability == nullptr || defaultValue == nullptr) {
        PRINT_HILOGW("capability or defaultValue is null");
        return false;
    }
    if (!UpdatePageSizeCapability(printerCap, capability, defaultValue)) {
        return false;
    }
    UpdateColorCapability(printerCap, capability);
    uint32_t defaultColorMode = static_cast<uint32_t>(defaultValue->defaultColorMode);
    printerCap.SetPrinterAttrNameAndValue("defaultColorMode", std::to_string(defaultColorMode).c_str());
    UpdateDuplexCapability(printerCap, capability);
    uint32_t defaultDuplexMode = static_cast<uint32_t>(defaultValue->defaultDuplexMode);
    printerCap.SetPrinterAttrNameAndValue("sides-default", std::to_string(defaultDuplexMode).c_str());
    UpdateQualityCapability(printerCap, capability);
    UpdateResolutionCapability(printerCap, capability);
    UpdateResolutionDefaultValue(printerCap, defaultValue);
    UpdateCopiesCapability(printerCap, capability, defaultValue);
    UpdateOrientationCapability(printerCap, capability, defaultValue);
    UpdateMediaCapability(printerCap, capability, defaultValue);
    UpdateMarginCapability(printerCap, defaultValue);
    return true;
}

bool UpdatePrinterInfoWithCapability(PrinterInfo &info, const Print_DiscoveryItem *discoveryItem,
    const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue)
{
    PrinterCapability printerCap;
    if (!UpdatePrinterCapability(printerCap, capability, defaultValue)) {
        PRINT_HILOGW("update capability fail");
        return false;
    }
    Json::Value options;
    if (discoveryItem != nullptr) {
        if (discoveryItem->makeAndModel != nullptr) {
            options["make"] = std::string(discoveryItem->makeAndModel);
        }
        if (discoveryItem->printerName != nullptr) {
            options["printerName"] = info.GetPrinterName();
        }
        if (discoveryItem->printerUuid != nullptr) {
            options["printer-uuid"] = std::string(discoveryItem->printerUuid);
        }
    }
    Json::Value cupsOptionsJson = printerCap.GetPrinterAttrGroupJson();
    options["cupsOptions"] = cupsOptionsJson;
    std::string optionStr = PrintJsonUtil::WriteString(options);
    PRINT_HILOGD("SetOption: %{public}s", optionStr.c_str());
    printerCap.SetOption(optionStr);
    info.SetCapability(printerCap);
    info.Dump();
    return true;
}

std::shared_ptr<PrinterInfo> ConvertVendorCapabilityToPrinterInfo(const Print_DiscoveryItem *printer,
    const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue)
{
    if (printer == nullptr || printer->printerId == nullptr) {
        PRINT_HILOGW("printer null");
        return nullptr;
    }
    std::shared_ptr<PrinterInfo> info = std::make_shared<PrinterInfo>();
    if (info == nullptr) {
        return nullptr;
    }
    if (!UpdatePrinterInfoWithDiscovery(*info, printer)) {
        PRINT_HILOGW("update printer info fail");
        return nullptr;
    }
    if (!UpdatePrinterInfoWithCapability(*info, printer, capability, defaultValue)) {
        PRINT_HILOGW("update printer capability fail");
        return nullptr;
    }
    return info;
}

bool ConvertStringVectorToStringList(const std::vector<std::string> &stringVector, Print_StringList &stringList)
{
    size_t count = stringVector.size();
    if (count == 0 || count > MAX_STRING_COUNT) {
        return false;
    }
    stringList.count = 0;
    stringList.list = new (std::nothrow) char *[count];
    if (stringList.list == nullptr) {
        PRINT_HILOGW("stringList list allocate fail");
        return false;
    }
    if (memset_s(stringList.list, count * sizeof(char *), 0, count * sizeof(char *)) != 0) {
        PRINT_HILOGW("memset_s fail");
        delete[] stringList.list;
        stringList.list = nullptr;
        return false;
    }
    for (auto const &key : stringVector) {
        stringList.list[stringList.count] = CopyString(key);
        stringList.count++;
    }
    return true;
}

void ReleaseStringList(Print_StringList &stringList)
{
    if (stringList.list != nullptr) {
        for (uint32_t i = 0; i < stringList.count; i++) {
            if (stringList.list[i] != nullptr) {
                delete[] stringList.list[i];
                stringList.list[i] = nullptr;
            }
        }
        delete[] stringList.list;
        stringList.list = nullptr;
    }
    stringList.count = 0;
}
}  // namespace OHOS::Print
