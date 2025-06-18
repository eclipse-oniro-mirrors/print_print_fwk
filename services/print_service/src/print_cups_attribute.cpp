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

#include <vector>
#include <string>

#include "print_cups_attribute.h"
#include "print_service_converter.h"
#include "print_log.h"

namespace OHOS::Print {
template <typename T>
bool ParseAttributeToValue(ipp_t *response, const std::string &keyword, T &value,
    bool (*convertAttr)(const char *src, T &dst))
{
    if (convertAttr == nullptr) {
        PRINT_HILOGW("convertAttr is null");
        return false;
    }
    ipp_attribute_t *attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_KEYWORD);
    if (attrPtr == nullptr) {
        PRINT_HILOGW("attrPtr is null");
        return false;
    }
    const char *attrString = ippGetString(attrPtr, 0, nullptr);
    if (attrString == nullptr) {
        PRINT_HILOGW("attrString is null");
        return false;
    }
    PRINT_HILOGD("attrString: %{public}s", attrString);
    if (!convertAttr(attrString, value)) {
        PRINT_HILOGW("ConvertFunction fail");
        return false;
    }
    return true;
}

template <typename T>
bool ParseAttributesToList(ipp_t *response, const std::string &keyword, std::vector<T> &list,
    bool (*convertAttr)(const char *src, T &dst))
{
    if (convertAttr == nullptr) {
        PRINT_HILOGW("convertAttr is null");
        return false;
    }
    ipp_attribute_t *attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_KEYWORD);
    if (attrPtr == nullptr) {
        PRINT_HILOGW("attrPtr is null");
        return false;
    }
    int num = ippGetCount(attrPtr);
    PRINT_HILOGD("number of values %{public}d", num);
    for (int i = 0; i < num; i++) {
        const char *attrString = ippGetString(attrPtr, i, nullptr);
        if (attrString == nullptr) {
            PRINT_HILOGW("attrString is null");
            continue;
        }
        PRINT_HILOGD("attrString: %{public}s", attrString);
        T attrValue;
        if (!convertAttr(attrString, attrValue)) {
            PRINT_HILOGW("ConvertFunction fail");
            continue;
        }
        AddToUniqueList<T>(list, attrValue);
    }
    return true;
}

bool ConvertDuplexModeCode(const char *src, DuplexModeCode &dst)
{
    if (src == nullptr) {
        return false;
    }
    if (strcasestr(src, CUPS_SIDES_ONE_SIDED)) {
        dst = DUPLEX_MODE_ONE_SIDED;
    } else if (strcasestr(src, CUPS_SIDES_TWO_SIDED_PORTRAIT)) {
        dst = DUPLEX_MODE_TWO_SIDED_LONG_EDGE;
    } else if (strcasestr(src, CUPS_SIDES_TWO_SIDED_LANDSCAPE)) {
        dst = DUPLEX_MODE_TWO_SIDED_SHORT_EDGE;
    } else {
        return false;
    }
    return true;
}

std::string ConvertIppAttributesToJsonString(ipp_t *response, const std::string &keyword)
{
    ipp_attribute_t *attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_KEYWORD);
    if (attrPtr == nullptr) {
        return "";
    }
    Json::Value jsonArray;
    for (int i = 0; i < ippGetCount(attrPtr); i++) {
        const char *attrString = ippGetString(attrPtr, i, nullptr);
        if (attrString == nullptr) {
            continue;
        }
        jsonArray.append(attrString);
    }
    return PrintJsonUtil::WriteString(jsonArray);
}

void SetCapabilityGroupAttribute(ipp_t *response, PrinterCapability &printerCaps)
{
    ipp_attribute_t *attrPtr;
    if ((attrPtr = ippFindAttribute(response, "printer-state", IPP_TAG_ENUM)) != nullptr) {
        printerCaps.SetPrinterAttrNameAndValue("printer-state",
            ippEnumString("printer-state", ippGetInteger(attrPtr, 0)));
    }
    if ((attrPtr = ippFindAttribute(response, "printer-info", IPP_TAG_TEXTLANG)) != nullptr) {
        printerCaps.SetPrinterAttrNameAndValue("printer-info", ippGetString(attrPtr, 0, nullptr));
    }
    if ((attrPtr = ippFindAttribute(response, "printer-location", IPP_TAG_TEXT)) != nullptr) {
        printerCaps.SetPrinterAttrNameAndValue("printer-location", ippGetString(attrPtr, 0, nullptr));
    }
}

void ParseDuplexModeAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    std::string keyword = "sides-supported";
    std::vector<DuplexModeCode> list;
    ParseAttributesToList(response, keyword, list, ConvertDuplexModeCode);
    std::string duplexModeJson = ConvertListToJson<DuplexModeCode>(list, ConvertDuplexModeToJson);
    printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), duplexModeJson.c_str());
    size_t num = list.size();
    if (static_cast<int>(num) <= 1) {
        printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_ONE_SIDED);
    } else {
        printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_TWO_SIDED_LONG_EDGE);
    }
    printerCaps.SetSupportedDuplexMode(std::vector<uint32_t>(list.begin(), list.end()));

    keyword = "sides-default";
    DuplexModeCode code;
    if (ParseAttributeToValue<DuplexModeCode>(response, keyword, code, ConvertDuplexModeCode)) {
        uint32_t value = static_cast<uint32_t>(code);
        printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), std::to_string(value).c_str());
    }
}

void ParseColorModeAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    std::string keyword = "print-color-mode-supported";
    std::vector<ColorModeCode> supportedColorModes;
    ParseAttributesToList<ColorModeCode>(response, keyword, supportedColorModes, ConvertColorModeCode);
    std::string colorModeJson = ConvertListToJson<ColorModeCode>(supportedColorModes, ConvertColorModeToJson);
    printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), colorModeJson.c_str());

    keyword = "print-color-mode-default";
    ColorModeCode code;
    if (ParseAttributeToValue<ColorModeCode>(response, keyword, code, ConvertColorModeCode)) {
        uint32_t mode = static_cast<uint32_t>(code);
        printerCaps.SetPrinterAttrNameAndValue("defaultColorMode", std::to_string(mode).c_str());
    }
    for (auto& color : supportedColorModes) {
        if (color == ColorModeCode::COLOR_MODE_COLOR) {
            printerCaps.SetColorMode(ColorModeCode::COLOR_MODE_COLOR);
            break;
        }
    }
    printerCaps.SetSupportedColorMode(std::vector<uint32_t>(supportedColorModes.begin(), supportedColorModes.end()));
}

void ParsePageSizeAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    std::string keyword = "media-supported";
    std::vector<PrintPageSize> supportedPageSizes;
    ParseAttributesToList<PrintPageSize>(response, keyword, supportedPageSizes, ConvertPrintPageSize);
    printerCaps.SetSupportedPageSize(supportedPageSizes);

    std::string defaultPageSizeId;
    keyword = "media-default";
    if (ParseAttributeToValue<std::string>(response, keyword, defaultPageSizeId, ConvertPageSizeId)) {
        printerCaps.SetPrinterAttrNameAndValue("defaultPageSizeId", defaultPageSizeId.c_str());
    }
}

void ParseQualityAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    std::string keyword = "print-quality-supported";
    ipp_attribute_t *attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_ENUM);
    if (attrPtr == nullptr) {
        PRINT_HILOGW("%{public}s missing", keyword.c_str());
        return;
    }
    Json::Value supportedQualities;
    std::vector<uint32_t> list;
    for (int i = 0; i < ippGetCount(attrPtr); i++) {
        Json::Value jsonObject;
        int quality = ippGetInteger(attrPtr, i);
        if (quality < 0) {
            PRINT_HILOGE("%{public}s meet error quality", keyword.c_str());
            continue;
        }
        uint32_t value = static_cast<uint32_t>(quality);
        jsonObject["quality"] = value;
        supportedQualities.append(jsonObject);
        list.emplace_back(value);
    }
    std::string attrString = PrintJsonUtil::WriteString(supportedQualities);
    PRINT_HILOGD("%{public}s: %{public}s", keyword.c_str(), attrString.c_str());
    printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), attrString.c_str());
    printerCaps.SetSupportedQuality(list);
}

void ParseCopiesAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    ipp_attribute_t *attrPtr = ippFindAttribute(response, "copies-supported", IPP_TAG_RANGE);
    if (attrPtr != nullptr) {
        int upper = 0;
        for (int i = 0; i < ippGetCount(attrPtr); i++) {
            ippGetRange(attrPtr, i, &upper);
        }
        printerCaps.SetPrinterAttrNameAndValue("copies-supported", std::to_string(upper).c_str());
    }
    attrPtr = ippFindAttribute(response, "copies-default", IPP_TAG_INTEGER);
    if (attrPtr != nullptr) {
        printerCaps.SetPrinterAttrNameAndValue("copies-default", std::to_string(ippGetInteger(attrPtr, 0)).c_str());
    }
}

void ParseSupportedResolutionAttribute(ipp_t *response, PrinterCapability &printerCaps)
{
    std::string keyword = "printer-resolution-supported";
    ipp_attribute_t *attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_RESOLUTION);
    if (attrPtr == nullptr) {
        PRINT_HILOGW("attrPtr is null");
        return;
    }
    int num = ippGetCount(attrPtr);
    PRINT_HILOGD("number of values %{public}d", num);
    Json::Value resolutionArray;
    std::vector<PrintResolution> list;
    for (int i = 0; i < num; i++) {
        ipp_res_t units = IPP_RES_PER_INCH;
        int xres = 0;
        int yres = 0;
        xres = ippGetResolution(attrPtr, i, &yres, &units);
        if (xres == 0 || yres == 0) {
            continue;
        }
        if (units == IPP_RES_PER_CM) {
            xres = DpcToDpi(xres);
            yres = DpcToDpi(yres);
        } else if (units != IPP_RES_PER_INCH) {
            PRINT_HILOGW("unknown dpi unit: %{public}d", static_cast<int>(units));
            continue;
        }
        Json::Value object;
        object["horizontalDpi"] = xres;
        object["verticalDpi"] = yres;
        PrintResolution printResolution;
        printResolution.SetHorizontalDpi(xres);
        printResolution.SetVerticalDpi(yres);
        list.emplace_back(printResolution);
        resolutionArray.append(object);
    }
    printerCaps.SetResolution(list);
    printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), (PrintJsonUtil::WriteString(resolutionArray)).c_str());
}

void ParseDefaultResolutionAttribute(ipp_t *response, PrinterCapability &printerCaps)
{
    std::string keyword = "printer-resolution-default";
    ipp_attribute_t *attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_RESOLUTION);
    if (attrPtr == nullptr) {
        PRINT_HILOGW("attrPtr is null");
        return;
    }
    int num = ippGetCount(attrPtr);
    PRINT_HILOGD("number of values %{public}d", num);
    for (int i = 0; i < num; i++) {
        ipp_res_t units = IPP_RES_PER_INCH;
        int xres = 0;
        int yres = 0;
        xres = ippGetResolution(attrPtr, i, &yres, &units);
        if (xres == 0 || yres == 0) {
            continue;
        }
        if (units == IPP_RES_PER_CM) {
            xres = DpcToDpi(xres);
            yres = DpcToDpi(yres);
        } else if (units != IPP_RES_PER_INCH) {
            PRINT_HILOGW("unknown dpi unit: %{public}d", static_cast<int>(units));
            continue;
        }
        Json::Value object;
        object["horizontalDpi"] = xres;
        object["verticalDpi"] = yres;
        printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), (PrintJsonUtil::WriteString(object)).c_str());
        break;
    }
}

void ParseMediaColDefaultAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    ipp_attribute_t *defaultMediaPtr = ippFindAttribute(response, "media-col-default", IPP_TAG_BEGIN_COLLECTION);
    if (defaultMediaPtr == nullptr) {
        PRINT_HILOGW("media-col-default missing");
        return;
    }
    ipp_t *defaultMediaCol = defaultMediaPtr->values[0].collection;
    if (defaultMediaCol == nullptr) {
        PRINT_HILOGW("defaultMediaCol is null");
        return;
    }
    std::vector<std::string> keywordList;
    keywordList.push_back("media-top-margin");
    keywordList.push_back("media-bottom-margin");
    keywordList.push_back("media-left-margin");
    keywordList.push_back("media-right-margin");
    for (auto &keyword : keywordList) {
        ipp_attribute_t *attrPtr = ippFindAttribute(defaultMediaCol, keyword.c_str(), IPP_TAG_INTEGER);
        if (attrPtr != nullptr) {
            int value = ippGetInteger(attrPtr, 0);
            PRINT_HILOGD("%{public}s found: %{public}d", keyword.c_str(), value);
            std::string defaultKeyword = keyword + "-default";
            printerCaps.SetPrinterAttrNameAndValue(defaultKeyword.c_str(), std::to_string(value).c_str());
        }
    }
    ipp_attribute_t *attrPtr = ippFindAttribute(defaultMediaCol, "duplex-supported", IPP_TAG_BOOLEAN);
    if (attrPtr != nullptr) {
        PRINT_HILOGD("duplex-supported found: %{public}d", ippGetBoolean(attrPtr, 0));
    }
    attrPtr = ippFindAttribute(defaultMediaCol, "media-source", IPP_TAG_KEYWORD);
    if (attrPtr != nullptr) {
        PRINT_HILOGD("media-source-default found: %{public}s", ippGetString(attrPtr, 0, nullptr));
        printerCaps.SetPrinterAttrNameAndValue("media-source-default", ippGetString(attrPtr, 0, nullptr));
    }
    attrPtr = ippFindAttribute(defaultMediaCol, "media-type", IPP_TAG_KEYWORD);
    if (attrPtr != nullptr) {
        PRINT_HILOGD("media-type-default found: %{public}s", ippGetString(attrPtr, 0, nullptr));
        printerCaps.SetPrinterAttrNameAndValue("media-type-default", ippGetString(attrPtr, 0, nullptr));
    }
}

void ParseMediaMarginAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    ipp_attribute_t *attrPtr;
    if ((attrPtr = ippFindAttribute(response, "media-bottom-margin-supported", IPP_TAG_INTEGER)) != nullptr) {
        printerCaps.SetPrinterAttrNameAndValue("media-bottom-margin-supported",
            std::to_string(ippGetInteger(attrPtr, 0)).c_str());
    }
    if ((attrPtr = ippFindAttribute(response, "media-top-margin-supported", IPP_TAG_INTEGER)) != nullptr) {
        printerCaps.SetPrinterAttrNameAndValue("media-top-margin-supported",
            std::to_string(ippGetInteger(attrPtr, 0)).c_str());
    }
    if ((attrPtr = ippFindAttribute(response, "media-left-margin-supported", IPP_TAG_INTEGER)) != nullptr) {
        printerCaps.SetPrinterAttrNameAndValue("media-left-margin-supported",
            std::to_string(ippGetInteger(attrPtr, 0)).c_str());
    }
    if ((attrPtr = ippFindAttribute(response, "media-right-margin-supported", IPP_TAG_INTEGER)) != nullptr) {
        printerCaps.SetPrinterAttrNameAndValue("media-right-margin-supported",
            std::to_string(ippGetInteger(attrPtr, 0)).c_str());
    }
}

void ParseOrientationAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    std::string keyword = "orientation-requested-default";
    ipp_attribute_t *attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_ENUM);
    if (attrPtr != nullptr) {
        int orientationEnum = ippGetInteger(attrPtr, 0);
        printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), std::to_string(orientationEnum).c_str());
        PRINT_HILOGD("orientation-default found: %{public}d", orientationEnum);
    }
    keyword = "orientation-requested-supported";
    attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_ENUM);
    if (attrPtr != nullptr) {
        int num = ippGetCount(attrPtr);
        if (num > 0) {
            Json::Value supportedOrientationArray;
            std::vector<uint32_t> supportedOrientations;
            supportedOrientations.reserve(num);
            for (int i = 0; i < ippGetCount(attrPtr); i++) {
                int orientationEnum = ippGetInteger(attrPtr, i);
                supportedOrientationArray.append(orientationEnum);
                supportedOrientations.emplace_back(orientationEnum);
                PRINT_HILOGD("orientation-supported found: %{public}d", orientationEnum);
            }
            printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(),
                (PrintJsonUtil::WriteString(supportedOrientationArray)).c_str());
            printerCaps.SetSupportedOrientation(supportedOrientations);
        }
    }
}

void ParseOtherAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    std::string keyword = "media-source-supported";
    std::string attrString = ConvertIppAttributesToJsonString(response, keyword);
    PRINT_HILOGD("%{public}s: %{public}s", keyword.c_str(), attrString.c_str());
    if (!attrString.empty()) {
        printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), attrString.c_str());
    }

    keyword = "multiple-document-handling-supported";
    attrString = ConvertIppAttributesToJsonString(response, keyword);
    PRINT_HILOGD("%{public}s: %{public}s", keyword.c_str(), attrString.c_str());
    if (!attrString.empty()) {
        printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), attrString.c_str());
    }
}

void SetOptionAttribute(ipp_t *response, PrinterCapability &printerCaps)
{
    ipp_attribute_t *attrPtr;
    Json::Value options;
    if ((attrPtr = ippFindAttribute(response, "printer-make-and-model", IPP_TAG_TEXT)) != nullptr) {
        options["make"] = ippGetString(attrPtr, 0, nullptr);
    }
    if ((attrPtr = ippFindAttribute(response, "printer-uuid", IPP_TAG_URI)) != nullptr) {
        options["uuid"] = ippGetString(attrPtr, 0, nullptr);
    }
    if ((attrPtr = ippFindAttribute(response, "printer-name", IPP_TAG_NAME)) != nullptr) {
        options["printerName"] = ippGetString(attrPtr, 0, nullptr);
    }
    std::string keyword = "media-type-supported";
    std::string supportTypes;
    std::vector<std::string> list;
    attrPtr = ippFindAttribute(response, keyword.c_str(), IPP_TAG_ZERO);
    if (attrPtr == nullptr) {
        supportTypes = "";
    } else {
        Json::Value jsonArray;
        for (int i = 0; i < ippGetCount(attrPtr); i++) {
            const char *attrString = ippGetString(attrPtr, i, nullptr);
            if (attrString == nullptr) {
                continue;
            }
            jsonArray.append(attrString);
            list.emplace_back(attrString);
        }
        supportTypes = PrintJsonUtil::WriteString(jsonArray);
    }
    PRINT_HILOGD("%{public}s: %{public}s", keyword.c_str(), supportTypes.c_str());
    if (!supportTypes.empty()) {
        printerCaps.SetSupportedMediaType(list);
        printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), supportTypes.c_str());
    }

    Json::Value cupsOptionsJson = printerCaps.GetPrinterAttrGroupJson();
    options["cupsOptions"] = cupsOptionsJson;

    std::string optionStr = PrintJsonUtil::WriteString(options);
    PRINT_HILOGD("SetOption: %{public}s", optionStr.c_str());
    printerCaps.SetOption(optionStr);
}

void ParsePrinterAttributesFromIPP(ipp_t *response, PrinterCapability &printerCaps)
{
    SetCapabilityGroupAttribute(response, printerCaps);
    ParseColorModeAttributes(response, printerCaps);
    ParseDuplexModeAttributes(response, printerCaps);
    ParsePageSizeAttributes(response, printerCaps);
    ParseQualityAttributes(response, printerCaps);
    ParseSupportedResolutionAttribute(response, printerCaps);
    ParseDefaultResolutionAttribute(response, printerCaps);
    ParseMediaColDefaultAttributes(response, printerCaps);
    ParseMediaMarginAttributes(response, printerCaps);
    ParseOrientationAttributes(response, printerCaps);
    ParseCopiesAttributes(response, printerCaps);
    ParseOtherAttributes(response, printerCaps);
    SetOptionAttribute(response, printerCaps);
}

bool ParsePrinterStatusAttributes(ipp_t *response, PrinterStatus &status)
{
    ipp_attribute_t *attrPtr = ippFindAttribute(response, "printer-state", IPP_TAG_ENUM);
    if (attrPtr != nullptr) {
        int enumValue = ippGetInteger(attrPtr, 0) - IPP_PSTATE_IDLE;
        if (enumValue >= PRINTER_STATUS_IDLE && enumValue <= PRINTER_STATUS_UNAVAILABLE) {
            status = static_cast<PrinterStatus>(enumValue);
            return true;
        }
    }
    return false;
}
}  // namespace OHOS::Print