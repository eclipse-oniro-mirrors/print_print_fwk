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

#include "print_service_converter.h"
#include "print_log.h"
#include "print_constant.h"
#include <sstream>
#include <cstdlib>  // for std::strtod
#include <cerrno>   // for errno
#include <cmath>   // for std::isfinite
#include <cstdint> // for UINT32_MAX

namespace OHOS {
namespace Print {
std::string GetQulityString(int code)
{
    return std::to_string(code);
}

bool ConvertColorModeCode(const char *src, ColorModeCode &dst)
{
    if (src == nullptr) {
        return false;
    }
    if (strcasestr(src, "color")) {
        dst = COLOR_MODE_COLOR;
    } else if (strcasestr(src, "monochrome")) {
        dst = COLOR_MODE_MONOCHROME;
    } else if (strcasestr(src, "auto")) {
        dst = COLOR_MODE_AUTO;
    } else {
        return false;
    }
    return true;
}

bool ConvertColorModeToJson(const ColorModeCode &code, Json::Value &jsonObject)
{
    jsonObject["color"] = std::to_string(static_cast<int>(code));
    return true;
}

bool ConvertDuplexModeToJson(const DuplexModeCode &code, Json::Value &jsonObject)
{
    jsonObject["duplex"] = std::to_string(static_cast<int>(code));
    return true;
}

bool ConvertPageSizeId(const char *src, std::string &id)
{
    if (src == nullptr) {
        return false;
    }
    std::string pageString(src);
    id = PrintPageSize::MatchPageSize(pageString);
    return !id.empty();
}

bool ConvertStrToDouble(const std::string& str, double& value)
{
    char* endPtr = nullptr;
    const char* cstr = str.c_str();
    
    errno = 0;
    value = std::strtod(cstr, &endPtr);
    
    if (cstr == endPtr) {
        return false;
    }
    if (errno == ERANGE) {
        errno = 0;
        return false;
    }
    if (!std::isfinite(value)) {
        return false;
    }
    if (*endPtr != '\0') {
        return false;
    }
    return true;
}

bool ConvertCustomPageSizeFromWidthAndLength(const double widthValue, const double lengthValue,
    const std::string& unit, PrintPageSize &dst)
{
    if (widthValue < 0 || lengthValue < 0 ||
        !std::isfinite(widthValue) || !std::isfinite(lengthValue)) {
        PRINT_HILOGE("invalid width or length value");
        return false;
    }
    uint32_t width = 0;
    uint32_t length = 0;

    std::stringstream postfixName;
    if (unit == "mm") {
        double widthRounded = round(widthValue * HUNDRED_OF_MILLIMETRE_TO_INCH);
        double lengthRounded = round(lengthValue * HUNDRED_OF_MILLIMETRE_TO_INCH);
        if (widthRounded > UINT32_MAX || lengthRounded > UINT32_MAX) {
            PRINT_HILOGE("width or length value overflow");
            return false;
        }
        width = static_cast<uint32_t>(widthRounded);
        length = static_cast<uint32_t>(lengthRounded);
        postfixName << round(widthValue) << "x" << round(lengthValue) << "mm";
    } else if (unit == "in") {
        double widthRounded = round(widthValue * ONE_THOUSAND_INCH);
        double lengthRounded = round(lengthValue * ONE_THOUSAND_INCH);
        if (widthRounded > UINT32_MAX || lengthRounded > UINT32_MAX) {
            PRINT_HILOGE("width or length value overflow");
            return false;
        }
        width = static_cast<uint32_t>(widthRounded);
        length = static_cast<uint32_t>(lengthRounded);
        postfixName << round(widthValue * ONE_THOUSAND_INCH / HUNDRED_OF_MILLIMETRE_TO_INCH) << "x" <<
            round(lengthValue * ONE_THOUSAND_INCH / HUNDRED_OF_MILLIMETRE_TO_INCH) << "mm";
    } else {
        PRINT_HILOGE("IPP media-supported do not found unitstr");
        return false;
    }
    std::string pwgName = CUSTOM_PREFIX + postfixName.str();
    dst = PrintPageSize(pwgName, pwgName, width, length);
    return true;
}

bool ConvertCustomPageSizeFromPwgName(const char *src, PrintPageSize &dst)
{
    if (src == nullptr) {
        PRINT_HILOGE("IPP media-supported src is empty");
        return false;
    }
    std::string pwgNameStr(src);
    size_t lastPartPos = pwgNameStr.find_last_of('_');
    size_t firstPartPos = pwgNameStr.find_first_of('_');
    if (lastPartPos == std::string::npos || firstPartPos == std::string::npos ||
        lastPartPos + 1 >= pwgNameStr.size() || lastPartPos - firstPartPos < 1) {
        PRINT_HILOGE("IPP media-supported do not found \"_\"");
        return false;
    }
    std::string middleNmae = pwgNameStr.substr(firstPartPos + 1, lastPartPos - firstPartPos - 1);
    if (middleNmae == "max" || middleNmae == "min") {
        PRINT_HILOGE("IPP media-supported contains max or min");
        return false;
    }
    std::string sizeName = pwgNameStr.substr(lastPartPos + 1);
    size_t xPos = sizeName.find('x');
    if (xPos == std::string::npos || xPos + 1 >= sizeName.size() ||
        sizeName.size() < xPos + PAGE_SIZE_UNIT_LENGTH + 1 || sizeName.size() < PAGE_SIZE_UNIT_LENGTH) {
        PRINT_HILOGE("IPP media-supported do not found \"x\"");
        return false;
    }
    std::string widthStr = sizeName.substr(0, xPos);
    std::string lengthStr = sizeName.substr(xPos + 1, sizeName.size() - xPos - PAGE_SIZE_UNIT_LENGTH - 1);
    std::string unit = sizeName.substr(sizeName.size() - PAGE_SIZE_UNIT_LENGTH);
    double widthValue = 0;
    double lengthValue = 0;

    if (!ConvertStrToDouble(widthStr, widthValue) || !ConvertStrToDouble(lengthStr, lengthValue)) {
        PRINT_HILOGE("Bad SafeStof Convert!");
        return false;
    }

    return ConvertCustomPageSizeFromWidthAndLength(widthValue, lengthValue, unit, dst);
}

bool ConvertPwgSizeField(const std::string &sizeName, PrintPageSize &dst)
{
    size_t xPos = sizeName.find('x');
    if (xPos == std::string::npos || xPos + 1 >= sizeName.size() ||
        sizeName.size() < xPos + PAGE_SIZE_UNIT_LENGTH + 1 || sizeName.size() < PAGE_SIZE_UNIT_LENGTH) {
        PRINT_HILOGE("IPP media-supported do not found \"x\"");
        return false;
    }
    std::string widthStr = sizeName.substr(0, xPos);
    std::string lengthStr = sizeName.substr(xPos + 1, sizeName.size() - xPos - PAGE_SIZE_UNIT_LENGTH - 1);
    std::string unit = sizeName.substr(sizeName.size() - PAGE_SIZE_UNIT_LENGTH);
    double widthValue = 0;
    double lengthValue = 0;
    if (!ConvertStrToDouble(widthStr, widthValue) || !ConvertStrToDouble(lengthStr, lengthValue)) {
        PRINT_HILOGE("Bad SafeStof Convert!");
        return false;
    }
    return ConvertCustomPageSizeFromWidthAndLength(widthValue, lengthValue, unit, dst);
}

bool SplitPwgKeyword(const std::string &pwgNameStr, std::string &middleName, std::string &sizeName)
{
    size_t firstPartPos = pwgNameStr.find_first_of('_');
    size_t lastPartPos = pwgNameStr.find_last_of('_');
    if (firstPartPos == std::string::npos || lastPartPos == std::string::npos ||
        lastPartPos + 1 >= pwgNameStr.size() || lastPartPos <= firstPartPos + 1) {
        return false;
    }
    middleName = pwgNameStr.substr(firstPartPos + 1, lastPartPos - firstPartPos - 1);
    sizeName = pwgNameStr.substr(lastPartPos + 1);
    return true;
}

void NormalizeCustomPageSizeList(std::vector<PrintPageSize> &entryList)
{
    const std::string suffix = "mm";
    const char sizeOpen = '(';
    const char sizeClose = ')';
    auto it = entryList.begin();
    while (it != entryList.end()) {
        PrintPageSize &item = *it;
        std::string name = item.GetName();
        // name format: <user-input>(<w>x<h>mm)
        size_t openPos = name.find_last_of(sizeOpen);
        size_t closePos = name.find_last_of(sizeClose);
        if (openPos == std::string::npos || closePos == std::string::npos || openPos >= closePos ||
            openPos == 0 || closePos != name.size() - 1) {
            it = entryList.erase(it);
            continue;
        }
        std::string inner = name.substr(openPos + 1, closePos - openPos - 1);
        if (inner.size() <= suffix.size() ||
            inner.compare(inner.size() - suffix.size(), suffix.size(), suffix) != 0) {
            it = entryList.erase(it);
            continue;
        }
        std::string mid = inner.substr(0, inner.size() - suffix.size());
        size_t xPos = mid.find('x');
        if (xPos == std::string::npos || xPos == 0 || xPos == mid.size() - 1) {
            it = entryList.erase(it);
            continue;
        }
        std::string wStr = mid.substr(0, xPos);
        std::string hStr = mid.substr(xPos + 1);
        double wMm = 0;
        double hMm = 0;
        if (!ConvertStrToDouble(wStr, wMm) || !ConvertStrToDouble(hStr, hMm)) {
            it = entryList.erase(it);
            continue;
        }
        PrintPageSize pageSize;
        if (!ConvertCustomPageSizeFromWidthAndLength(wMm, hMm, suffix, pageSize)) {
            it = entryList.erase(it);
            continue;
        }
        item.SetWidth(pageSize.GetWidth());
        item.SetHeight(pageSize.GetHeight());
        ++it;
    }
}

bool ConvertCustomPageSizeBound(const char *src, bool &isMinBound, uint32_t &widthMils, uint32_t &heightMils)
{
    if (src == nullptr) {
        PRINT_HILOGE("custom page size bound keyword is null");
        return false;
    }
    std::string middleName;
    std::string sizeName;
    if (!SplitPwgKeyword(std::string(src), middleName, sizeName)) {
        return false;
    }
    if (middleName == "min") {
        isMinBound = true;
    } else if (middleName == "max") {
        isMinBound = false;
    } else {
        return false;
    }
    PrintPageSize pageSize;
    if (!ConvertPwgSizeField(sizeName, pageSize)) {
        PRINT_HILOGE("custom page size bound has an invalid size field");
        return false;
    }
    widthMils = pageSize.GetWidth();
    heightMils = pageSize.GetHeight();
    return true;
}

bool ConvertPrintPageSize(const char *src, PrintPageSize &dst)
{
    if (src == nullptr) {
        PRINT_HILOGE("ConvertPrintPageSize is empty");
        return false;
    }
    std::string id;
    if (ConvertPageSizeId(src, id)) {
        PRINT_HILOGI("IPP media-supported match pageId: %{public}s", id.c_str());
        return PrintPageSize::FindPageSizeById(id, dst);
    }
    // Not standard, use custom page size
    return ConvertCustomPageSizeFromPwgName(src, dst);
}

bool ConvertPageSizeToJson(const PrintPageSize &pageSize, Json::Value &jsonObject)
{
    jsonObject["id"] = pageSize.GetId();
    jsonObject["name"] = pageSize.GetName();
    jsonObject["width"] = pageSize.GetWidth();
    jsonObject["height"] = pageSize.GetHeight();
    return true;
}

bool ConvertJsonToPageSizeList(const Json::Value &list, std::vector<PrintPageSize> &pageSizes)
{
    if (!list.isArray()) {
        PRINT_HILOGE("custom page size list is not an array");
        return false;
    }
    for (const auto &item : list) {
        if (!item.isObject()) {
            PRINT_HILOGW("skip non-object custom page size entry");
            continue;
        }
        if (!PrintJsonUtil::IsMember(item, CUSTOM_PAGE_SIZE_ITEM_ID) ||
            !item[CUSTOM_PAGE_SIZE_ITEM_ID].isString() ||
            !PrintJsonUtil::IsMember(item, CUSTOM_PAGE_SIZE_ITEM_NAME) ||
            !item[CUSTOM_PAGE_SIZE_ITEM_NAME].isString() ||
            !PrintJsonUtil::IsMember(item, CUSTOM_PAGE_SIZE_ITEM_WIDTH) ||
            !item[CUSTOM_PAGE_SIZE_ITEM_WIDTH].isUInt() ||
            !PrintJsonUtil::IsMember(item, CUSTOM_PAGE_SIZE_ITEM_HEIGHT) ||
            !item[CUSTOM_PAGE_SIZE_ITEM_HEIGHT].isUInt()) {
            PRINT_HILOGW("skip malformed custom page size entry");
            continue;
        }
        pageSizes.emplace_back(item[CUSTOM_PAGE_SIZE_ITEM_ID].asString(),
            item[CUSTOM_PAGE_SIZE_ITEM_NAME].asString(),
            item[CUSTOM_PAGE_SIZE_ITEM_WIDTH].asUInt(),
            item[CUSTOM_PAGE_SIZE_ITEM_HEIGHT].asUInt());
    }
    return true;
}

uint32_t GetUtf8CharCount(const std::string &s)
{
    constexpr unsigned char UTF8_ASCII_MASK = 0x80;
    constexpr unsigned char UTF8_TWO_BYTE_MASK = 0xE0;
    constexpr unsigned char UTF8_TWO_BYTE_TAG = 0xC0;
    constexpr unsigned char UTF8_THREE_BYTE_MASK = 0xF0;
    constexpr unsigned char UTF8_THREE_BYTE_TAG = 0xE0;
    constexpr unsigned char UTF8_FOUR_BYTE_MASK = 0xF8;
    constexpr unsigned char UTF8_FOUR_BYTE_TAG = 0xF0;
    constexpr size_t UTF8_ASCII_STEP = 1;
    constexpr size_t UTF8_TWO_BYTE_STEP = 2;
    constexpr size_t UTF8_THREE_BYTE_STEP = 3;
    constexpr size_t UTF8_FOUR_BYTE_STEP = 4;

    uint32_t count = 0;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < UTF8_ASCII_MASK) {
            i += UTF8_ASCII_STEP;
        } else if ((c & UTF8_TWO_BYTE_MASK) == UTF8_TWO_BYTE_TAG) {
            i += UTF8_TWO_BYTE_STEP;
        } else if ((c & UTF8_THREE_BYTE_MASK) == UTF8_THREE_BYTE_TAG) {
            i += UTF8_THREE_BYTE_STEP;
        } else if ((c & UTF8_FOUR_BYTE_MASK) == UTF8_FOUR_BYTE_TAG) {
            i += UTF8_FOUR_BYTE_STEP;
        } else {
            i += UTF8_ASCII_STEP;
        }
        count++;
    }
    return count;
}
}  // namespace Print
}  // namespace OHOS