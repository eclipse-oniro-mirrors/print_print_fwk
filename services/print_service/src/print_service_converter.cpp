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
#include <sstream>

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
        lastPartPos + 1 >= pwgNameStr.size() || lastPartPos - firstPartPos - 1 < 0) {
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
        sizeName.size() - xPos - PAGE_SIZE_UNIT_LENGTH - 1 < 0 || sizeName.size() - PAGE_SIZE_UNIT_LENGTH < 0) {
        PRINT_HILOGE("IPP media-supported do not found \"x\"");
        return false;
    }
    std::string widthStr = sizeName.substr(0, xPos);
    std::string lengthStr = sizeName.substr(xPos + 1, sizeName.size() - xPos - PAGE_SIZE_UNIT_LENGTH - 1);
    std::string unit = sizeName.substr(sizeName.size() - PAGE_SIZE_UNIT_LENGTH);
    uint32_t width = 0;
    uint32_t length = 0;
    std::stringstream postfixName;
    if (unit == "mm") {
        width = round(std::stof(widthStr) * HUNDRED_OF_MILLIMETRE_TO_INCH);
        length = round(std::stof(lengthStr) * HUNDRED_OF_MILLIMETRE_TO_INCH);
        postfixName << round(std::stof(widthStr)) << "x" << round(std::stof(lengthStr)) << "mm";
    } else if (unit == "in") {
        width = round(std::stof(widthStr) * ONE_THOUSAND_INCH);
        length = round(std::stof(lengthStr) * ONE_THOUSAND_INCH);
        postfixName << round(std::stof(widthStr) * ONE_THOUSAND_INCH / HUNDRED_OF_MILLIMETRE_TO_INCH) << "x" <<
            round(std::stof(lengthStr) * ONE_THOUSAND_INCH / HUNDRED_OF_MILLIMETRE_TO_INCH) << "mm";
    } else {
        PRINT_HILOGE("IPP media-supported do not found unitstr");
        return false;
    }
    std::string pwgName = CUSTOM_PREFIX + postfixName.str();
    dst = PrintPageSize(pwgName, pwgName, width, length);
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
}  // namespace Print
}  // namespace OHOS