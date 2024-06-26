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

bool ConvertColorModeToJson(const ColorModeCode &code, nlohmann::json &jsonObject)
{
    jsonObject["color"] = std::to_string(static_cast<int>(code));
    return true;
}

bool ConvertDuplexModeToJson(const DuplexModeCode &code, nlohmann::json &jsonObject)
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

bool ConvertPrintPageSize(const char *src, PrintPageSize &dst)
{
    std::string id;
    if (ConvertPageSizeId(src, id)) {
        return PrintPageSize::FindPageSizeById(id, dst);
    }
    return false;
}

bool ConvertPageSizeToJson(const PrintPageSize &pageSize, nlohmann::json &jsonObject)
{
    jsonObject["id"] = pageSize.GetId();
    jsonObject["name"] = pageSize.GetName();
    jsonObject["width"] = pageSize.GetWidth();
    jsonObject["height"] = pageSize.GetHeight();
    return true;
}
}  // namespace Print
}  // namespace OHOS