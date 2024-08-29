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

#ifndef PRINT_SERVICE_CONVERTER_H
#define PRINT_SERVICE_CONVERTER_H

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "print_page_size.h"

namespace OHOS {
namespace Print {
enum DuplexModeCode {
    DUPLEX_MODE_ONE_SIDED = 0,
    DUPLEX_MODE_TWO_SIDED_LONG_EDGE = 1,
    DUPLEX_MODE_TWO_SIDED_SHORT_EDGE = 2,
};

enum ColorModeCode {
    COLOR_MODE_MONOCHROME = 0,
    COLOR_MODE_COLOR = 1,
    COLOR_MODE_AUTO = 2
};

const int CONST_VALUE_300 = 300;
const int CONST_VALUE_120 = 120;

inline int DpcToDpi(int dpc)
{
    return dpc * CONST_VALUE_300 / CONST_VALUE_120; // 300 DPI = 120 DPC
}

template <typename T>
void AddToUniqueList(std::vector<T> &list, T value)
{
    for (auto &item : list) {
        if (item == value) {
            return;
        }
    }
    list.push_back(value);
}

template <typename T>
std::string ConvertListToJson(const std::vector<T> &list, bool (*ConvertToJson)(const T &, nlohmann::json &))
{
    nlohmann::json array = nlohmann::json::array();
    for (auto &item : list) {
        nlohmann::json object;
        if (ConvertToJson(item, object)) {
            array.push_back(object);
        }
    }
    return array.dump();
}

bool ConvertColorModeCode(const char *src, ColorModeCode &dst);
bool ConvertColorModeToJson(const ColorModeCode &code, nlohmann::json &jsonObject);
bool ConvertDuplexModeToJson(const DuplexModeCode &code, nlohmann::json &jsonObject);
bool ConvertPageSizeId(const char *src, std::string &id);
bool ConvertPrintPageSize(const char *src, PrintPageSize &dst);
bool ConvertPageSizeToJson(const PrintPageSize &code, nlohmann::json &jsonObject);
std::string GetQulityString(int code);
}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_SERVICE_CONVERTER_H
