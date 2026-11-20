/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "print_custom_page_size_util.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "print_service_converter.h"

namespace OHOS::Print {

void PrintCustomPageSizeUtil::UpdateOptionWithCustomPageSizes(const PrinterUserPreferences &userPrefs,
    PrinterPreferences &printerPreference, Json::Value &opsJson, bool hasValidOption)
{
    if (userPrefs.HasCustomPageSizes()) {
        Json::Value listJson(Json::arrayValue);
        for (const auto &pageSize : userPrefs.GetCustomPageSizes()) {
            Json::Value entry;
            ConvertPageSizeToJson(pageSize, entry);
            listJson.append(entry);
        }
        opsJson[CUSTOM_PAGE_SIZE_LIST_KEY] = listJson;
    }
    if (hasValidOption || userPrefs.HasCustomPageSizes()) {
        printerPreference.SetOption(PrintJsonUtil::WriteString(opsJson));
    }
}
} // namespace OHOS::Print
