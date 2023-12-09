/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "print_range_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_RANGE_STARTPAGE = "startPage";
static constexpr const char *PARAM_RANGE_ENDPAGE = "endPage";
static constexpr const char *PARAM_RANGE_PAGES = "pages";

napi_value PrintRangeHelper::MakeJsObject(napi_env env, const PrintRange &range)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    if (range.HasStartPage()) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RANGE_STARTPAGE, range.GetStartPage());
    }
    if (range.HasEndPage()) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RANGE_ENDPAGE, range.GetEndPage());
    }

    if (range.HasPages()) {
        std::vector<uint32_t> pages;
        range.GetPages(pages);
        if (range.GetStartPage() == 0 && range.GetEndPage() == 0 && pages.size() > 0) {
            napi_value arrPages = nullptr;
            PRINT_CALL(env, napi_create_array(env, &arrPages));
            uint32_t arrPagesLength = pages.size();
            for (uint32_t i = 0; i < arrPagesLength; i++) {
                napi_value value;
                PRINT_CALL(env, napi_create_uint32(env, pages[i], &value));
                PRINT_CALL(env, napi_set_element(env, arrPages, i, value));
            }
            PRINT_CALL(env, napi_set_named_property(env, jsObj, PARAM_RANGE_PAGES, arrPages));
        }
    }
    return jsObj;
}

std::shared_ptr<PrintRange> PrintRangeHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintRange>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print range");
        return nullptr;
    }

    auto jsStartPage = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_STARTPAGE);
    if (jsStartPage != nullptr) {
        nativeObj->SetStartPage(NapiPrintUtils::GetUint32FromValue(env, jsStartPage));
    }

    auto jsEndPage = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_ENDPAGE);
    if (jsEndPage != nullptr) {
        nativeObj->SetEndPage(NapiPrintUtils::GetUint32FromValue(env, jsEndPage));
    }

    if (nativeObj->GetEndPage() != 0 && nativeObj->GetEndPage() < nativeObj->GetStartPage()) {
        PRINT_HILOGE("Start and end page conflict");
        return nullptr;
    }

    napi_value jsPages = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_PAGES);
    if (jsPages != nullptr) {
        std::vector<uint32_t> pages;
        bool isArray = false;
        PRINT_CALL(env, napi_is_array(env, jsPages, &isArray));
        if (!isArray) {
            PRINT_HILOGE("Invalid pages of page range");
            return nullptr;
        }
        uint32_t arrayLength = 0;
        PRINT_CALL(env, napi_get_array_length(env, jsPages, &arrayLength));
        for (uint32_t index = 0; index < arrayLength; index++) {
            napi_value jsPage;
            uint32_t pageNo;
            PRINT_CALL(env, napi_get_element(env, jsPages, index, &jsPage));
            PRINT_CALL(env, napi_get_value_uint32(env, jsPage, &pageNo));
            pages.emplace_back(pageNo);
        }
        nativeObj->SetPages(pages);
    }

    PRINT_HILOGI("Build Page Range succeed");
    return nativeObj;
}

bool PrintRangeHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_RANGE_STARTPAGE, PRINT_PARAM_OPT},
        {PARAM_RANGE_ENDPAGE, PRINT_PARAM_OPT},
        {PARAM_RANGE_PAGES, PRINT_PARAM_OPT},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = PRINT_PARAM_SET;
    }
    bool hasStartPage = propertyList[PARAM_RANGE_STARTPAGE] == PRINT_PARAM_SET;
    bool hasEndPage = propertyList[PARAM_RANGE_ENDPAGE] == PRINT_PARAM_SET;
    bool hasPages = propertyList[PARAM_RANGE_PAGES] == PRINT_PARAM_SET;
    if ((hasStartPage || hasEndPage) && hasPages) {
        return false;
    }
    return true;
}
} // namespace OHOS::Print
