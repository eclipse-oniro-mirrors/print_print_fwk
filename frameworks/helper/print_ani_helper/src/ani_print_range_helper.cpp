/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <ani.h>
#include "print_base_ani_util.h"
#include "print_object_ani_util.h"
#include "ani_print_range_helper.h"
#include "print_log.h"

namespace {
const char* START_PAGE_STR = "startPage";
const char* END_PAGE_STR = "endPage";
const char* PAGES_STR = "pages";
const char* CLASS_NAME = "@ohos.print.print.PrinterRangeImp";
}

namespace OHOS::Print {
PrintRange AniPrintRangeHelper::ParsePrinterRange(ani_env *env, ani_object rangeAni)
{
    PRINT_HILOGI("enter ParsePrinterRange");
    PrintRange range;
    int32_t startPageAni = 0;
    if (GetIntProperty(env, rangeAni, START_PAGE_STR, startPageAni)) {
        PRINT_HILOGD("The parsed colorMode part %{public}d", static_cast<uint32_t>(startPageAni));
        range.SetStartPage(static_cast<uint32_t>(startPageAni));
    }
    int32_t endPageAni = 0;
    if (GetIntProperty(env, rangeAni, END_PAGE_STR, endPageAni)) {
        PRINT_HILOGD("The parsed colorMode part %{public}d", static_cast<uint32_t>(endPageAni));
        range.SetEndPage(static_cast<uint32_t>(endPageAni));
    }

    std::vector<int32_t> pagesAni;
    if (GetIntArrayProperty(env, rangeAni, PAGES_STR, pagesAni)) {
        std::vector<uint32_t> pages;
        for (auto page : pagesAni) {
            pages.push_back(static_cast<uint32_t>(page));
        }
        range.SetPages(pages);
    }
    return range;
}

ani_object AniPrintRangeHelper::CreatePrinterRange(ani_env *env, const PrintRange& printRange)
{
    PRINT_HILOGI("enter CreatePrinterRange");
    ani_object obj = CreateObject(env, nullptr, CLASS_NAME);

    SetIntProperty(env, obj, START_PAGE_STR, static_cast<int32_t>(printRange.GetStartPage()));
    SetIntProperty(env, obj, END_PAGE_STR, static_cast<int32_t>(printRange.GetEndPage()));
    std::vector<uint32_t> pages;
    printRange.GetPages(pages);
    SetIntArrayProperty(env, obj, PAGES_STR, std::vector<int32_t>(pages.begin(), pages.end()));
    return obj;
}
}  // namespace OHOS::Print
