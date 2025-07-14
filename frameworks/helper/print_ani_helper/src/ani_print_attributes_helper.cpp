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
#include "ani_print_page_size_helper.h"
#include "ani_print_attributes_helper.h"
#include "print_log.h"

namespace {
const char* COPY_NUMBER_STR = "copyNumber";
const char* PAGE_RANGE_STR = "pageRange";
const char* PAGE_SIZE_STR = "pageSize";
const char* DIRECTION_MODE_STR = "directionMode";
const char* COLOR_MODE_STR = "colorMode";
const char* DUPLEX_MODE_STR = "duplexMode";
}
namespace OHOS::Print {
PrintAttributes AniPrintAttributesHelper::ParsePrintAttributes(ani_env *env, ani_object attributes)
{
    PRINT_HILOGI("enter ParsePrintAttributes");
    PrintAttributes attrs;
    int32_t copyNumber;
    if (GetIntProperty(env, attributes, COPY_NUMBER_STR, copyNumber)) {
        attrs.SetCopyNumber(static_cast<uint32_t>(copyNumber));
    }
    ani_ref pageRangeRef;
    if (GetRefProperty(env, attributes, PAGE_RANGE_STR, pageRangeRef)) {
        PrintRange pageRange = AniPrintRangeHelper::ParsePrinterRange(env, static_cast<ani_object>(pageRangeRef));
        attrs.SetPageRange(pageRange);
    }
    ani_ref pageSizeRef;
    if (GetRefProperty(env, attributes, PAGE_SIZE_STR, pageSizeRef)) {
        PrintPageSize pageSize = AniPrintPageSizeHelper::ParsePrintPageSize(env, static_cast<ani_object>(pageSizeRef));
        attrs.SetPageSize(pageSize);
    }
    ani_ref directionModeEnum = nullptr;
    uint32_t directionModeValue = 0;
    if (GetRefProperty(env, attributes, DIRECTION_MODE_STR, directionModeEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(directionModeEnum), directionModeValue)) {
        attrs.SetDirectionMode(directionModeValue);
    }
    ani_ref colorModeEnum = nullptr;
    uint32_t colorModeValue = 0;
    if (GetRefProperty(env, attributes, COLOR_MODE_STR, colorModeEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(colorModeEnum), colorModeValue)) {
        attrs.SetColorMode(colorModeValue);
    }
    ani_ref duplexModeEnum = nullptr;
    uint32_t duplexModeValue = 0;
    if (GetRefProperty(env, attributes, DUPLEX_MODE_STR, duplexModeEnum) &&
        GetEnumValueInt(env, static_cast<ani_enum_item>(duplexModeEnum), duplexModeValue)) {
        attrs.SetColorMode(duplexModeValue);
    }
    return attrs;
}

}  // namespace OHOS::Print