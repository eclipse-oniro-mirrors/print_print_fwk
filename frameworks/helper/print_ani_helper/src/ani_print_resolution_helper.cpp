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
#include "ani_print_resolution_helper.h"
#include "print_log.h"
namespace {
    const char* ID = "id";
    const char* HORIZONTAL_DPI = "horizontalDpi";
    const char* VERTICAL_DPI = "verticalDpi";
}
namespace OHOS::Print {
PrintResolution AniPrintResolutionHelper::ParsePrintResolution(ani_env *env, ani_object resolutionAni)
{
    PRINT_HILOGI("enter ParsePrintResolution");
    PrintResolution resolution;
    std::string id;
    if (GetStringOrUndefined(env, resolutionAni, ID, id)) {
        resolution.SetId(id);
    }
    int32_t horizontalDpi = 0;
    if (GetIntByName(env, resolutionAni, HORIZONTAL_DPI, horizontalDpi)) {
        resolution.SetHorizontalDpi(static_cast<uint32_t>(horizontalDpi));
    }
    int32_t verticalDpi = 0;
    if (GetIntByName(env, resolutionAni, VERTICAL_DPI, verticalDpi)) {
        resolution.SetVerticalDpi(static_cast<uint32_t>(verticalDpi));
    }
    return resolution;
}

}  // namespace OHOS::Print