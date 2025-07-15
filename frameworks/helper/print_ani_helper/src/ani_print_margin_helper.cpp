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
#include "ani_print_margin_helper.h"
#include "print_log.h"

namespace {
const char* TOP_STR = "top";
const char* BOTTOM_STR = "bottom";
const char* LEFT_STR = "left";
const char* RIGHT_STR = "right";
}

namespace OHOS::Print {
PrintMargin AniPrintMarginHelper::ParsePrintMargin(ani_env *env, ani_object marginAni)
{
    PRINT_HILOGI("enter ParsePrintMargin");
    PrintMargin margin;
    int32_t top = 0;
    if (GetIntProperty(env, marginAni, TOP_STR, top)) {
        margin.SetTop(static_cast<uint32_t>(top));
    }
    int32_t bottom = 0;
    if (GetIntProperty(env, marginAni, BOTTOM_STR, bottom)) {
        margin.SetBottom(static_cast<uint32_t>(bottom));
    }
    int32_t left = 0;
    if (GetIntProperty(env, marginAni, LEFT_STR, left)) {
        margin.SetLeft(static_cast<uint32_t>(left));
    }
    int32_t right = 0;
    if (GetIntProperty(env, marginAni, RIGHT_STR, right)) {
        margin.SetRight(static_cast<uint32_t>(right));
    }
    return margin;
}

ani_object AniPrintMarginHelper::CreatePrintMargin(ani_env *env, const PrintMargin& margin)
{
    PRINT_HILOGI("enter CreatePrintMargin");
    static const char *className = "@ohos.print.print.PrintMarginImp";

    ani_object obj = CreateObject(env, nullptr, className);
    if (margin.HasTop()) {
        SetIntProperty(env, obj, TOP_STR, static_cast<int32_t>(margin.GetTop()));
    }

    if (margin.HasBottom()) {
        SetIntProperty(env, obj, BOTTOM_STR, static_cast<int32_t>(margin.GetBottom()));
    }

    if (margin.HasLeft()) {
        SetIntProperty(env, obj, LEFT_STR, static_cast<int32_t>(margin.GetLeft()));
    }

    if (margin.HasRight()) {
        SetIntProperty(env, obj, RIGHT_STR, static_cast<int32_t>(margin.GetRight()));
    }

    return obj;
}
}  // namespace OHOS::Print