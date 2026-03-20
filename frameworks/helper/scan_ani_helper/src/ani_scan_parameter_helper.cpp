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
#include "ani_scan_parameter_helper.h"
#include "ani_scan_range_helper.h"
#include "scan_log.h"

namespace {
const char* PARAM_OPTION_NAME = "optionName";
const char* PARAM_OPTION_INDEX = "optionIndex";
const char* PARAM_OPTION_TITLE = "optionTitle";
const char* PARAM_OPTION_DESC = "optionDesc";
const char* PARAM_OPTION_TYPE = "optionType";
const char* PARAM_OPTION_UNIT = "optionUnit";
const char* PARAM_OPTION_CONSTRAINT_TYPE = "optionConstraintType";
const char* PARAM_OPTION_CONSTRAINT_STRING = "optionConstraintString";
const char* PARAM_OPTION_CONSTRAINT_INT = "optionConstraintInt";
const char* PARAM_OPTION_CONSTRAINT_RANGE = "optionConstraintRange";
const char *CLASSNAME = "@ohos.scan.scan.ScannerParameter";
}

namespace OHOS::Scan {
using namespace OHOS::Print;
ani_object AniScanParameterHelper::CreateScanParameter(ani_env *env, const ScanOptionDescriptor &desc)
{
    if (env == nullptr) {
        SCAN_HILOGE("null env");
        return nullptr;
    }
    ani_object obj = CreateObject(env, nullptr, CLASSNAME);
    if (obj == nullptr) {
        SCAN_HILOGE("null obj");
        return nullptr;
    }
    SetStringProperty(env, obj, PARAM_OPTION_NAME, desc.GetOptionName());
    SetIntProperty(env, obj, PARAM_OPTION_INDEX, static_cast<int32_t>(desc.GetOptionIndex()));
    SetStringProperty(env, obj, PARAM_OPTION_TITLE, desc.GetOptionTitle());
    SetStringProperty(env, obj, PARAM_OPTION_DESC, desc.GetOptionDesc());
    SetIntProperty(env, obj, PARAM_OPTION_TYPE, static_cast<int32_t>(desc.GetOptionType()));
    SetIntProperty(env, obj, PARAM_OPTION_UNIT, static_cast<int32_t>(desc.GetOptionUnit()));
    SetIntProperty(env, obj, PARAM_OPTION_CONSTRAINT_TYPE, static_cast<int32_t>(desc.GetOptionConstraintType()));

    std::vector<std::string> constraintString;
    desc.GetOptionConstraintString(constraintString);
    if (!constraintString.empty()) {
        ani_object stringArray = CreateAniStringArray(env, constraintString);
        SetRefProperty(env, obj, PARAM_OPTION_CONSTRAINT_STRING, stringArray);
    }

    std::vector<int32_t> constraintInt;
    desc.GetOptionConstraintNumber(constraintInt);
    ani_object intArray = CreateAniIntArray(env, constraintInt);
    if (intArray != nullptr) {
        SetRefProperty(env, obj, PARAM_OPTION_CONSTRAINT_INT, intArray);
    }

    ScanRange range;
    desc.GetOptionConstraintRange(range);
    ani_object rangeObj = AniScanRangeHelper::CreateScanRange(env, range);
    if (rangeObj != nullptr) {
        SetRefProperty(env, obj, PARAM_OPTION_CONSTRAINT_RANGE, rangeObj);
    }
    return obj;
}

ani_object AniScanParameterHelper::CreateScanParameterArray(ani_env *env,
    const std::vector<ScanOptionDescriptor> &descs)
{
    if (env == nullptr) {
        SCAN_HILOGE("null env");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    ani_status status = env->FindClass("std.core.Array", &arrayCls);
    if (status != ANI_OK) {
        SCAN_HILOGE("FindClass failed");
        return nullptr;
    }
    ani_method arrayCtor = nullptr;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        SCAN_HILOGE("Class_FindMethod failed");
        return nullptr;
    }
    ani_size length = descs.size();
    ani_object arrayObj = nullptr;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, length);
    if (status != ANI_OK) {
        SCAN_HILOGE("Object_New failed");
        return nullptr;
    }

    for (size_t i = 0; i < descs.size(); i++) {
        ani_object paramObj = CreateScanParameter(env, descs[i]);
        if (paramObj == nullptr) {
            SCAN_HILOGW("null paramObj");
            continue;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", i, paramObj)) {
            SCAN_HILOGE("Set Array item failed");
            return nullptr;
        }
    }
    return arrayObj;
}
}  // namespace OHOS::Scan
