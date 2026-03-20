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
#include "ani_scan_option_value_helper.h"
#include "scan_log.h"

namespace {
const char* PARAM_VALUE_TYPE = "valueType";
const char* PARAM_NUM_VALUE = "numValue";
const char* PARAM_STR_VALUE = "strValue";
const char* PARAM_BOOL_VALUE = "boolValue";
const char *CLASSNAME = "@ohos.scan.scan.ScannerOptionValue";
}

namespace OHOS::Scan {
using namespace OHOS::Print;
ani_object AniScanOptionValueHelper::CreateScanOptionValue(ani_env *env, const ScanOptionValue &value)
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
    SetIntProperty(env, obj, PARAM_VALUE_TYPE, static_cast<int32_t>(value.GetScanOptionValueType()));

    switch (value.GetScanOptionValueType()) {
        case SCAN_VALUE_BOOL:
            SetBoolProperty(env, obj, PARAM_BOOL_VALUE, value.GetBoolValue());
            break;
        case SCAN_VALUE_STR:
            SetStringProperty(env, obj, PARAM_STR_VALUE, value.GetStrValue());
            break;
        default:
            SetIntProperty(env, obj, PARAM_NUM_VALUE, value.GetNumValue());
            break;
    }

    return obj;
}

ScanOptionValue AniScanOptionValueHelper::ParseScanOptionValue(ani_env *env, ani_object obj)
{
    ScanOptionValue value;
    int32_t valueType = 0;
    if (GetIntProperty(env, obj, PARAM_VALUE_TYPE, valueType)) {
        value.SetScanOptionValueType(static_cast<ScanOptionValueType>(valueType));
    }
    switch (static_cast<ScanOptionValueType>(valueType)) {
        case SCAN_VALUE_BOOL: {
            bool boolValue = false;
            if (GetBoolProperty(env, obj, PARAM_BOOL_VALUE, boolValue)) {
                value.SetBoolValue(boolValue);
            }
            break;
        }
        case SCAN_VALUE_NUM: {
            int32_t numValue = 0;
            if (GetIntProperty(env, obj, PARAM_NUM_VALUE, numValue)) {
                value.SetNumValue(numValue);
            }
            break;
        }
        case SCAN_VALUE_STR: {
            std::string strValue;
            if (GetStringProperty(env, obj, PARAM_STR_VALUE, strValue)) {
                value.SetStrValue(strValue);
            }
            break;
        }
        default:
            SCAN_HILOGW("not support type %{public}d", valueType);
            break;
    }

    return value;
}
}  // namespace OHOS::Scan
