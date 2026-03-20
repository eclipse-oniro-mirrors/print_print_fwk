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
#include "ani_scan_range_helper.h"
#include "scan_log.h"

namespace {
const char* PARAM_MIN_VALUE = "minValue";
const char* PARAM_MAX_VALUE = "maxValue";
const char* PARAM_QUANT_VALUE = "quantValue";
const char *CLASSNAME = "@ohos.scan.scan.Range";
}

namespace OHOS::Scan {
using namespace OHOS::Print;
ani_object AniScanRangeHelper::CreateScanRange(ani_env *env, const ScanRange &range)
{
    if (env == nullptr) {
        SCAN_HILOGE("null env");
        return nullptr;
    }
    ani_object rangeObj = CreateObject(env, nullptr, CLASSNAME);
    if (rangeObj == nullptr) {
        SCAN_HILOGE("null obj");
        return nullptr;
    }
    SetIntProperty(env, rangeObj, PARAM_MIN_VALUE, static_cast<int32_t>(range.GetMinValue()));
    SetIntProperty(env, rangeObj, PARAM_MAX_VALUE, static_cast<int32_t>(range.GetMaxValue()));
    SetIntProperty(env, rangeObj, PARAM_QUANT_VALUE, static_cast<int32_t>(range.GetQuantValue()));
    return rangeObj;
}
}  // namespace OHOS::Scan
