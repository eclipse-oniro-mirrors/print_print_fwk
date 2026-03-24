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
#ifndef OHOS_ANI_SCAN_OPTION_VALUE_HELPER_H
#define OHOS_ANI_SCAN_OPTION_VALUE_HELPER_H

#include <ani.h>
#include "scan_option_value.h"
#include "scan_constant.h"

namespace OHOS::Scan {
class AniScanOptionValueHelper {
public:
    static ani_object CreateScanOptionValue(ani_env *env, const ScanOptionValue &value);
    static ScanOptionValue ParseScanOptionValue(ani_env *env, ani_object obj);
};
}
#endif
