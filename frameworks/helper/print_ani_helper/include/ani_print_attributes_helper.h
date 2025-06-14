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
#ifndef OHOS_ANI_PRINT_ATTRIBUTES_HELPER_H
#define OHOS_ANI_PRINT_ATTRIBUTES_HELPER_H

#include <ani.h>
#include <string>
#include "print_attributes.h"
namespace OHOS::Print {
class AniPrintAttributesHelper {
public:
    static PrintAttributes ParsePrintAttributes(ani_env *env, ani_object printAttribute);
};
}  // namespace OHOS::Print
#endif  // OHOS_ANI_PRINT_ATTRIBUTES_HELPER_H