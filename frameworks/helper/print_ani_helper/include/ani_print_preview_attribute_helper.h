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
#ifndef OHOS_PRINT_PREVIEW_ATTRIBUTE_HELPER_H
#define OHOS_PRINT_PREVIEW_ATTRIBUTE_HELPER_H

#include <ani.h>
#include <string>
#include "print_preview_attribute.h"
namespace OHOS::Print {
class AniPrintPreviewAttributeHelper {
public:
    static ani_object CreatePreviewAttribute(ani_env *env, const PrintPreviewAttribute& preview);
    static PrintPreviewAttribute ParsePreviewAttribute(ani_env *env, ani_object previewAttribute);
};
}  // namespace OHOS::Print
#endif  // OHOS_PRINT_PREVIEW_ATTRIBUTE_HELPER_H