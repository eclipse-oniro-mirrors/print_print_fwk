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
#include "ani_print_preview_attribute_helper.h"
#include "ani_print_range_helper.h"
#include "print_log.h"

namespace {
const char* PREVIEW_RANGE_STR = "previewRange";
const char* RESULT_STR = "result";
const char *CLASS_NAME = "L@ohos/print/PrintPreviewAttribute;";
}

namespace OHOS::Print {
ani_object AniPrintPreviewAttributeHelper::CreatePreviewAttribute(ani_env *env, const PrintPreviewAttribute& preview)
{
    PRINT_HILOGI("enter CreatePreviewAttribute");
    ani_class cls;
    ani_object obj = CreateObject(env, CLASS_NAME, cls);

    PrintRange previewRange;
    preview.GetPreviewRange(previewRange);
    ani_ref previewRangeRef = AniPrintRangeHelper::CreatePrinterRange(env, previewRange);
    SetFieldRef(env, cls, obj, PREVIEW_RANGE_STR, previewRangeRef);

    if (preview.HasResult()) {
        SetFieldInt(env, cls, obj, RESULT_STR, static_cast<int32_t>(preview.GetResult()));
    }

    return obj;
}

PrintPreviewAttribute AniPrintPreviewAttributeHelper::ParsePreviewAttribute(ani_env *env, ani_object previewAttribute)
{
    PrintPreviewAttribute preview;

    ani_ref previewRangeRef;
    if (GetRefFieldByName(env, previewAttribute, PREVIEW_RANGE_STR, previewRangeRef)) {
        preview.SetPreviewRange(AniPrintRangeHelper::ParsePrinterRange(env, static_cast<ani_object>(previewRangeRef)));
    }

    ani_double result;
    if (GetDoubleOrUndefined(env, previewAttribute, RESULT_STR, result)) {
        preview.SetResult(static_cast<uint32_t>(result));
    }

    return preview;
}
}  // namespace OHOS::Print
