/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mock_napi_scan_utils.h"
#include "napi_scan_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "scan_constant.h"

bool g_mockGetRefReturnNonNull = false;

namespace OHOS::Scan {
napi_value NapiScanUtils::GetReference(napi_env env, napi_ref callbackRef)
{
    if (g_mockGetRefReturnNonNull) {
        return reinterpret_cast<napi_value>(1);
    }
    if (callbackRef == nullptr) {
        return nullptr;
    }
    napi_value callback = nullptr;
    SCAN_CALL(env, napi_get_reference_value(env, callbackRef, &callback));
    return callback;
}
}
