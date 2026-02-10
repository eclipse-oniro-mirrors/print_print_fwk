/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_print_callback.h"
#include "napi/native_node_api.h"
#include "print_log.h"
#include "print_constant.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::Print;

bool JsPrintCallback::Call(napi_env env, WorkParam *param, std::function<void(WorkParam*)> workCb)
{
    auto task = [param, workCb]() {
        if (param == nullptr) {
            PRINT_HILOGE("param is a nullptr");
            return;
        }
        workCb(param);
        delete param;
    };

    napi_status ret = napi_send_event(env, task, napi_eprio_immediate);
    if (ret != napi_ok) {
        PRINT_HILOGE("napi_send_event fail");
        return false;
    }
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS
