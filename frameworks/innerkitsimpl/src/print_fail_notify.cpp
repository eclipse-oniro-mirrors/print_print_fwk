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

#include "print_fail_notify.h"

#include <uv.h>

#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
PrintFailNotify::PrintFailNotify(napi_env env, const std::string &type, napi_ref ref) : PrintBaseNotify(env, type, ref)
{}

PrintFailNotify::~PrintFailNotify()
{
    PRINT_HILOGD("");
}

void PrintFailNotify::OnCallBack(MessageParcel &data)
{
    PRINT_HILOGD("Failed callback in");
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        PRINT_HILOGE("Failed to get uv event loop");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        PRINT_HILOGE("Failed to create uv work");
        return;
    }

    NotifyData *notifyData = GetNotifyData();
    notifyData->env = env_;
    notifyData->ref = ref_;
    notifyData->type = type_;
    notifyData->firstArgv = data.ReadUint32();
    PRINT_HILOGD("recv error code is %{public}d", notifyData->firstArgv);
    work->data = notifyData;

    uv_queue_work(
        loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int statusInt) {
            PRINT_HILOGD("this is new fail callback");
            NotifyData *notifyData = static_cast<NotifyData *>(work->data);
            napi_value undefined = 0;
            napi_get_undefined(notifyData->env, &undefined);
            napi_value callbackFunc = nullptr;
            napi_get_reference_value(notifyData->env, notifyData->ref, &callbackFunc);
            napi_value result = nullptr;
            napi_value callbackValue;
            napi_create_uint32(notifyData->env, notifyData->firstArgv, &callbackValue);
            napi_call_function(
                notifyData->env, nullptr, callbackFunc, PrintNapiUtils::ONE_ARG, &callbackValue, &result);
            if (work != nullptr) {
                delete work;
                work = nullptr;
            }
            delete notifyData;
            notifyData = nullptr;
        });
}
} // namespace OHOS::Print
