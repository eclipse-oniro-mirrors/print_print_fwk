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

#ifndef JS_PRINT_CALLBACK_H
#define JS_PRINT_CALLBACK_H

#include <memory>
#include <mutex>
#include <uv.h>
#include <vector>

#include "napi/native_api.h"

namespace OHOS {
namespace AbilityRuntime {
class JsRuntime;
class JsPrintCallback : public std::enable_shared_from_this<JsPrintCallback> {
public:
    explicit JsPrintCallback(JsRuntime &jsRutime);
    ~JsPrintCallback() = default;
    static bool Call(napi_env env, void *data, uv_after_work_cb afterCallback);
    napi_value Exec(napi_value jsObj, const std::string &name, napi_value const *argv = nullptr, size_t argc = 0,
        bool isSync = true);

private:
    uv_loop_s *GetJsLoop(JsRuntime &jsRuntime);
    bool BuildJsWorker(napi_value jsObj, const std::string &name,
        napi_value const *argv, size_t argc, bool isSync);

private:
    struct JsWorkParam {
        std::shared_ptr<JsPrintCallback> self;
        napi_env nativeEngine;
        napi_value jsObj;
        napi_value jsMethod;
        napi_value const *argv;
        size_t argc;
        napi_value jsResult;
        bool isSync;
        bool isCompleted;
        JsWorkParam()
        {
            self = nullptr;
            nativeEngine = nullptr;
            jsObj = nullptr;
            jsMethod = nullptr;
            argv = nullptr;
            argc = 0;
            jsResult = nullptr;
            isSync = false;
            isCompleted = false;
        }
    };

    JsRuntime &jsRuntime_;
    uv_work_t *jsWorker_;

    JsPrintCallback::JsWorkParam jsParam_;

    std::mutex conditionMutex_;
    std::condition_variable syncCon_;
    static constexpr int SYNC_TIME_OUT = 1000;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // JS_PRINT_CALLBACK_H
