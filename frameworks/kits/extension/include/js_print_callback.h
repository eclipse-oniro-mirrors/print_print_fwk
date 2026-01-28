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
#include <vector>
#include <functional>
#include "napi/native_api.h"
#include "print_job.h"

namespace OHOS {
namespace AbilityRuntime {
struct WorkParam {
    napi_env env;
    std::string funcName;
    std::string printerId;
    Print::PrintJob job;
    WorkParam(napi_env env, std::string funcName) : env(env), funcName(funcName) {}
};

class JsPrintCallback {
public:
    JsPrintCallback() = default;
    ~JsPrintCallback() = default;
    static bool Call(napi_env env, WorkParam *param, std::function<void(WorkParam*)> workCb);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // JS_PRINT_CALLBACK_H
