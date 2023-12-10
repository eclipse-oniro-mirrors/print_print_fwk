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

#ifndef NAPI_PRINT_TASK_H
#define NAPI_PRINT_TASK_H

#include <string>
#include "ability.h"
#include "ability_context.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_inner_print.h"

namespace OHOS::Print {
struct PrintTaskContext : public PrintAsyncCall::Context {
    napi_ref ref = nullptr;
    PrintTaskContext() : Context(nullptr, nullptr) {}
    PrintTaskContext(InputAction input, OutputAction output) : Context(std::move(input), std::move(output)) {};
    virtual ~PrintTaskContext() {}
};
class NapiPrintTask {
public:
    static napi_value Print(napi_env env, napi_callback_info info);

private:
    static napi_value GetCtor(napi_env env);
    static napi_value Initialize(napi_env env, napi_callback_info info);
    static bool IsValidFile(const std::string &fileName);
    static napi_value GetAbilityContext(
        napi_env env, napi_value value, std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> &abilityContext);
    static napi_value WrapVoidToJS(napi_env env);
    static napi_status VerifyParameters(napi_env env, size_t argc, napi_value *argv,
        const std::shared_ptr<PrintTaskContext> context);
    static napi_value PrintByAdapter(napi_env env, napi_callback_info info);
    static napi_value ParsePrintAdapterParameter(napi_env env, size_t argc, napi_value *argv, napi_value self);

private:
    static __thread napi_ref globalCtor;
};
}  // namespace OHOS::Print
#endif  // _NAPI_PRINT_TASK_H
