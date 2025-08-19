/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PRINT_CONTEXT_H
#define PRINT_CONTEXT_H

#include "ability_context.h"
#include "ui_extension_context.h"
#include "napi/native_api.h"
#include <string>
#include <vector>

#include "print_log.h"

namespace OHOS {
namespace Print {

enum PrintRequestType {
    REQUEST_TYPE_START,
    REQUEST_TYPE_INVALID,
};

struct PrintInfo {
    std::string jobId;
    std::string fileList;
};

struct ErrorMessage {
    int32_t code;
    std::string message;
};

struct BaseContext {
    napi_env env = nullptr;
    napi_value jsCallback = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> context = nullptr;
    std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> uiExtensionContext = nullptr;
    PrintRequestType requestType = PrintRequestType::REQUEST_TYPE_INVALID;
    ErrorMessage errorMessage;

    ~BaseContext()
    {
        PRINT_HILOGI("release enter");
        if (this->callback != nullptr) {
            napi_delete_reference(this->env, this->callback);
            this->callback = nullptr;
            PRINT_HILOGI("release callback");
        }

        if (this->deferred != nullptr) {
            this->deferred = nullptr;
            PRINT_HILOGI("release deferred");
        }
        PRINT_HILOGI("release exit");
    }
};

struct PrintContext : BaseContext {
    PrintInfo printInfo;
};
} // namespace OHOS
} // namespace Print
#endif
