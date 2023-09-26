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

#ifndef JS_PRINT_EXTENSION_CONTEXT_H
#define JS_PRINT_EXTENSION_CONTEXT_H

#include <memory>

#include "ability_connect_callback.h"
#include "event_handler.h"
#include "print_extension_context.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AbilityRuntime {
napi_value CreateJsPrintExtensionContext(napi_env engine,
    std::shared_ptr<PrintExtensionContext> context, std::string &extensionId);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // JS_PRINT_EXTENSION_CONTEXT_H