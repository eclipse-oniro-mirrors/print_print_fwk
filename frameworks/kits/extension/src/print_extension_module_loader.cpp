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

#include "print_extension_module_loader.h"

#include "print_extension.h"
#include "print_log.h"

namespace OHOS::AbilityRuntime {
PrintExtensionModuleLoader::PrintExtensionModuleLoader() = default;
PrintExtensionModuleLoader::~PrintExtensionModuleLoader() = default;

Extension *PrintExtensionModuleLoader::Create(const std::unique_ptr<Runtime> &runtime) const
{
    PRINT_HILOGD("jws PrintExtension::Create runtime");
    return PrintExtension::Create(runtime);
}

std::map<std::string, std::string> PrintExtensionModuleLoader::GetParams()
{
    std::map<std::string, std::string> params;
    params.insert(std::pair<std::string, std::string>("type", "15"));
    params.insert(std::pair<std::string, std::string>("name", "PrintExtension"));
    return params;
}

extern "C" __attribute__((visibility("default"))) void *OHOS_EXTENSION_GetExtensionModule()
{
    return &PrintExtensionModuleLoader::GetInstance();
}
} // namespace OHOS::AbilityRuntime