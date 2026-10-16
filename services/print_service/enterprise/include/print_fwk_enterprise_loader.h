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

#ifndef PRINT_FWK_ENTERPRISE_LOADER_H
#define PRINT_FWK_ENTERPRISE_LOADER_H

#include <mutex>

#include "print_fwk_enterprise_api.h"

namespace OHOS::Print {

class PrintFwkEnterpriseLoader {
public:
    PrintFwkEnterpriseLoader() = default;
    ~PrintFwkEnterpriseLoader();

    bool Load();
    bool IsLoaded() const { return api_ != nullptr && handle_ != nullptr; }
    void Unload();

    int32_t IsEnterpriseWorkspace(int32_t workspaceId, bool &isEnterprise);

private:
    void *OpenLibrary() const;
    const PrintFwkEnterpriseApi *ResolveApi(void *libHandle) const;
    bool ValidateApi(const PrintFwkEnterpriseApi *api) const;

    void *handle_ = nullptr;
    const PrintFwkEnterpriseApi *api_ = nullptr;
    std::mutex mutex_;
};

} // namespace OHOS::Print

#endif // PRINT_FWK_ENTERPRISE_LOADER_H
