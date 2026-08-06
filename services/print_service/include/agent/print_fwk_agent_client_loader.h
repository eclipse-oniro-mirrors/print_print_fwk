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

#ifndef PRINT_FWK_AGENT_CLIENT_LOADER_H
#define PRINT_FWK_AGENT_CLIENT_LOADER_H

#include <mutex>
#include <string>

#include "agent/print_fwk_agent_client_api.h"

namespace OHOS::Print {

class PrintFwkAgentClientLoader {
public:
    virtual ~PrintFwkAgentClientLoader();

    virtual bool Load();
    bool IsLoaded() const { return api_ != nullptr && handle_ != nullptr; }
    void Unload();

    int32_t AddPrinter(const PrintAddPrinterParam &params,
        PrintAgentAddDoneCb doneCb,
        PrintAgentProgressCb progressCb, void *userData);

    int32_t RemovePrinter(const std::string &name, const std::string &backendType,
        PrintAgentRemoveDoneCb doneCb, void *userData);

    void SetApiForTest(const PrintFwkAgentClientApi *api,
        PrintFwkAgentClient *client);
    static int32_t MapError(int32_t e);

private:
    void *OpenClientLibrary() const;
    const PrintFwkAgentClientApi *ResolveClientApi(void *libHandle) const;
    bool ValidateApi(const PrintFwkAgentClientApi *api) const;

    void *libHandle_ = nullptr;
    const PrintFwkAgentClientApi *api_ = nullptr;
    PrintFwkAgentClient *handle_ = nullptr;
    std::mutex mutex_;
};

} // namespace OHOS::Print

#endif // PRINT_FWK_AGENT_CLIENT_LOADER_H
