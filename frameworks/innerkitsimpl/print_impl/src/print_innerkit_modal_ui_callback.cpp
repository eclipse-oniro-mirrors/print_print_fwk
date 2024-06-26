/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "print_innerkit_modal_ui_callback.h"
#include "napi_print_utils.h"
#include "print_log.h"

#include "ui_content.h"

using namespace OHOS::Ace;

namespace OHOS {
namespace Print {

PrintInnerkitModalUICallback::PrintInnerkitModalUICallback(OHOS::Ace::UIContent *uiContent)
{
    this->uiContent = uiContent;
    PRINT_HILOGD("constructor ModalUICallback");
}

void PrintInnerkitModalUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void PrintInnerkitModalUICallback::OnRelease(int32_t releaseCode)
{
    PRINT_HILOGD("OnRelease enter. release code is %{public}d", releaseCode);
    if (this->uiContent == nullptr) {
        PRINT_HILOGE("OnRelease uiContent is null");
        return;
    }

    PRINT_HILOGI("CloseModalUIExtension");
    this->uiContent->CloseModalUIExtension(this->sessionId_);
    return;
}

void PrintInnerkitModalUICallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    PRINT_HILOGD("OnReceive enter.");
}

void PrintInnerkitModalUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    PRINT_HILOGE("OnError enter. errorCode=%{public}d, name=%{public}s, message=%{public}s",
        code, name.c_str(), message.c_str());
    if (this->uiContent == nullptr) {
        PRINT_HILOGE("OnError uiContent is null");
        return;
    }

    PRINT_HILOGI("CloseModalUIExtension");
    this->uiContent->CloseModalUIExtension(this->sessionId_);
    return;
}

void PrintInnerkitModalUICallback::OnResultForModal(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    PRINT_HILOGD("OnResultForModal enter.");
}
} // namespace Print
} // namespace OHOS