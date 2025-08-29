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

#ifndef PRINT_MODAL_UI_CALLBACK_H
#define PRINT_MODAL_UI_CALLBACK_H

#include "want.h"
#include <string>
#include <uv.h>
#include <js_native_api.h>
#include "napi/native_api.h"
#include "ability_context.h"
#include "ui_extension_context.h"

#include "print_task.h"
#include "print_context.h"

namespace OHOS {
namespace Print {

class PrintModalUICallback {
public:
    explicit PrintModalUICallback(std::shared_ptr<BaseContext> baseContext);
    void OnRelease(int32_t releaseCode);
    void OnResultForModal(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void SetSessionId(int32_t sessionId);

private:
    static napi_status CreateResultMessage(BaseContext* context, napi_value* result, uint32_t length);
    static napi_status CreatePrintResult(PrintContext* context, napi_value& result);
    static napi_value CreateBusinessError(const napi_env& env, int32_t errCode, const std::string& errMsg);
    void SendMessageBack();
    static void SendMessageBackWork(uv_work_t* work, int statusIn);
    static void CloseModalUIExtension(BaseContext *context);
    int32_t sessionId_ = 0;
    std::shared_ptr<BaseContext> baseContext = nullptr;
    bool isResultForModal = false;
};
} // namespace Print
} // namespace OHOS
#endif // PRINT_MODAL_UI_CALLBACK_H