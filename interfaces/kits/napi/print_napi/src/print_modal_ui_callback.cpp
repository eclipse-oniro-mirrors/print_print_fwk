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

#include "print_modal_ui_callback.h"
#include "napi_print_utils.h"

#include <uv.h>
#include <js_native_api.h>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_base_context.h"
#include "ui_content.h"

using namespace OHOS::Ace;

#define PRINT_ERROR_CODE "code"
#define PRINT_ERROR_MSG "message"

namespace OHOS {
namespace Print {

const uint32_t RESULT_LENGTH_TWO = 2;

PrintModalUICallback::PrintModalUICallback(std::shared_ptr<BaseContext> baseContext)
{
    this->baseContext = baseContext;
    PRINT_HILOGI("constructor ModalUICallback");
}

void PrintModalUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void PrintModalUICallback::OnRelease(int32_t releaseCode)
{
    PRINT_HILOGE("OnRelease enter. release code is %{public}d", releaseCode);
    if (this->baseContext == nullptr) {
        PRINT_HILOGE("OnRelease baseContext is null");
        return;
    }

    if (this->isResultForModal) {
        PRINT_HILOGE("SendMessageBack isResultForModal true.");
        return;
    }

    this->isResultForModal = true;

    this->baseContext->errorMessage.code = E_PRINT_NONE;
    SendMessageBack();
    return;
}

void PrintModalUICallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    PRINT_HILOGI("OnReceive enter.");
}

void PrintModalUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    PRINT_HILOGE("OnError enter. errorCode=%{public}d, name=%{public}s, message=%{public}s",
        code, name.c_str(), message.c_str());
    if (this->baseContext == nullptr) {
        PRINT_HILOGE("OnError baseContext is null");
        return;
    }

    if (this->isResultForModal) {
        PRINT_HILOGE("SendMessageBack isResultForModal true.");
        return;
    }

    this->isResultForModal = true;

    this->baseContext->errorMessage.code = E_PRINT_SERVER_FAILURE;
    SendMessageBack();
    return;
}

void PrintModalUICallback::OnResultForModal(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    PRINT_HILOGI("OnResultForModal enter. resultCode is %{public}d", resultCode);
    if (this->baseContext == nullptr) {
        PRINT_HILOGE("OnResultForModal baseContext is null");
        return;
    }

    if (this->isResultForModal) {
        PRINT_HILOGI("SendMessageBack isResultForModal true.");
        return;
    }

    this->isResultForModal = true;

    this->baseContext->errorMessage.code = resultCode;
    if (this->baseContext->errorMessage.code != E_PRINT_NONE) {
        this->baseContext->errorMessage.message = result.GetStringParam("message");
        PRINT_HILOGI("OnResultForModal errorMessage is %s", this->baseContext->errorMessage.message.c_str());
    }

    SendMessageBack();
    return;
}

void PrintModalUICallback::SendMessageBack()
{
    PRINT_HILOGI("SendMessageBack enter.");
    if (this->baseContext == nullptr) {
        PRINT_HILOGE("baseContext is null");
        return;
    }

    auto abilityContext = this->baseContext->context;
    auto uiExtContext = this->baseContext->uiExtensionContext;
    OHOS::Ace::UIContent* uiContent = nullptr;
    if (abilityContext != nullptr) {
        uiContent = abilityContext->GetUIContent();
    } else if (uiExtContext != nullptr) {
        uiContent = uiExtContext->GetUIContent();
    }

    if (uiContent != nullptr) {
        PRINT_HILOGE("CloseModalUIExtension");
        uiContent->CloseModalUIExtension(this->sessionId_);
    }

    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(this->baseContext->env, &loop);
    if (loop == nullptr) {
        PRINT_HILOGE("loop is nullptr");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        PRINT_HILOGE("work is nullptr");
        return;
    }
    BaseContext *printBaseContext = new (std::nothrow) BaseContext(*this->baseContext);
    if (printBaseContext == nullptr) {
        PRINT_HILOGE("printBaseContext is nullptr.");
        delete work;
        work = nullptr;
        return;
    }
    work->data = reinterpret_cast<void*>(printBaseContext);

    int ret = uv_queue_work(
        loop, work, [](uv_work_t* work) { (void)work; }, SendMessageBackWork);
    if (ret != 0) {
        PRINT_HILOGE("Failed to get uv_queue_work.");
        delete printBaseContext;
        delete work;
        work = nullptr;
    }
}

void PrintModalUICallback::SendMessageBackWork(uv_work_t* work, int statusIn)
{
    (void)statusIn;
    napi_handle_scope scope = nullptr;
    if (work == nullptr) {
        PRINT_HILOGE("work is nullptr");
        return;
    }
    BaseContext* context = reinterpret_cast<BaseContext*>(work->data);
    if (context == nullptr) {
        PRINT_HILOGE("context is null");
        delete work;
        work = nullptr;
        return;
    }

    napi_status status;
    size_t resultLength = RESULT_LENGTH_TWO;
    size_t errorIndex = NapiPrintUtils::INDEX_ZERO;
    size_t resultIndex = NapiPrintUtils::INDEX_ONE;

    napi_open_handle_scope(context->env, &scope);
    if (scope == nullptr) {
        PRINT_HILOGE("open handle scope failed");
    }

    napi_value result[2] = { nullptr };
    CreateResultMessage(context, result, resultLength);
    if (context->deferred) {
        if (context->errorMessage.code == E_PRINT_NONE) {
            status = napi_resolve_deferred(context->env, context->deferred, result[resultIndex]);
            PRINT_HILOGD("promise SUCCEED status %{public}d", (status == napi_ok));
        } else {
            status = napi_reject_deferred(context->env, context->deferred, result[errorIndex]);
            PRINT_HILOGE("promise FAILD status %{public}d", (status == napi_ok));
        }
    } else {
        napi_value callback = nullptr;
        status = napi_get_reference_value(context->env, context->callback, &callback);
        status = napi_call_function(context->env, nullptr, callback, sizeof(result) / sizeof(result[0]), result,
                                    nullptr);
        PRINT_HILOGD("callBack status %{public}d", (status == napi_ok));
    }

    PRINT_HILOGD("uv_queue_work callback success");
    napi_close_handle_scope(context->env, scope);

    // context.callback will be deleted on other share_ptr, not need delete it!
    context->callback = nullptr;
    delete context;
    context = nullptr;
    delete work;
    work = nullptr;
}

napi_status PrintModalUICallback::CreateResultMessage(BaseContext* context, napi_value* result, uint32_t length)
{
    PRINT_HILOGD("CreateResultMessage resultLength %{public}d", length);
    size_t errorIndex = NapiPrintUtils::INDEX_ZERO;
    if (length < RESULT_LENGTH_TWO) {
        PRINT_HILOGE("Result length is less than 2.");
        return napi_invalid_arg;
    }
    size_t resultIndex = NapiPrintUtils::INDEX_ONE;
    napi_status status;

    if (context == nullptr) {
        PRINT_HILOGE("context is nullptr");
        return napi_invalid_arg;
    }
    PRINT_HILOGD("errorcode: %{public}d", context->errorMessage.code);
    if (context->errorMessage.code == E_PRINT_NONE) {
        if (context->requestType == PrintRequestType::REQUEST_TYPE_START) {
            PrintContext* printContext = static_cast<PrintContext*>(context);
            CreatePrintResult(printContext, result[resultIndex]);
            status = napi_get_undefined(context->env, &result[errorIndex]);
            return status;
        }
        status = napi_get_undefined(context->env, &result[resultIndex]);
        status = napi_get_undefined(context->env, &result[errorIndex]);
        return status;
    } else {
        result[errorIndex] =
            CreateBusinessError(context->env, context->errorMessage.code, context->errorMessage.message);
        status = napi_get_undefined(context->env, &result[resultIndex]);
        return status;
    }
}

napi_status PrintModalUICallback::CreatePrintResult(PrintContext* printContext, napi_value& result)
{
    if (printContext == nullptr) {
        PRINT_HILOGE("printContext is nullptr");
        return napi_invalid_arg;
    }
    napi_status status = napi_create_object(printContext->env, &result);
    if (status != napi_ok) {
        PRINT_HILOGE("create js object failed");
    }
    return status;
}

napi_value PrintModalUICallback::CreateBusinessError(const napi_env& env, int32_t errCode, const std::string& errMsg)
{
    PRINT_HILOGD("CreateBusinessError errCode: %{public}d errMsg: %{public}s", errCode, errMsg.c_str());

    napi_value message = nullptr;
    napi_status status = napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);
    if (status != napi_ok) {
        PRINT_HILOGE("napi create errorMessage failed");
        return message;
    }

    napi_value code = nullptr;
    status = napi_create_int32(env, errCode, &code);
    if (status != napi_ok) {
        PRINT_HILOGE("napi create errorCode failed");
        return code;
    }

    napi_value businessError = nullptr;
    status = napi_create_object(env, &businessError);
    if (status != napi_ok) {
        PRINT_HILOGE("napi create businessError failed");
        return businessError;
    }

    status = napi_set_named_property(env, businessError, PRINT_ERROR_CODE, code);
    if (status != napi_ok) {
        PRINT_HILOGE("napi set errorCode failed");
    }

    status = napi_set_named_property(env, businessError, PRINT_ERROR_MSG, message);
    if (status != napi_ok) {
        PRINT_HILOGE("napi set errorMessage failed");
    }

    PRINT_HILOGI("CreateBusinessError exit");
    return businessError;
}

} // namespace Print
} // namespace OHOS