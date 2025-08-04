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

#include "scan_async_call.h"
#include "napi_scan_utils.h"
#include "scan_log.h"

namespace OHOS::Scan {
ScanAsyncCall::ScanAsyncCall(napi_env env, napi_callback_info info,
    std::shared_ptr<Context> context) : env_(env)
{
    context_ = new AsyncContext();
    size_t argc = NapiScanUtils::MAX_ARGC;
    napi_value self = nullptr;
    napi_value argv[NapiScanUtils::MAX_ARGC] = { nullptr };
    SCAN_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));
    context_->paramStatus = (*context)(env, argc, argv, self);
    context_->ctx = std::move(context);
    napi_create_reference(env, self, 1, &context_->self);
}

ScanAsyncCall::~ScanAsyncCall()
{
    if (context_ == nullptr) {
        return;
    }

    DeleteContext(env_, context_);
}

napi_value ScanAsyncCall::Call(napi_env env, Context::ExecAction exec)
{
    SCAN_HILOGD("async call exec");
    if (context_ != nullptr && context_->ctx != nullptr) {
        context_->ctx->exec_ = std::move(exec);
    } else {
        SCAN_HILOGE("context_ is null or context->ctx is null");
        return nullptr;
    }
    napi_value promise = nullptr;
    napi_create_promise(env, &context_->defer, &promise);
    napi_async_work work = context_->work;
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "ScanAsyncCall", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource, ScanAsyncCall::OnExecute,
        ScanAsyncCall::OnComplete, context_, &work);
    context_->work = work;
    context_ = nullptr;
    napi_queue_async_work(env, work);
    return promise;
}

void ScanAsyncCall::OnExecute(napi_env env, void *data)
{
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    if (context == nullptr || context->ctx == nullptr) {
        SCAN_HILOGE("context->ctx is null");
        return;
    }

    SCAN_HILOGD("run the async runnable");
    if (context->ctx->GetErrorIndex() == E_SCAN_NONE) {
        context->ctx->Exec();
    }
}

void ScanAsyncCall::PrepareSuccessResult(napi_env env, napi_value output, napi_value result[])
{
    napi_get_undefined(env, &result[ARG_ERROR]);
    if (output != nullptr) {
        result[ARG_DATA] = output;
        SCAN_HILOGD("async call napi_ok.");
    } else {
        napi_get_undefined(env, &result[ARG_DATA]);
    }
}

void ScanAsyncCall::PrepareErrorResult(napi_env env, const AsyncContext* context, napi_value result[])
{
    uint32_t errorCode = E_SCAN_GENERIC_FAILURE;
    if (context->paramStatus != napi_ok) {
        errorCode = E_SCAN_INVALID_PARAMETER;
    }
    if (context->ctx != nullptr) {
        errorCode = context->ctx->GetErrorIndex();
    }
    std::string errorMessage;
    NapiScanUtils::SetErrorText(errorCode, errorMessage);
    SCAN_HILOGE("ErrorMessage: [%{public}s], ErrorIndex:[%{public}d]",
        errorMessage.c_str(), errorCode);

    napi_value businessError = nullptr;
    napi_create_object(env, &businessError);
    
    napi_value codeValue = nullptr;
    napi_create_uint32(env, errorCode, &codeValue);
    napi_set_named_property(env, businessError, "code", codeValue);
        
    if (!errorMessage.empty()) {
        napi_value messageValue = nullptr;
        napi_create_string_utf8(env, errorMessage.c_str(), errorMessage.length(), &messageValue);
        napi_set_named_property(env, businessError, "message", messageValue);
    }

    result[ARG_ERROR] = businessError;
    napi_get_undefined(env, &result[ARG_DATA]);
}

void ScanAsyncCall::OnComplete(napi_env env, napi_status status, void *data)
{
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    if (context == nullptr) {
        SCAN_HILOGE("OnComplete called with null context");
        return;
    }
    if (context->ctx == nullptr || context->ctx->GetErrorIndex() != E_SCAN_NONE) {
        status = napi_generic_failure;
    }
    napi_value output = nullptr;
    napi_status runStatus = napi_generic_failure;
    if (context->ctx != nullptr) {
        runStatus = (*context->ctx)(env, &output);
    }
    SCAN_HILOGD("runStatus: [%{public}d], status: [%{public}d]", runStatus, status);
    napi_value result[ARG_BUTT] = { 0 };
    if (status == napi_ok && runStatus == napi_ok) {
        PrepareSuccessResult(env, output, result);
    } else {
        PrepareErrorResult(env, context, result);
    }
    if (status == napi_ok && runStatus == napi_ok) {
        napi_resolve_deferred(env, context->defer, result[ARG_DATA]);
    } else {
        napi_reject_deferred(env, context->defer, result[ARG_ERROR]);
    }
    DeleteContext(env, context);
}

void ScanAsyncCall::DeleteContext(napi_env env, AsyncContext *context)
{
    if (context == nullptr) {
        return;
    }
    if (context->work != nullptr) {
        napi_delete_async_work(env, context->work);
    }
    if (context->self != nullptr) {
        napi_delete_reference(env, context->self);
    }
    delete context;
    context = nullptr;
}
} // namespace OHOS::Scan
