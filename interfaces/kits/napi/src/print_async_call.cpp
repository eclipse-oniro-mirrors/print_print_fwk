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

#include "print_async_call.h"

#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
PrintAsyncCall::PrintAsyncCall(napi_env env, napi_callback_info info,
                               std::shared_ptr<Context> context, size_t pos)
    : env_(env) {
  context_ = new AsyncContext();
  size_t argc = NapiPrintUtils::MAX_ARGC;
  napi_value self = nullptr;
  napi_value argv[NapiPrintUtils::MAX_ARGC] = {nullptr};
  PRINT_CALL_RETURN_VOID(
      env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));
  pos = ((pos == ASYNC_DEFAULT_POS) ? (argc - 1) : pos);
  if (pos >= 0 && pos < argc) {
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[pos], &valueType);
    if (valueType == napi_function) {
      napi_create_reference(env, argv[pos], 1, &context_->callback);
      argc = pos;
    }
  }
  context_->paramStatus = (*context)(env, argc, argv, self);
  if (context_->paramStatus == napi_ok) {
    context_->ctx = std::move(context);
    napi_create_reference(env, self, 1, &context_->self);
  }
}

PrintAsyncCall::~PrintAsyncCall() {
  if (context_ == nullptr) {
    return;
  }

  DeleteContext(env_, context_);
}

napi_value PrintAsyncCall::Call(napi_env env, Context::ExecAction exec) {
  PRINT_HILOGD("async call exec");
  if (context_->ctx != nullptr) {
    context_->ctx->exec_ = std::move(exec);
  }
  napi_value promise = nullptr;
  if (context_->callback == nullptr) {
    napi_create_promise(env, &context_->defer, &promise);
  } else {
    napi_get_undefined(env, &promise);
  }
  napi_async_work work = context_->work;
  napi_value resource = nullptr;
  napi_create_string_utf8(env, "PrintAsyncCall", NAPI_AUTO_LENGTH, &resource);
  napi_create_async_work(env, nullptr, resource, PrintAsyncCall::OnExecute,
                         PrintAsyncCall::OnComplete, context_, &work);
  context_->work = work;
  context_ = nullptr;
  napi_queue_async_work(env, work);
  PRINT_HILOGD("async call exec");
  return promise;
}

napi_value PrintAsyncCall::SyncCall(napi_env env,
                                    PrintAsyncCall::Context::ExecAction exec) {
  if (context_ != nullptr && context_->ctx != nullptr) {
    context_->ctx->exec_ = std::move(exec);
  }
  napi_value promise = nullptr;
  if (context_->callback == nullptr) {
    napi_create_promise(env, &context_->defer, &promise);
  } else {
    napi_get_undefined(env, &promise);
  }
  PrintAsyncCall::OnExecute(env, context_);
  PrintAsyncCall::OnComplete(env, napi_ok, context_);
  return promise;
}

void PrintAsyncCall::OnExecute(napi_env env, void *data) {
  AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
  if (context->ctx == nullptr) {
    PRINT_HILOGE("context->ctx is null");
    return;
  }

  PRINT_HILOGD("run the async runnable");
  if (context->ctx->GetErrorIndex() == ERROR_NONE) {
    context->ctx->Exec();
  }
}

void PrintAsyncCall::OnComplete(napi_env env, napi_status status, void *data) {
  AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
  PRINT_HILOGD("run the js callback function");
  if (context->ctx == nullptr || context->ctx->GetErrorIndex() != ERROR_NONE) {
    status = napi_generic_failure;
  }
  napi_value output = nullptr;
  napi_status runStatus = napi_generic_failure;
  if (context->ctx != nullptr) {
    runStatus = (*context->ctx)(env, &output);
  }
  PRINT_HILOGD("runStatus: [%{public}d], status: [%{public}d]", runStatus,
               status);

  napi_value result[ARG_BUTT] = {0};
  if (status == napi_ok && runStatus == napi_ok) {
    napi_get_undefined(env, &result[ARG_ERROR]);
    if (output != nullptr) {
      result[ARG_DATA] = output;
      PRINT_HILOGD("async call napi_ok.");
    } else {
      napi_get_undefined(env, &result[ARG_DATA]);
      PRINT_HILOGD("async call napi_ok, but output is nullptr.");
    }
  } else {
    napi_value message = nullptr;
    uint32_t errorIndex = ERROR_NONE;
    if (context->paramStatus != napi_ok) {
      errorIndex = ERROR_INVALID_PARAMETER;
    } else {
      errorIndex = context->ctx->GetErrorIndex();
    }
    PRINT_HILOGE("ErrorMessage: [%{public}s], ErrorIndex:[%{public}d]",
                 ErrorMessage[errorIndex].c_str(), errorIndex);
    napi_create_uint32(env, errorIndex, &message);
    PRINT_HILOGE("async call failed. creating errors...");
    result[ARG_ERROR] = message;
    napi_get_undefined(env, &result[ARG_DATA]);
  }
  if (context->defer != nullptr) {
    // promise
    if (status == napi_ok && runStatus == napi_ok) {
      PRINT_HILOGD("async_call napi_resolve_deferred is running.");
      napi_resolve_deferred(env, context->defer, result[ARG_DATA]);
    } else {
      PRINT_HILOGD("async_call napi_reject_deferred is running.");
      napi_reject_deferred(env, context->defer, result[ARG_ERROR]);
    }
  } else {
    // callback
    napi_value callback = nullptr;
    PRINT_HILOGD("async_call napi_get_reference_value is running.");
    napi_get_reference_value(env, context->callback, &callback);
    napi_value returnValue;
    napi_call_function(env, nullptr, callback, ARG_BUTT, result, &returnValue);
  }
  DeleteContext(env, context);
}
void PrintAsyncCall::DeleteContext(napi_env env, AsyncContext *context) {
  if (env != nullptr) {
    napi_delete_reference(env, context->callback);
    napi_delete_reference(env, context->self);
    napi_delete_async_work(env, context->work);
  }
  delete context;
}
} // namespace OHOS::Print