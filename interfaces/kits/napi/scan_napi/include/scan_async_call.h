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
#ifndef SCAN_ASYNC_CALL_H
#define SCAN_ASYNC_CALL_H

#include <functional>
#include <memory>
#include <unordered_map>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "scan_constant.h"
#define TDD_ENABLE 1

namespace OHOS::Scan {
struct AsyncResult {
    napi_value error = nullptr;
    napi_value data = nullptr;
};

class ScanAsyncCall final {
public:
    class Context {
    public:
        using InputAction = std::function<napi_status(napi_env, size_t, napi_value *, napi_value)>;
        using OutputAction = std::function<napi_status(napi_env, napi_value *)>;
        using ExecAction = std::function<void(Context *)>;
        Context(InputAction input, OutputAction output) : input_(std::move(input)), output_(std::move(output)) {};

        virtual ~Context() {};
        void SetAction(InputAction input, OutputAction output = nullptr)
        {
            input_ = input;
            output_ = output;
        }

        void SetAction(OutputAction output)
        {
            SetAction(nullptr, std::move(output));
        }

        virtual napi_status operator()(napi_env env, size_t argc, napi_value *argv, napi_value self)
        {
            if (input_ == nullptr) {
                return napi_ok;
            }
            return input_(env, argc, argv, self);
        }

        virtual napi_status operator()(napi_env env, napi_value *result)
        {
            if (output_ == nullptr) {
                *result = nullptr;
                return napi_ok;
            }
            return output_(env, result);
        }

        virtual void Exec()
        {
            if (exec_ == nullptr) {
                return;
            }
            exec_(this);
        };

        void SetErrorIndex(uint32_t errorIndex)
        {
            errorIndex_ = errorIndex;
        }

        uint32_t GetErrorIndex()
        {
            return errorIndex_;
        }
    #ifndef TDD_ENABLE
    protected:
    #endif
        friend class ScanAsyncCall;
        InputAction input_ = nullptr;
        OutputAction output_ = nullptr;
        ExecAction exec_ = nullptr;
        uint32_t errorIndex_ = E_SCAN_NONE;
    };

    ScanAsyncCall(napi_env env, napi_callback_info info, std::shared_ptr<Context> context);
    ~ScanAsyncCall();
    napi_value Call(napi_env env, Context::ExecAction exec);

#ifndef TDD_ENABLE
private:
#endif
    static void OnExecute(napi_env env, void *data);
    static void OnComplete(napi_env env, napi_status status, void *data);
    static std::string GetErrorText(uint32_t code);
    struct AsyncContext {
        std::shared_ptr<Context> ctx = nullptr;
        napi_ref self = nullptr;
        napi_deferred defer = nullptr;
        napi_async_work work = nullptr;
        napi_status paramStatus = napi_ok;
    };
    static void PrepareSuccessResult(napi_env env, napi_value output, AsyncResult& result);
    static void PrepareErrorResult(napi_env env, const AsyncContext* context, AsyncResult& result);
    static void DeleteContext(napi_env env, AsyncContext *context);
    static void SetErrorText(uint32_t& code, std::string& message);

    AsyncContext *context_ = nullptr;
    napi_env env_ = nullptr;
};
} // namespace OHOS::Scan
#endif // REQUEST_ASYNC_CALL_H
