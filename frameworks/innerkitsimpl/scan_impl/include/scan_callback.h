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

#ifndef SCAN_CALLBACK_H
#define SCAN_CALLBACK_H
#define TDD_ENABLE 1

#include <mutex>
#include <uv.h>
#include <functional>
#include "napi/native_api.h"
#include "scan_callback_stub.h"
#include "scanner_info_helper.h"

namespace OHOS::Scan {
struct CallbackParam {
    napi_env env;
    napi_ref ref;
    std::mutex* mutexPtr;
    uint32_t state;

    bool isGetSucc;
    int32_t sizeRead;
    int32_t scanVersion;
    std::string message;

    ScanDeviceInfoTCP deviceInfoTCP;
    ScanDeviceInfo deviceInfo;
    ScanDeviceInfoSync deviceInfoSync;

    void InitialCallbackParam(napi_env &env_, napi_ref &ref_, std::mutex &mutex_);
    void SetCallbackParam(uint32_t &state, const ScanDeviceInfoTCP &deviceInfoTCP);
    void SetCallbackParam(uint32_t &state, const ScanDeviceInfo &deviceInfo);
    void SetCallbackSyncParam(uint32_t &state, const ScanDeviceInfoSync &deviceInfoSync);
    void SetCallbackParam(bool &isGetSucc, int32_t &sizeRead);
    void SetCallbackParam(int32_t &scanVersion);
    void SetCallbackParam(std::string &message);
};

struct Param {
    napi_env env;
    napi_ref callbackRef;
};

typedef std::function<void(CallbackParam* &cbParam, napi_value &callbackFunc,
    napi_value &callbackResult)> uv_work_function;

struct CallbackContext {
    CallbackParam* callBackParam;
    uv_work_function uvWorkLambda;
    void SetCallbackContext(CallbackParam* &callBackParam, uv_work_function &uvWorkLambda, std::mutex &mutex_);
};


class ScanCallback : public ScanCallbackStub {
public:
    ScanCallback(napi_env env, napi_ref ref);
    explicit ScanCallback(std::function<void(std::vector<ScanDeviceInfo> &infos)> callbackFunction);
    virtual ~ScanCallback();
    bool OnCallback(uint32_t state, const ScanDeviceInfoTCP &info) override;
    bool OnCallback(uint32_t state, const ScanDeviceInfo &info) override;
    bool OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info) override;
    bool OnGetFrameResCallback(bool isGetSucc, int32_t sizeRead) override;
    bool OnScanInitCallback(int32_t &scanVersion) override;
    bool OnSendSearchMessage(std::string &message) override;
    bool OnGetDevicesList(std::vector<ScanDeviceInfo> &info) override;
    bool ExecuteUvQueueWork(CallbackContext* &param, uv_work_t* &work, uv_loop_s* &loop);
    void CreateCallbackParam(uv_work_t *&work, CallbackParam *&param, CallbackContext *&context, bool &flag);

#ifndef TDD_ENABLE
private:
#endif
    int UvQueueWork(uv_loop_s *loop, uv_work_t *work);
    napi_env env_;
    napi_ref ref_;
    std::function<void(std::vector<ScanDeviceInfo> &infos)> callbackFunction_;
    std::mutex mutex_;
};
} // namespace OHOS::Scan

#endif // SCAN_CALLBACK_H
