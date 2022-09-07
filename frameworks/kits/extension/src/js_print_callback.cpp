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

#include "js_print_callback.h"

#include "ability_info.h"
#include "iprint_extension_callback.h"
#include "js_print_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_print_utils.h"
#include "napi_remote_object.h"
#include "print_log.h"
#include "print_manager_client.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
using namespace OHOS::Print;

JsPrintCallback::JsPrintCallback(JsRuntime &jsRuntime)
    : jsRuntime_(jsRuntime) {}

NativeValue *JsPrintCallback::Exec(NativeValue *jsObj, const std::string &name,
                                   NativeValue *const *argv, size_t argc,
                                   bool isSync) {
  HandleScope handleScope(jsRuntime_);
  NativeObject *obj = ConvertNativeValueTo<NativeObject>(jsObj);
  if (obj == nullptr) {
    PRINT_HILOGE("Failed to get PrintExtension object");
    return nullptr;
  }

  NativeValue *method = obj->GetProperty(name.c_str());
  if (method == nullptr) {
    PRINT_HILOGE("Failed to get '%{public}s' from PrintExtension object",
                 name.c_str());
    return nullptr;
  }

  PRINT_HILOGD("%{public}s callback in", name.c_str());

  NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
  uv_loop_s *loop = nullptr;
  napi_get_uv_event_loop(reinterpret_cast<napi_env>(nativeEngine), &loop);
  if (loop == nullptr) {
    PRINT_HILOGE("Failed to get uv event loop");
    return nullptr;
  }
  jsWorker_ = new (std::nothrow) uv_work_t;
  if (jsWorker_ == nullptr) {
    PRINT_HILOGE("Failed to create uv work");
    return nullptr;
  }

  container_.self = shared_from_this();
  container_.nativeEngine = nativeEngine;
  container_.jsObj = jsObj;
  container_.jsMethod = method;
  container_.argv = argv;
  container_.argc = argc;
  container_.jsResult = nullptr;
  container_.isSync = isSync;
  container_.isCompleted = false;
  jsWorker_->data = &container_;

  uv_queue_work(
      loop, jsWorker_, [](uv_work_t *work) {},
      [](uv_work_t *work, int statusInt) {
        auto container =
            reinterpret_cast<JsPrintCallback::Container *>(work->data);
        if (container != nullptr) {
          container->jsResult = container->nativeEngine->CallFunction(
              container->jsObj, container->jsMethod, container->argv,
              container->argc);
          container->isCompleted = true;
          if (container->isSync) {
            container->self = nullptr;
          } else {
            std::unique_lock<std::mutex> lock(container->self->conditionMutex_);
            container->self->syncCon_.notify_one();
          }
        }
      });
  if (isSync) {
    std::unique_lock<std::mutex> conditionLock(conditionMutex_);
    auto waitStatus = syncCon_.wait_for(
        conditionLock, std::chrono::milliseconds(SYNC_TIME_OUT),
        [this]() { return container_.isCompleted; });
    if (!waitStatus) {
      PRINT_HILOGE("print server load sa timeout");
      return nullptr;
    }
    return container_.jsResult;
  }
  return nullptr;
}
} // namespace AbilityRuntime
} // namespace OHOS
