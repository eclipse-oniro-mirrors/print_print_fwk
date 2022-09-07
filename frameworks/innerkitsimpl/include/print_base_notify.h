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

#ifndef PRINT_BASE_NOTIFY_H
#define PRINT_BASE_NOTIFY_H

#include <string>

#include "napi/native_api.h"
#include "noncopyable.h"
#include "print_callback_stub.h"
#include "print_job.h"
#include "printer_info.h"

namespace OHOS::Print {
struct NotifyData {
  napi_env env;
  napi_ref ref;
  std::string objectType;
  std::string type;
  uint32_t firstArgv;
  PrinterInfo secondArgv;
  PrintJob thirdArgv;
};

class PrintBaseNotify : public PrintCallbackStub {
public:
  ACE_DISALLOW_COPY_AND_MOVE(PrintBaseNotify);
  explicit PrintBaseNotify(napi_env env, const std::string &type, napi_ref ref);
  virtual ~PrintBaseNotify();
  void OnCallBack(MessageParcel &data) override;

protected:
  NotifyData *GetNotifyData();

protected:
  napi_env env_;
  std::string type_;
  napi_ref ref_;
};
} // namespace OHOS::Print

#endif // PRINT_BASE_NOTIFY_H