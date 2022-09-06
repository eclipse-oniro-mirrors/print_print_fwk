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

#ifndef PRINT_PROGRESS_NOTIFY_H
#define PRINT_PROGRESS_NOTIFY_H

#include <string>

#include "napi/native_api.h"
#include "noncopyable.h"
#include "print_base_notify.h"

namespace OHOS::Print {
class PrintProgressNotify final : public PrintBaseNotify {
public:
    ACE_DISALLOW_COPY_AND_MOVE(PrintProgressNotify);

    explicit PrintProgressNotify(napi_env env, const std::string &type, napi_ref ref);
    virtual ~PrintProgressNotify();
    static void DataReadInfo(PrinterInfo &info, MessageParcel &data);
    static void DataReadJob(PrintJob &job, MessageParcel &data);
    static void WriteInfoJsObject(napi_env env, PrinterInfo info, napi_value *result);
    static void WriteJobJsObject(napi_env env, PrintJob job, napi_value *result);
    void OnCallBack(MessageParcel &data) override;
};
} // namespace OHOS::Print

#endif // PRINT_PROGRESS_NOTIFY_H