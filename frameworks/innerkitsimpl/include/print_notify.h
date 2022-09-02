/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_NOTIFY_H
#define PRINT_NOTIFY_H

#include <string>
#include "print_notify_stub.h"
#include "napi/native_api.h"
#include "noncopyable.h"

namespace OHOS::Print {
class PrintNotify final : public PrintNotifyStub {
public:
    ACE_DISALLOW_COPY_AND_MOVE(PrintNotify);
    explicit PrintNotify(); 
    virtual ~PrintNotify();
    void OnCallBack(MessageParcel &data) override;
};
} // namespace OHOS::Print

#endif // PRINT_NOTIFY_H