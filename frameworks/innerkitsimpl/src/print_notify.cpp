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

#include "print_notify.h"

#include <uv.h>

#include "print_log.h"
#include "print_napi_utils.h"

namespace OHOS::Print {
PrintNotify::PrintNotify() {}

PrintNotify::~PrintNotify()
{
    PRINT_HILOGD("");
}

void PrintNotify::OnCallBack(MessageParcel &data)
{
    PRINT_HILOGD("Failed callback in");
}
} // namespace OHOS::Print
