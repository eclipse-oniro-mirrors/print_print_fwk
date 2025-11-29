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

#include "print_state.h"
#include "print_log.h"

namespace OHOS::Print {

PrintState::PrintState(Print_OnPrintJobStateChanged callback)
{
    jobStateChangedCb_ = callback;
}

void PrintState::onJobStateChanged(const std::string &jobId, uint32_t state)
{
    if (jobStateChangedCb_ == nullptr) {
        PRINT_HILOGE("PrintState jobStateChangedCb_ is null.");
        return;
    }
    jobStateChangedCb_(jobId.c_str(), static_cast<Print_PrintJobState>(state));
}
}