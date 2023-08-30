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

#include "iprint_adapter_inner.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
void PrintDocumentInnerAdapter::onStartLayoutWrite(const std::string &jobId, const PrintAttributes &oldAttrs,
    const PrintAttributes &newAttrs, uint32_t fd,
    std::function<void(std::string, uint32_t)> writeResultCallback)
{
    PRINT_HILOGI("onStartLayoutWrite jobId:%{public}s", jobId.c_str());
    // 应用写layout和write file的逻辑

    //
    writeResultCallback(jobId, PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS);
}

void PrintDocumentInnerAdapter::onJobStateChanged(const std::string &jobId, uint32_t state)
{
    PRINT_HILOGI("onJobStateChanged jobId:%{public}s state:%{public}d", jobId.c_str(), state);
}
}