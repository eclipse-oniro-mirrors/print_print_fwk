/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef I_PRINT_FAILURE_AI_NOTIFIER_H
#define I_PRINT_FAILURE_AI_NOTIFIER_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "i_print_feature.h"

namespace OHOS::Print {

class IPrintFailureAiNotifier : public IPrintFeature {
public:
    ~IPrintFailureAiNotifier() override = default;

    virtual void HandleJobBlocked(const std::string &jobId, uint32_t subState,
        const std::string &printerName, int32_t userId) = 0;
    virtual void ClearJobState(const std::string &jobId) = 0;
};

} // namespace OHOS::Print
#endif // I_PRINT_FAILURE_AI_NOTIFIER_H
