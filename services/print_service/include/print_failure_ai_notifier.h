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

#ifndef PRINT_FAILURE_AI_NOTIFIER_H
#define PRINT_FAILURE_AI_NOTIFIER_H

#include <mutex>
#include <string>

#include "i_print_failure_ai_notifier.h"

namespace OHOS::Print {

class PrintFailureAiNotifier {
public:
    static PrintFailureAiNotifier &GetInstance();

    void HandleJobBlocked(const std::string &jobId, uint32_t subState,
        const std::string &printerName);

    void ClearJobState(const std::string &jobId);

    void Reset();

private:
    PrintFailureAiNotifier() = default;
    ~PrintFailureAiNotifier() = default;
    PrintFailureAiNotifier(const PrintFailureAiNotifier &) = delete;
    PrintFailureAiNotifier &operator=(const PrintFailureAiNotifier &) = delete;

    void EnsureLoaded();

    std::mutex mutex_;
    IPrintFailureAiNotifier *impl_ = nullptr;
};

} // namespace OHOS::Print
#endif // PRINT_FAILURE_AI_NOTIFIER_H
