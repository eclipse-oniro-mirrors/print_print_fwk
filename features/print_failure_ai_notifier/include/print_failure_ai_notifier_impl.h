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

#ifndef PRINT_FAILURE_AI_NOTIFIER_IMPL_H
#define PRINT_FAILURE_AI_NOTIFIER_IMPL_H

#include <map>
#include <mutex>
#include <set>
#include <string>

#include "i_print_failure_ai_notifier.h"

namespace OHOS::Print {

class PrintFailureAiNotifierImpl : public IPrintFailureAiNotifier {
public:
    PrintFailureAiNotifierImpl();
    ~PrintFailureAiNotifierImpl() override = default;

    void *QueryInterface(PrintFeatureIid iid) override;

    void HandleJobBlocked(const std::string &jobId, uint32_t subState,
        const std::string &printerName) override;
    void ClearJobState(const std::string &jobId) override;

private:
    PrintFailureAiNotifierImpl(const PrintFailureAiNotifierImpl &) = delete;
    PrintFailureAiNotifierImpl &operator=(const PrintFailureAiNotifierImpl &) = delete;

    std::set<uint32_t> SplitSubState(uint32_t subState);
    void ReportFailure(uint32_t state, const std::string &printerName);

    std::map<std::string, std::set<uint32_t>> jobStateMap_;
    std::mutex jobStateMutex_;
};

} // namespace OHOS::Print
#endif // PRINT_FAILURE_AI_NOTIFIER_IMPL_H
