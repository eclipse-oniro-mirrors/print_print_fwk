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

#include "print_failure_ai_notifier.h"

#include "i_print_feature.h"
#include "print_feature_plugin_manager.h"
#include "print_log.h"

namespace OHOS::Print {

PrintFailureAiNotifier &PrintFailureAiNotifier::GetInstance()
{
    static PrintFailureAiNotifier instance;
    return instance;
}

IPrintFailureAiNotifier *PrintFailureAiNotifier::GetAiInterface(IPrintFeature *feature)
{
    if (feature == nullptr) {
        return nullptr;
    }
    return static_cast<IPrintFailureAiNotifier *>(
        feature->QueryInterface(PrintFeatureIid::IID_PRINT_FAILURE_AI_NOTIFIER));
}

void PrintFailureAiNotifier::HandleJobBlocked(const std::string &jobId, uint32_t subState,
    const std::string &printerName, int32_t userId)
{
    auto guard = PrintFeaturePluginManager::GetInstance().AcquireFeature(PrintFeatureType::AI_NOTIFIER);
    auto impl = GetAiInterface(guard.Get());
    if (impl == nullptr) {
        PRINT_HILOGE("AiNotifier plugin not available");
        return;
    }
    impl->HandleJobBlocked(jobId, subState, printerName, userId);
}

void PrintFailureAiNotifier::ClearJobState(const std::string &jobId)
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    if (!manager.IsFeatureLoaded(PrintFeatureType::AI_NOTIFIER)) {
        return;
    }

    auto guard = manager.AcquireFeature(PrintFeatureType::AI_NOTIFIER);
    auto impl = GetAiInterface(guard.Get());
    if (impl == nullptr) {
        return;
    }
    impl->ClearJobState(jobId);
}

void PrintFailureAiNotifier::Reset()
{
    // No cached implementation pointer; plugin manager unloading prevents future AcquireFeature.
}

} // namespace OHOS::Print
