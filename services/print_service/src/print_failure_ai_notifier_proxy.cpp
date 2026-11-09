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

void PrintFailureAiNotifier::EnsureLoaded()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (impl_ != nullptr) {
        return;
    }

    auto base = PrintFeaturePluginManager::GetInstance().GetFeature(PrintFeatureType::AI_NOTIFIER);
    if (base == nullptr) {
        PRINT_HILOGE("AiNotifier plugin not loaded");
        return;
    }

    impl_ = static_cast<IPrintFailureAiNotifier *>(
        base->QueryInterface(PrintFeatureIid::IID_PRINT_FAILURE_AI_NOTIFIER));
    if (impl_ == nullptr) {
        PRINT_HILOGE("AiNotifier plugin does not implement IPrintFailureAiNotifier");
    }
}

void PrintFailureAiNotifier::HandleJobBlocked(const std::string &jobId, uint32_t subState,
    const std::string &printerName)
{
    EnsureLoaded();
    if (impl_ != nullptr) {
        impl_->HandleJobBlocked(jobId, subState, printerName);
    }
}

void PrintFailureAiNotifier::ClearJobState(const std::string &jobId)
{
    if (impl_ == nullptr) {
        return;
    }
    impl_->ClearJobState(jobId);
}

void PrintFailureAiNotifier::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    impl_ = nullptr;
}

} // namespace OHOS::Print
