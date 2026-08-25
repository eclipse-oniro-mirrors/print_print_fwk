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

#ifndef EDM_PRINT_POLICY_MANAGER_H
#define EDM_PRINT_POLICY_MANAGER_H

#include <mutex>
#include <string>
#include <unordered_set>
#include "nocopyable.h"
#include "print_job.h"
#include "printer_info.h"

namespace OHOS::Print {

#ifdef EDM_PRINT_POLICY_ENABLE

struct EdmPrintPolicy {
    std::unordered_set<std::string> ipWhitelist;
};

class EdmPrintPolicyManager : public NoCopyable {
public:
    static EdmPrintPolicyManager& GetInstance();

#ifdef UNIT_TEST
    friend class EdmPrintPolicyManagerTest;
#endif // UNIT_TEST

    bool IsPrintJobAllowedEdm(const PrintJob &printJob);
    bool IsPrinterAllowedEdm(const PrinterInfo &printerInfo);
    void InitPrintPolicyFromEdm(int32_t userId);
    void UpdatePrintPolicyFromEdm(const std::string &eventData);
    void OnUserSwitched(int32_t newUserId);
    void OnCurrentUserRemoved(int32_t userId);

private:
    EdmPrintPolicyManager() = default;
    ~EdmPrintPolicyManager() override = default;

    bool IsInIpWhitelist(const std::string &ip);
    bool RetryQueryFromEdm();
    bool QueryPolicyFromEdm(int32_t userId);
    void ClearCache();
    bool ParsePolicyJson(const std::string &json, EdmPrintPolicy &policy);
    std::string ResolveEffectiveUri(const PrinterInfo &printerInfo);

    mutable std::mutex mutex_;
    mutable std::mutex queryMutex_;
    EdmPrintPolicy policy_;
    bool edmQuerySuccess_ = false;
};

#endif // EDM_PRINT_POLICY_ENABLE

} // namespace OHOS::Print

#endif // EDM_PRINT_POLICY_MANAGER_H
