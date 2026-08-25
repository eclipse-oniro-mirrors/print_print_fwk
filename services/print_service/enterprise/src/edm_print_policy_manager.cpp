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

#ifdef EDM_PRINT_POLICY_ENABLE

#include "../include/edm_print_policy_manager.h"
#include <memory>
#include <json/json.h>
#include "system_manager_proxy.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "print_log.h"
#include "print_service_ability.h"
#include "print_utils.h"
#ifdef PRINT_FWK_AGENT_CLIENT_ENABLE
#include "agent/print_fwk_agent_manager.h"
#endif

namespace OHOS::Print {

namespace {

constexpr const char *PRINTER_POLICIES_KEY = "printer_policies";
constexpr const char *DEVICE_IP_KEY = "device_ip";
constexpr const char *USER_ID_KEY = "user_id";

void ParsePolicyItem(const Json::Value &item, EdmPrintPolicy &policy)
{
    if (item.isMember(DEVICE_IP_KEY) && item[DEVICE_IP_KEY].isString()) {
        std::string ip = item[DEVICE_IP_KEY].asString();
        if (!ip.empty()) {
            policy.ipWhitelist.insert(ip);
        }
    }
}

} // namespace

EdmPrintPolicyManager& EdmPrintPolicyManager::GetInstance()
{
    static EdmPrintPolicyManager instance;
    return instance;
}

bool EdmPrintPolicyManager::IsPrintJobAllowedEdm(const PrintJob &printJob)
{
    PrinterInfo printerInfo;
    PrintServiceAbility::GetInstance()->QueryAddedPrinterInfoByPrinterId(printJob.GetPrinterId(), printerInfo);
    return IsPrinterAllowedEdm(printerInfo);
}

bool EdmPrintPolicyManager::IsPrinterAllowedEdm(const PrinterInfo &printerInfo)
{
    std::string uri = ResolveEffectiveUri(printerInfo);
    if (uri.find(VIRTUAL_PRINTER_SCHEME + "://") == 0) {
        PRINT_HILOGI("Virtual printer, allow by default");
        return true;
    }
    std::string printerIp = uri.find("://") == std::string::npos ? uri : PrintUtils::ExtractIpFromUri(uri);
    return IsInIpWhitelist(printerIp);
}

void EdmPrintPolicyManager::InitPrintPolicyFromEdm(int32_t userId)
{
    PRINT_HILOGI("EdmPrintPolicyManager::InitPrintPolicyFromEdm userId=%{public}d", userId);
    QueryPolicyFromEdm(userId);
}

void EdmPrintPolicyManager::OnUserSwitched(int32_t newUserId)
{
    PRINT_HILOGI("EdmPrintPolicyManager::OnUserSwitched newUserId=%{public}d", newUserId);
    ClearCache();
    InitPrintPolicyFromEdm(newUserId);
}

void EdmPrintPolicyManager::OnCurrentUserRemoved(int32_t userId)
{
    int32_t currentUserId = PrintServiceAbility::GetInstance()->GetCurrentUserId();
    if (userId == currentUserId) {
        ClearCache();
        PRINT_HILOGI("Current user removed, clear cache for userId=%{public}d", userId);
    }
}

void EdmPrintPolicyManager::UpdatePrintPolicyFromEdm(const std::string &eventData)
{
    if (eventData.empty()) {
        PRINT_HILOGW("EDM print policy event data is empty, ignore");
        return;
    }

    Json::Value root;
    if (!PrintJsonUtil::Parse(eventData, root) ||
        !PrintJsonUtil::IsMember(root, USER_ID_KEY) ||
        !root[USER_ID_KEY].isInt()) {
        PRINT_HILOGW("Invalid EDM print policy event data, ignore");
        return;
    }

    int32_t userId = root[USER_ID_KEY].asInt();
    PRINT_HILOGI("EDM print policy update event, userId=%{public}d (-1 means all users)", userId);

    int32_t currentUserId = PrintServiceAbility::GetInstance()->GetCurrentUserId();
    if (userId != -1 && userId != currentUserId) {
        PRINT_HILOGI("Event userId=%{public}d does not match current userId=%{public}d, ignore",
            userId, currentUserId);
        return;
    }
    QueryPolicyFromEdm(currentUserId);
}

std::string EdmPrintPolicyManager::ResolveEffectiveUri(const PrinterInfo &printerInfo)
{
    std::string uri = printerInfo.HasUri() ? printerInfo.GetUri() : "";
#ifdef PRINT_FWK_AGENT_CLIENT_ENABLE
    std::string sourceUri = PrintFwkAgentManager::ExtractSourceUriFromOption(printerInfo.GetOption());
    if (!sourceUri.empty()) {
        uri = sourceUri;
    }
#endif
    return uri;
}

bool EdmPrintPolicyManager::IsInIpWhitelist(const std::string &ip)
{
    if (!RetryQueryFromEdm()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (policy_.ipWhitelist.empty()) {
        PRINT_HILOGI("IP Whitelist is empty, allow by default");
        return true;
    }
    if (ip.empty()) {
        PRINT_HILOGW("IP is empty, block by default");
        return false;
    }
    if (policy_.ipWhitelist.find(ip) != policy_.ipWhitelist.end()) {
        PRINT_HILOGI("IP %{public}s is in whitelist", PrintUtils::AnonymizeIp(ip).c_str());
        return true;
    }
    PRINT_HILOGI("IP %{public}s not in whitelist", PrintUtils::AnonymizeIp(ip).c_str());
    return false;
}

bool EdmPrintPolicyManager::RetryQueryFromEdm()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (edmQuerySuccess_) {
            return true;
        }
    }
    PRINT_HILOGW("EDM query not successful, try retry query");
    int32_t userId = PrintServiceAbility::GetInstance()->GetCurrentUserId();
    if (!QueryPolicyFromEdm(userId)) {
        PRINT_HILOGW("EDM retry query still failed, block by default");
        return false;
    }
    PRINT_HILOGW("EDM retry query successful");
    return true;
}

bool EdmPrintPolicyManager::QueryPolicyFromEdm(int32_t userId)
{
    std::lock_guard<std::mutex> queryLock(queryMutex_);
    std::string policyJson;

    ErrCode ret = OHOS::EDM::SystemManagerProxy::GetSystemManagerProxy()->
        GetPrintPolicy(std::to_string(userId), policyJson);
    if (ret != ERR_OK || policyJson.empty()) {
        PRINT_HILOGE("Query print policy from EDM failed for userId=%{public}d, ret=%{public}d, default to block all",
            userId, ret);
        std::lock_guard<std::mutex> lock(mutex_);
        policy_ = EdmPrintPolicy{};
        edmQuerySuccess_ = false;
        return false;
    }

    EdmPrintPolicy policy;
    if (!ParsePolicyJson(policyJson, policy)) {
        PRINT_HILOGE("Parse print policy json failed for userId=%{public}d, default to block all", userId);
        std::lock_guard<std::mutex> lock(mutex_);
        policy_ = EdmPrintPolicy{};
        edmQuerySuccess_ = false;
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    policy_ = std::move(policy);
    edmQuerySuccess_ = true;

    PRINT_HILOGI("Query print policy from EDM for userId=%{public}d, edmQuerySuccess=true, ipWhitelistCount=%{public}",
        userId, policy_.ipWhitelist.size());
    return true;
}

void EdmPrintPolicyManager::ClearCache()
{
    std::lock_guard<std::mutex> lock(mutex_);
    policy_ = EdmPrintPolicy{};
    edmQuerySuccess_ = false;
    PRINT_HILOGI("EdmPrintPolicyManager cache cleared");
}

bool EdmPrintPolicyManager::ParsePolicyJson(const std::string &json, EdmPrintPolicy &policy)
{
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    std::string errors;
    if (!reader->parse(json.c_str(), json.c_str() + json.length(), &root, &errors)) {
        PRINT_HILOGE("Parse print policy json failed: %{public}s", errors.c_str());
        return false;
    }

    if (!root.isObject()) {
        PRINT_HILOGE("Print policy json root is not an object");
        return false;
    }

    // Empty JSON "{}" — no policy set
    if (!root.isMember(PRINTER_POLICIES_KEY)) {
        PRINT_HILOGI("No printer_policies in json, treat as no policy set");
        return true;
    }

    const Json::Value &policies = root[PRINTER_POLICIES_KEY];
    if (!policies.isArray()) {
        PRINT_HILOGE("printer_policies is not an array");
        return false;
    }

    for (Json::ArrayIndex i = 0; i < policies.size(); ++i) {
        const Json::Value &item = policies[i];
        if (item.isObject()) {
            ParsePolicyItem(item, policy);
        }
    }

    return true;
}

} // namespace OHOS::Print

#endif // EDM_PRINT_POLICY_ENABLE
