/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <regex>

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "print_setting_data_helper.h"
#include "print_constant.h"
#include "print_log.h"


namespace OHOS::Print {
using namespace std;
const std::string SETTINGS_DATA_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
const std::string USER_SETTINGS_DATA_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_#UserId#?Proxy=true";
const std::string USER_SETTINGS_DATA_SECURE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_#UserId#?Proxy=true";
const std::string SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
const std::string SETTINGS_DATA_KEYWORD = "KEYWORD";
const std::string SETTINGS_DATA_VALUE = "VALUE";

PrintSettingDataHelper& PrintSettingDataHelper::GetInstance()
{
    static PrintSettingDataHelper instance;
    return instance;
}

void PrintSettingDataHelper::RegisterSettingDataObserver(const std::string &key,
    PrintSettingDataObserver::ObserverCallback &observerCallback, int32_t userId, bool isSecureSetting)
{
    PRINT_HILOGI("RegisterSettingDataObserver key: %{public}s", key.c_str());
    const std::string baseUri = BuildSettingDataUri(userId, isSecureSetting);
    sptr<PrintSettingDataObserver> observer = sptr<PrintSettingDataObserver>::MakeSptr();
    if (!observer) {
        PRINT_HILOGE("observer is nullptr for key: %{public}s", key.c_str());
        return;
    }
    observer->SetObserverCallback(observerCallback);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper(baseUri);
    if (dataShareHelper == nullptr) {
        PRINT_HILOGE("CreateDataShareHelper is nullptr for key: %{public}s", key.c_str());
        return;
    }
    Uri settingsUri = Uri(baseUri + "&key=" + key);
    PRINT_HILOGI("RegisterSettingDataObserver settingsUri: %{public}s", settingsUri.ToString().c_str());
    dataShareHelper->RegisterObserver(settingsUri, observer);
    dataShareHelper->Release();
    PRINT_HILOGI("RegisterSettingDataObserver succeed");
}

std::string PrintSettingDataHelper::BuildSettingDataUri(int32_t userId, bool isSecureSetting)
{
    std::string baseUri = SETTINGS_DATA_URI;
    if (userId != INVALID_USER_ID) {
        baseUri = isSecureSetting ? USER_SETTINGS_DATA_SECURE_URI : USER_SETTINGS_DATA_URI;
        std::regex userIdReg("#UserId#");
        baseUri = std::regex_replace(baseUri, userIdReg, std::to_string(userId));
    }
    PRINT_HILOGI("BuildSettingDataUri baseUri: %{public}s", baseUri.c_str());
    return baseUri;
}

std::shared_ptr<DataShare::DataShareHelper> PrintSettingDataHelper::CreateDataShareHelper(const std::string &uri)
{
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        PRINT_HILOGE("GetSystemAbilityManager failed");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObj = samgr->GetSystemAbility(PRINT_SERVICE_ID);
    if (remoteObj == nullptr) {
        PRINT_HILOGE("GetSystemAbility failed");
        return nullptr;
    }
    auto [ret, helper] = DataShare::DataShareHelper::Create(remoteObj, uri, SETTINGS_DATA_EXT_URI);
    if (ret != 0) {
        PRINT_HILOGE("Create data share helper failed, ret: %{public}d", ret);
        return nullptr;
    }
    return helper;
}

PrintSettingDataObserver::PrintSettingDataObserver() = default;
PrintSettingDataObserver::~PrintSettingDataObserver() = default;

void PrintSettingDataObserver::SetObserverCallback(ObserverCallback &observerCallback)
{
    observerCallback_ = observerCallback;
}

void PrintSettingDataObserver::OnChange()
{
    if (observerCallback_) {
        observerCallback_();
    }
}
}