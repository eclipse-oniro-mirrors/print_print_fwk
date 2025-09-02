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

#ifndef PRINT_SETTING_DATA_HELPER_H
#define PRINT_SETTING_DATA_HELPER_H

#include "data_ability_observer_stub.h"
#include "datashare_helper.h"

namespace OHOS::Print {
class PrintSettingDataObserver : public AAFwk::DataAbilityObserverStub {
public:
    PrintSettingDataObserver();
    ~PrintSettingDataObserver() override;
    void OnChange() override;

    using ObserverCallback = std::function<void()>;
    void SetObserverCallback(ObserverCallback &observerCallback);

private:
    ObserverCallback observerCallback_ = nullptr;
};

class PrintSettingDataHelper {
public:
    static PrintSettingDataHelper& GetInstance();
    void RegisterSettingDataObserver(const std::string &key,
        PrintSettingDataObserver::ObserverCallback &observerCallback, int32_t userId, bool isSecureSetting);

private:
    PrintSettingDataHelper() = default;
    std::string BuildSettingDataUri(int32_t userId, bool isSecureSetting);
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(const std::string &uri);
};
}
#endif // PRINT_SETTING_DATA_HELPER_H