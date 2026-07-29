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

#include "ability_manager_adapter_fuzzer.h"
#include "ability_manager_adapter.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_log.h"

namespace OHOS {
namespace Print {
namespace {
constexpr size_t MAX_STRING_LENGTH = 255;
constexpr int MAX_USER_ID = 100;
constexpr int MAX_REQUEST_CODE = 1000;
}  // namespace

MockRemoteObject::MockRemoteObject() : IPCObjectStub(u"mock_remote_object")
{}

MockRemoteObject::~MockRemoteObject()
{}

bool MockRemoteObject::IsProxyObject() const
{
    return false;
}

bool MockRemoteObject::CheckObjectLegality() const
{
    return true;
}

sptr<IRemoteBroker> MockRemoteObject::AsInterface()
{
    return nullptr;
}

void MockAbilityConnectCallback::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{}

void MockAbilityConnectCallback::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{}

sptr<IRemoteObject> MockAbilityConnectCallback::AsObject()
{
    return new (std::nothrow) MockRemoteObject();
}

Want CreateFuzzedWant(FuzzedDataProvider *dataProvider)
{
    Want want;
    std::string action = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    if (!action.empty()) {
        want.SetAction(action);
    }
    std::string bundleName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    if (!bundleName.empty()) {
        std::string abilityName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        if (!abilityName.empty()) {
            want.SetElementName(bundleName, abilityName);
        }
    }
    return want;
}

void TestStartAbility(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    Want want = CreateFuzzedWant(dataProvider);
    int32_t requestCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_REQUEST_CODE);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID);
    uint64_t specifiedFullTokenId = dataProvider->ConsumeIntegral<uint64_t>();
    AbilityManagerAdapter::GetInstance().StartAbility(want, requestCode, userId, specifiedFullTokenId);
}

void TestConnectAbility(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    Want want = CreateFuzzedWant(dataProvider);
    sptr<IAbilityConnection> connect = new (std::nothrow) MockAbilityConnectCallback();
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID);
    AbilityManagerAdapter::GetInstance().ConnectAbility(want, connect, userId);
}

void TestConnectAbilityWithExtensionType(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    Want want = CreateFuzzedWant(dataProvider);
    sptr<IAbilityConnection> connect = new (std::nothrow) MockAbilityConnectCallback();
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockRemoteObject();
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID);
    uint32_t extensionTypeVal = dataProvider->ConsumeIntegralInRange<uint32_t>(
        0, static_cast<uint32_t>(AppExecFwk::ExtensionAbilityType::WINDOW));
    auto extensionType = static_cast<AppExecFwk::ExtensionAbilityType>(extensionTypeVal);
    AbilityManagerAdapter::GetInstance().ConnectAbilityWithExtensionType(
        want, connect, callerToken, userId, extensionType);
}

void TestDisconnectAbility(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    sptr<IAbilityConnection> connect = new (std::nothrow) MockAbilityConnectCallback();
    AbilityManagerAdapter::GetInstance().DisconnectAbility(connect);
}

}  // namespace Print
}  // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider dataProvider(data, size);
    using TestHandler = std::function<void(const uint8_t *, size_t, FuzzedDataProvider *)>;
    PRINT_HILOGI("Multithreading is running in function LLVMFuzzerTestOneInput.");
    TestHandler tasks[] = {
        &OHOS::Print::TestStartAbility,
        &OHOS::Print::TestConnectAbility,
        &OHOS::Print::TestConnectAbilityWithExtensionType,
        &OHOS::Print::TestDisconnectAbility,
    };
    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}