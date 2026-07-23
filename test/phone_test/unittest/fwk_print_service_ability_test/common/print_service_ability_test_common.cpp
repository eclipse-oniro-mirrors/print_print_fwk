/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "print_service_ability_test_common.h"

#include "print_service_mock_permission.h"

namespace OHOS {
uint32_t uid_ = 0;
pid_t IPCSkeleton::GetCallingUid()
{
    return uid_;
}

namespace Print {
REGISTER_SYSTEM_ABILITY_BY_ID(PrintServiceAbility, PRINT_SERVICE_ID, true);

void PrintServiceAbilityTest::SetUpTestCase(void)
{
    PrintServiceMockPermission::MockPermission();
}

void PrintServiceAbilityTest::TearDownTestCase(void)
{}

void PrintServiceAbilityTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGE("PrintServiceAbilityTest_%{public}d", ++testNo);
    parameterSaved = OHOS::system::GetParameter(ENTERPRISE_SPACE_PARAM, "");
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, "");
    // 确保 instance_ 非空，防止 OnStart/ManualStart 将 instance_ 设为
    // shared_ptr 管理的对象。sptr 和 shared_ptr 引用计数不共享：
    // 若 OnStart 把 instance_（sptr）指向 shared_ptr 管理的对象，
    // 用例结束后 shared_ptr 析构会释放对象，而 instance_（sptr）
    // 仍指向已释放的内存 → use-after-free。
    // 预先创建一个 sptr 管理的 dummy service 占位，OnStart 看到
    // instance_ != nullptr 就跳过赋值，从而避免上述问题。
    if (PrintServiceAbility::instance_ == nullptr) {
        PrintServiceAbility::instance_ = new PrintServiceAbility(PRINT_SERVICE_ID, true);
    }
}

std::shared_ptr<PrintServiceAbility> PrintServiceAbilityTest::CreateService()
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*helper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*helper, QueryAccounts(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int>{100}), Return(true)));
    service->SetHelper(helper);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    return service;
}

std::shared_ptr<PrintServiceAbility> PrintServiceAbilityTest::CreateMockService(
    std::shared_ptr<MockPrintServiceHelper> &mockHelper)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    mockHelper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_CALL(*mockHelper, CheckPermission(_))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mockHelper, QueryAccounts(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int>{100}), Return(true)));
    service->SetHelper(mockHelper);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    return service;
}

void PrintServiceAbilityTest::TearDown(void)
{
    OHOS::system::SetParameter(ENTERPRISE_SPACE_PARAM, parameterSaved);
    // 停止 PrintCallerAppMonitor 线程：用例可能通过 ManualStart→OnStart→Init→
    // StartCallerAppMonitor 启动 detach 线程，lambda 捕获 service 的 this。
    // 用例结束后 service 析构，this 悬空。delayUnload_=true 让线程跳过
    // unloadTask() 调用，isMonitoring_=false 让线程退出循环。
    auto& monitor = PrintCallerAppMonitor::GetInstance();
    monitor.delayUnload_.store(true);
    monitor.isMonitoring_.store(false);
    // 清理 BMS 单例的 helper，防止 gmock 泄漏
    std::shared_ptr<PrintServiceHelper> nullHelper;
    DelayedSingleton<PrintBMSHelper>::GetInstance()->SetHelper(nullHelper);
}

std::string PrintServiceAbilityTest::GetExtensionId(EXTENSION_ID_TYPE type)
{
    switch (type) {
        case TYPE_DEFAULT:
            return DEFAULT_EXTENSION_ID;

        case TYPE_UNLOAD:
            return UNLOAD_EXTENSION_ID;

        case TYPE_NON_EXIST:
            return NONEXIST_EXTENSION_ID;

        default:
            break;
    }
    return DEFAULT_EXTENSION_ID;
}

std::string PrintServiceAbilityTest::GetDefaultTaskId()
{
    return std::to_string(0);
}

std::string PrintServiceAbilityTest::GetDefaultJobId()
{
    return std::to_string(0);
}

std::string PrintServiceAbilityTest::GetDefaultPrinterId()
{
    return PrintUtils::GetGlobalId(DEFAULT_EXTENSION_ID, DEFAULT_EXT_PRINTER_ID);
}

std::string PrintServiceAbilityTest::GetInvalidPrinterId()
{
    return PrintUtils::GetGlobalId(DEFAULT_EXTENSION_ID, "wrong printer id");
}

void PrintServiceAbilityTest::InitExtPrinterList(std::vector<PrinterInfo> &printerList, size_t count)
{
    printerList.clear();
    PrinterInfo info;
    info.SetPrinterId(DEFAULT_EXT_PRINTER_ID);
    printerList.emplace_back(info);
    if (printerList.size() < count) {
        info.SetPrinterId(DEFAULT_EXT_PRINTER_ID2);
        printerList.emplace_back(info);
    }
}

void PrintServiceAbilityTest::InitPrinterList(std::vector<PrinterInfo> &printerList, size_t count)
{
    printerList.clear();
    PrinterInfo info;
    info.SetPrinterId(PrintUtils::GetGlobalId(DEFAULT_EXTENSION_ID, DEFAULT_EXT_PRINTER_ID));
    printerList.emplace_back(info);
    if (printerList.size() < count) {
        info.SetPrinterId(PrintUtils::GetGlobalId(DEFAULT_EXTENSION_ID, DEFAULT_EXT_PRINTER_ID2));
        printerList.emplace_back(info);
    }
}

void PrintServiceAbilityTest::InitExtPrinterIdList(std::vector<std::string> &idList, size_t count)
{
    idList.clear();
    idList.emplace_back(DEFAULT_EXT_PRINTER_ID);
    if (idList.size() < count) {
        idList.emplace_back(DEFAULT_EXT_PRINTER_ID2);
    }
}

void PrintServiceAbilityTest::InitFileList(std::vector<std::string> &fileList)
{
    fileList.emplace_back(DEFAULT_PRINT_FILE_A);
    fileList.emplace_back(DEFAULT_PRINT_FILE_B);
    fileList.emplace_back(DEFAULT_PRINT_FILE_C);
}

void PrintServiceAbilityTest::InitExtensionList(
    std::vector<AppExecFwk::ExtensionAbilityInfo> &extList)
{
    std::vector<std::string> nameList = {DEFAULT_EXTENSION_ID, UNLOAD_EXTENSION_ID};
    AppExecFwk::ExtensionAbilityInfo loadInfo;
    for (size_t index = 0; index < nameList.size(); index++) {
        loadInfo.bundleName = nameList[index];
        loadInfo.moduleName = nameList[index];
        loadInfo.name = nameList[index];
        extList.emplace_back(loadInfo);
    }
}
}  // namespace Print
}  // namespace OHOS
