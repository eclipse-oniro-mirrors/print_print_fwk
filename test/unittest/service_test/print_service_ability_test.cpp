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

#include <gtest/gtest.h>
#include "mock_print_service_helper.h"
#include "mock_bundle_mgr.h"
#include "print_service_ability.h"
#include "print_constant.h"
#include "system_ability_definition.h"
#include "print_utils.h"
#include "mock_print_extension_callback_proxy.h"
#include "mock_print_callback_proxy.h"
#include "print_service_mock_permission.h"

using namespace testing;
using namespace testing::ext;

constexpr int32_t TEST_VALUE_HUNDRED = 100;
constexpr int32_t TEST_VALUE_THOUSAND = 1000;
constexpr int32_t FDLIST_TEST_ONE = 1;
constexpr int32_t FDLIST_TEST_TWO = 2;
constexpr int32_t FDLIST_TEST_THREE = 3;

namespace OHOS {
namespace Print {
static constexpr const char *DEFAULT_EXTENSION_ID = "com.example.ext";
static constexpr const char *UNLOAD_EXTENSION_ID = "com.example.ext.unload";
static constexpr const char *NONEXIST_EXTENSION_ID = "com.example.ext.nonexist";
static constexpr const char *DEFAULT_EXT_PRINTER_ID = "https://10.10.10.10/FE8083DCD35F";
static constexpr const char *DEFAULT_EXT_PRINTER_ID2 = "https://10.10.10.10/0FDA6E208473";
static constexpr const char *DEFAULT_PRINT_FILE_A = "file://data/print/a.png";
static constexpr const char *DEFAULT_PRINT_FILE_B = "file://data/print/b.png";
static constexpr const char *DEFAULT_PRINT_FILE_C = "file://data/print/c.png";

static constexpr const char *PRINTER_EVENT_TYPE = "printerStateChange";
static constexpr const char *PRINTJOB_EVENT_TYPE = "jobStateChange";
static constexpr const char *EXTINFO_EVENT_TYPE = "extInfoChange";
static constexpr const char *EVENT_BLOCK = "block";
static constexpr const char *EVENT_SUCCESS = "succeed";
static constexpr const char *EVENT_FAIL = "fail";
static constexpr const char *EVENT_CANCEL = "cancel";
static constexpr const char *DEFAULT_EXT_INFO = "custom extension info";
enum EXTENSION_ID_TYPE {
    TYPE_DEFAULT,
    TYPE_UNLOAD,
    TYPE_NON_EXIST,
};
class PrintServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::string GetExtensionId(EXTENSION_ID_TYPE type);
    std::string GetDefaultTaskId();
    std::string GetDefaultJobId();
    std::string GetInvalidJobId();
    std::string GetDefaultPrinterId();
    std::string GetInvalidPrinterId();
    void InitExtPrinterList(std::vector<PrinterInfo> &printerList, size_t count);
    void InitPrinterList(std::vector<PrinterInfo> &printerList, size_t count);
    void InitExtPrinterIdList(std::vector<std::string> &idList, size_t count);
    void InitFileList(std::vector<std::string> &fileList);
    void InitFdList(std::vector<uint32_t> &fdList);
    void InitExtensionList(std::vector<AppExecFwk::ExtensionAbilityInfo>& extList);
    std::shared_ptr<MockPrintServiceHelper> CreatePrintServiceHelper(bool hasPermission,
                                        bool hasBundleMgr, bool hasAccountMgr, bool hasAbilityMgr);
    sptr<IPrintExtensionCallback> CreateExtCallback(bool hasCb, bool hasPrinterCb, bool hasJobCb, bool hasCapCb);
    sptr<IPrintCallback> CreateCallback(bool hasCb, bool hasPrinterCb, bool hasJobCb, bool hasExtCb);
    std::shared_ptr<PrintServiceAbility> CreateService();
    std::shared_ptr<PrintServiceAbility> CreateServiceWithoutEvent(int32_t ignoreEventType);

private:
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    sptr<MockBundleMgr> obj = nullptr;
};

void PrintServiceAbilityTest::SetUpTestCase(void) {}

void PrintServiceAbilityTest::TearDownTestCase(void) {}

void PrintServiceAbilityTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGE("PrintServiceAbilityTest_%{public}d", ++testNo);
}

void PrintServiceAbilityTest::TearDown(void) {}

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

std::string PrintServiceAbilityTest::GetInvalidJobId()
{
    return std::to_string(TEST_VALUE_THOUSAND);
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

void PrintServiceAbilityTest::InitFdList(std::vector<uint32_t> &fdList)
{
    fdList.emplace_back(FDLIST_TEST_ONE);
    fdList.emplace_back(FDLIST_TEST_TWO);
    fdList.emplace_back(FDLIST_TEST_THREE);
}

void PrintServiceAbilityTest::InitExtensionList(std::vector<AppExecFwk::ExtensionAbilityInfo>& extList)
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

std::shared_ptr<MockPrintServiceHelper> PrintServiceAbilityTest::CreatePrintServiceHelper(bool hasPermission,
    bool hasBundleMgr, bool hasAccountMgr, bool hasAbilityMgr)
{
    auto helper = std::make_shared<MockPrintServiceHelper>();
    EXPECT_NE(helper, nullptr);
    EXPECT_CALL(*helper, CheckPermission(_)).WillRepeatedly(Return(hasPermission));
    EXPECT_CALL(*helper, IsSyncMode()).WillRepeatedly(Return(true));
    ON_CALL(*helper, QueryAccounts).WillByDefault(
        [hasAccountMgr](std::vector<int> &accountList) {
            accountList.emplace_back(TEST_VALUE_HUNDRED);
            PRINT_HILOGE("QueryAccounts End");
            return hasAccountMgr;
        }
    );
    EXPECT_CALL(*helper, StartAbility(_)).WillRepeatedly(Return(hasAbilityMgr));
    if (hasBundleMgr) {
        obj = new (std::nothrow) MockBundleMgr();
        EXPECT_NE(obj, nullptr);
        ON_CALL(*helper, QueryExtension).WillByDefault(
            [this](sptr<AppExecFwk::IBundleMgr>, int userId,
                std::vector<AppExecFwk::ExtensionAbilityInfo>& extList) -> bool {
                InitExtensionList(extList);
                if (extList.size() > 0) {
                    PRINT_HILOGE("extList[0]: %{public}s", extList[0].bundleName.c_str());
                }
                PRINT_HILOGE("QueryExtension End");
                return true;
            });
        ON_CALL(*helper, QueryNameForUid).WillByDefault(
            [this](sptr<AppExecFwk::IBundleMgr>, int32_t, std::string &bundleName) -> bool {
                bundleName = GetExtensionId(TYPE_DEFAULT);
                PRINT_HILOGE("QueryNameForUid End");
                return true;
            });
        EXPECT_CALL(*obj, IsProxyObject()).WillRepeatedly(Return(true));
        EXPECT_CALL(*obj, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(*obj, AddDeathRecipient(_)).WillRepeatedly(
            [this](const sptr<IRemoteObject::DeathRecipient> &recipient) {
                deathRecipient = recipient;
                return true;
            });
        ON_CALL(*helper, GetBundleMgr).WillByDefault(
            [this] () -> sptr<IRemoteObject> {
                PRINT_HILOGE("GetBundleMgr End");
                return obj;
            });
    } else {
        EXPECT_CALL(*helper, GetBundleMgr()).WillRepeatedly(Return(nullptr));
    }
    return helper;
}

MATCHER_P(PrinterInfoMatcher, oParam, "Match Printer Info")
{
    const PrinterInfo& op = (const PrinterInfo&)arg;
    return op.GetPrinterId() == oParam.GetPrinterId();
}

MATCHER_P(PrintJobMatcher, oParam, "Match Print Job")
{
    const PrintJob& op = (const PrintJob&)arg;
    return op.GetJobId() == oParam.GetJobId();
}

sptr<IPrintExtensionCallback> PrintServiceAbilityTest::CreateExtCallback(bool hasCb,
    bool hasPrinterCb, bool hasJobCb, bool hasCapCb)
{
    auto listener = new (std::nothrow) MockPrintExtensionCallbackProxy();
    EXPECT_NE(listener, nullptr);
    EXPECT_CALL(*listener, OnCallback()).WillRepeatedly(Return(hasCb));
    auto testPrinterId = PrintUtils::GetGlobalId(GetExtensionId(TYPE_DEFAULT), DEFAULT_EXT_PRINTER_ID);
    EXPECT_CALL(*listener, OnCallback(testPrinterId)).WillRepeatedly(Return(hasPrinterCb));

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    EXPECT_CALL(*listener, OnCallback(Matcher<const PrintJob&>(PrintJobMatcher(testJob))))
    .WillRepeatedly(Return(hasJobCb));
    EXPECT_CALL(*listener, OnCallback(_, _)).WillRepeatedly(Return(hasCapCb));
    return listener;
}

sptr<IPrintCallback> PrintServiceAbilityTest::CreateCallback(bool hasCb,
    bool hasPrinterCb, bool hasJobCb, bool hasExtCb)
{
    auto listener = new (std::nothrow) MockPrintCallbackProxy();
    EXPECT_NE(listener, nullptr);
    EXPECT_CALL(*listener, OnCallback()).WillRepeatedly(Return(hasCb));

    PrinterInfo info;
    info.SetPrinterId(PrintUtils::GetGlobalId(GetExtensionId(TYPE_DEFAULT), DEFAULT_EXT_PRINTER_ID));
    EXPECT_CALL(*listener, OnCallback(_,
        Matcher<const PrinterInfo&>(PrinterInfoMatcher(info)))).WillRepeatedly(Return(hasPrinterCb));

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    EXPECT_CALL(*listener, OnCallback(_,
        Matcher<const PrintJob&>(PrintJobMatcher(testJob)))).WillRepeatedly(Return(hasJobCb));
    EXPECT_CALL(*listener, OnCallback(GetExtensionId(TYPE_DEFAULT), _)).WillRepeatedly(Return(hasExtCb));
    return listener;
}

std::shared_ptr<PrintServiceAbility> PrintServiceAbilityTest::CreateService()
{
    return CreateServiceWithoutEvent(PRINT_EXTCB_MAX);
}

std::shared_ptr<PrintServiceAbility> PrintServiceAbilityTest::CreateServiceWithoutEvent(int32_t ignoreEventType)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<std::string> fileList = {};
    InitFileList(fileList);
    std::vector<uint32_t> fdList = {};
    InitFdList(fdList);
    std::string taskId = "";
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_NONE);

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);
    auto eventCount = static_cast<int32_t>(PRINT_EXTCB_MAX - PRINT_EXTCB_START_DISCOVERY);
    for (int32_t index = 0; index < eventCount; index++) {
        auto eventType = PRINT_EXTCB_START_DISCOVERY + index;
        if (eventType == ignoreEventType) {
            continue;
        }
        auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), eventType);
        auto listener = CreateExtCallback(true, true, true, true);
        EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_NONE);
    }

    std::vector<std::string> taskEvent = {EVENT_BLOCK, EVENT_SUCCESS, EVENT_FAIL, EVENT_CANCEL};
    for (size_t index = 0; index < taskEvent.size(); index++) {
        sptr<IPrintCallback> listener = CreateCallback(true, true, true, true);
        EXPECT_EQ(service->On(taskId, taskEvent[index], listener), E_PRINT_NONE);
    }

    std::vector<std::string> spoolerEvent = {PRINTER_EVENT_TYPE, PRINTJOB_EVENT_TYPE, EXTINFO_EVENT_TYPE};
    for (size_t index = 0; index < spoolerEvent.size(); index++) {
        sptr<IPrintCallback> listener = CreateCallback(true, true, true, true);
        EXPECT_EQ(service->On("", spoolerEvent[index], listener), E_PRINT_NONE);
    }
    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_DEFAULT)), E_PRINT_NONE);
    return service;
}

/**
* @tc.name: PrintServiceAbilityTest_0001
* @tc.desc: PrintServiceAbility ctor/dtor
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0001, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->~PrintServiceAbility();
}

/**
* @tc.name: PrintServiceAbilityTest_0002
* @tc.desc: StartPrint: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0002, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    int result = PrintServiceAbility::GetInstance()->StartPrint(fileList, fdList, taskId);
    EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
    std::shared_ptr<PrintServiceHelper> helper = nullptr;
    PrintServiceAbility::GetInstance()->SetHelper(helper);
    result = PrintServiceAbility::GetInstance()->StartPrint(fileList, fdList, taskId);
    EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0003
* @tc.desc: StartPrint: empty fileList and fdList
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0003, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0004
* @tc.desc: StartPrint: mock failed to start ability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0004, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<std::string> fileList;
    InitFileList(fileList);
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_SERVER_FAILURE);
}

/**
* @tc.name: PrintServiceAbilityTest_0005
* @tc.desc: StartPrint: mock failed to start ability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0005, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    InitFdList(fdList);
    std::string taskId = "";
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_SERVER_FAILURE);
}

/**
* @tc.name: PrintServiceAbilityTest_0006
* @tc.desc: StartPrint: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0006, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, true));

    std::vector<std::string> fileList = {};
    InitFileList(fileList);
    std::vector<uint32_t> fdList = {};
    InitFdList(fdList);
    std::string taskId = "";
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0007
* @tc.desc: StopPrint: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0007, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string taskId = "1";
    EXPECT_EQ(service->StopPrint(taskId), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0008
* @tc.desc: StopPrint: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0008, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string taskId = "1";
    EXPECT_EQ(service->StopPrint(taskId), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0009
* @tc.desc: QueryAllExtension: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0009, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0010
* @tc.desc: QueryAllExtension: mock failed to get bms object
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0010, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_SERVER_FAILURE);
}

/**
* @tc.name: PrintServiceAbilityTest_0011
* @tc.desc: QueryAllExtension: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0011, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, false));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0012
* @tc.desc: StartDiscoverPrinter: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0012, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    std::vector<std::string> extensionIds;
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0013
* @tc.desc: StartDiscoverPrinter: empty extension list
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0013, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    std::vector<std::string> extensionIds;
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_INVALID_EXTENSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0014
* @tc.desc: StartDiscoverPrinter: input extension list not exist
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0014, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_NON_EXIST));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_INVALID_EXTENSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0015
* @tc.desc: StartDiscoverPrinter: mock failed to start extension
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0015, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, false));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0016
* @tc.desc: StartDiscoverPrinter: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0016, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0017
* @tc.desc: RegisterExtCallback: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0017, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string extensionCid = "";
    sptr<IPrintExtensionCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0018
* @tc.desc: RegisterExtCallback: invalid format of extensionCid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0018, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string extensionCid = "";
    sptr<IPrintExtensionCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0019
* @tc.desc: RegisterExtCallback: invalid extensionId of extensionCid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0019, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_NON_EXIST), PRINT_EXTCB_START_DISCOVERY);
    sptr<IPrintExtensionCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_EXTENSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0020
* @tc.desc: RegisterExtCallback: invalid state of extensionId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0020, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_UNLOAD), PRINT_EXTCB_START_DISCOVERY);
    sptr<IPrintExtensionCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_EXTENSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0021
* @tc.desc: RegisterExtCallback: invalid callbackId of extensionCid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0021, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_MAX);
    sptr<IPrintExtensionCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0022
* @tc.desc: RegisterExtCallback: invalid listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0022, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_START_DISCOVERY);
    sptr<IPrintExtensionCallback> listener = nullptr;
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0023
* @tc.desc: RegisterExtCallback: ok - insert istener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0023, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_START_DISCOVERY);
    auto listener = CreateExtCallback(false, false, false, false);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0024
* @tc.desc: RegisterExtCallback: ok - update istener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0024, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_START_DISCOVERY);
    auto listener = CreateExtCallback(false, false, false, false);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_NONE);
    auto listener2 = CreateExtCallback(true, false, false, false);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener2), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0025
* @tc.desc: UnregisterAllExtCallback: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0025, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    EXPECT_EQ(service->UnregisterAllExtCallback(GetExtensionId(TYPE_DEFAULT)), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0026
* @tc.desc: UnregisterAllExtCallback: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0026, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_START_DISCOVERY);
    auto listener = CreateExtCallback(false, false, false, false);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_NONE);
    EXPECT_EQ(service->UnregisterAllExtCallback(GetExtensionId(TYPE_DEFAULT)), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0027
* @tc.desc: LoadExtSuccess: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0027, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_DEFAULT)), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0028
* @tc.desc: LoadExtSuccess: invalid extensionId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0028, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_NON_EXIST)), E_PRINT_INVALID_EXTENSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0029
* @tc.desc: LoadExtSuccess: invalid state of extension
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0029, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_UNLOAD)), E_PRINT_INVALID_EXTENSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0030
* @tc.desc: LoadExtSuccess: ok - without START_DISCOVERY cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0030, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_DEFAULT)), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0031
* @tc.desc: LoadExtSuccess: ok - with START_DISCOVERY cb (false)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0031, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_START_DISCOVERY);
    auto listener = CreateExtCallback(false, false, false, false);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_NONE);
    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_DEFAULT)), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0032
* @tc.desc: LoadExtSuccess: ok - with START_DISCOVERY cb (true)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0032, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, true, true, true));

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);

    auto extensionCid = PrintUtils::EncodeExtensionCid(GetExtensionId(TYPE_DEFAULT), PRINT_EXTCB_START_DISCOVERY);
    auto listener = CreateExtCallback(true, false, false, false);
    EXPECT_EQ(service->RegisterExtCallback(extensionCid, listener), E_PRINT_NONE);
    EXPECT_EQ(service->LoadExtSuccess(GetExtensionId(TYPE_DEFAULT)), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0033
* @tc.desc: On: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0033, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string taskId = "";
    std::string type = "";
    sptr<IPrintCallback> listener = nullptr;
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0034
* @tc.desc: On: invalid event type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0034, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string taskId = "";
    std::string type = "";
    sptr<IPrintCallback> listener = nullptr;
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0035
* @tc.desc: On: invalid listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0035, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string taskId = GetDefaultTaskId();
    std::string type = "block";
    sptr<IPrintCallback> listener = nullptr;
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0036
* @tc.desc: On: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0036, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string taskId = GetDefaultTaskId();
    std::string type = "block";
    sptr<IPrintCallback> listener = CreateCallback(false, false, false, false);
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0037
* @tc.desc: On: update listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0037, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string taskId = GetDefaultTaskId();
    std::string type = "block";
    sptr<IPrintCallback> listener = CreateCallback(false, false, false, false);
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NONE);
    sptr<IPrintCallback> listener2 = CreateCallback(true, false, false, false);
    EXPECT_EQ(service->On(taskId, type, listener2), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0038
* @tc.desc: Off: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0038, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string taskId = "";
    std::string type = "";
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0039
* @tc.desc: Off: invalid event type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0039, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string taskId = "";
    std::string type = "";
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0040
* @tc.desc: Off: no event listener registerred
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0040, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string taskId = GetDefaultTaskId();
    std::string type = "block";
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0041
* @tc.desc: Off: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0041, TestSize.Level1)
{
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string taskId = GetDefaultTaskId();
    std::string type = "block";
    sptr<IPrintCallback> listener = CreateCallback(false, false, false, false);
    EXPECT_EQ(service->On(taskId, type, listener), E_PRINT_NONE);
    EXPECT_EQ(service->Off(taskId, type), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0042
* @tc.desc: AddPrinters: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0042, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::vector<PrinterInfo> printerInfos;
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0043
* @tc.desc: AddPrinters: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0043, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0044
* @tc.desc: AddPrinters: no printer event listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0044, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    EXPECT_EQ(service->Off("", PRINTER_EVENT_TYPE), E_PRINT_NONE);
    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0045
* @tc.desc: AddPrinters: duplicate printers
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0045, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    EXPECT_EQ(service->Off("", PRINTER_EVENT_TYPE), E_PRINT_NONE);
    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
    InitExtPrinterList(printerInfos, 2);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0046
* @tc.desc: RemovePrinters: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0046, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::vector<std::string> printerIds;
    EXPECT_EQ(service->RemovePrinters(printerIds), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0047
* @tc.desc: RemovePrinters: invalid printerId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0047, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<std::string> printerIds;
    InitExtPrinterIdList(printerIds, 1);
    EXPECT_EQ(service->RemovePrinters(printerIds), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0048
* @tc.desc: RemovePrinters: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0048, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
    std::vector<std::string> printerIds;
    InitExtPrinterIdList(printerIds, 1);
    EXPECT_EQ(service->RemovePrinters(printerIds), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0049
* @tc.desc: UpdatePrinters: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0049, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::vector<PrinterInfo> printerInfos;
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0050
* @tc.desc: UpdatePrinters: no printer exist
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0050, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0051
* @tc.desc: UpdatePrinters: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0051, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
    EXPECT_EQ(service->UpdatePrinters(printerInfos), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0052
* @tc.desc: StartPrintJob: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0052, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    PrintJob testJob;
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0053
* @tc.desc: StartPrintJob: invalid job id
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0053, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_INVALID_PRINTJOB);
}

/**
* @tc.name: PrintServiceAbilityTest_0054
* @tc.desc: StartPrintJob: without print job cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0054, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_START_PRINT);
    EXPECT_NE(service, nullptr);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_SERVER_FAILURE);
}

/**
* @tc.name: PrintServiceAbilityTest_0055
* @tc.desc: StartPrintJob: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0055, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0056
* @tc.desc: CancelPrintJob: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0056, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    EXPECT_EQ(service->CancelPrintJob(GetDefaultJobId()), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0057
* @tc.desc: CancelPrintJob: invalid job id
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0057, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    EXPECT_EQ(service->CancelPrintJob(GetDefaultJobId()), E_PRINT_INVALID_PRINTJOB);
}

/**
* @tc.name: PrintServiceAbilityTest_0058
* @tc.desc: CancelPrintJob: without cancel print cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0058, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_CANCEL_PRINT);
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NONE);
    EXPECT_EQ(service->CancelPrintJob(GetDefaultJobId()), E_PRINT_SERVER_FAILURE);
}

/**
* @tc.name: PrintServiceAbilityTest_0059
* @tc.desc: CancelPrintJob: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0059, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NONE);
    EXPECT_EQ(service->CancelPrintJob(GetDefaultJobId()), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0060
* @tc.desc: CancelPrintJob: job state is prepared
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0060, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NONE);
    EXPECT_EQ(service->UpdatePrintJobState(GetDefaultJobId(),
                    PRINT_JOB_PREPARED, PRINT_JOB_BLOCKED_UNKNOWN), E_PRINT_NONE);
    EXPECT_EQ(service->CancelPrintJob(GetDefaultJobId()), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0061
* @tc.desc: UpdatePrinterState: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0061, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string printerId = "";
    uint32_t state = 0;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0062
* @tc.desc: UpdatePrinterState: invalid state of printer
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0062, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string printerId = "";
    uint32_t state = PRINTER_UNKNOWN + 100;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0063
* @tc.desc: UpdatePrinterState: invalid printer id
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0063, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string printerId = DEFAULT_EXT_PRINTER_ID;
    uint32_t state = PRINTER_UPDATE_CAP;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_INVALID_PRINTER);
}

/**
* @tc.name: PrintServiceAbilityTest_0064
* @tc.desc: UpdatePrinterState: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0064, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    std::string printerId = DEFAULT_EXT_PRINTER_ID;
    uint32_t state = PRINTER_UPDATE_CAP;
    EXPECT_EQ(service->UpdatePrinterState(printerId, state), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0065
* @tc.desc: UpdatePrintJobState: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0065, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string jobId = "";
    uint32_t state = 0;
    uint32_t subState = 0;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0066
* @tc.desc: UpdatePrintJobState: invalid job state
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0066, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string jobId = "";
    uint32_t state = PRINT_JOB_UNKNOWN + 100;
    uint32_t subState = 0;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0067
* @tc.desc: UpdatePrintJobState: invalid substate of PRINT_JOB_COMPLETED
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0067, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string jobId = "";
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = PRINT_JOB_BLOCKED_UNKNOWN;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0068
* @tc.desc: UpdatePrintJobState: invalid substate of PRINT_JOB_BLOCKED
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0068, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string jobId = "";
    uint32_t state = PRINT_JOB_BLOCKED;
    uint32_t subState = PRINT_JOB_COMPLETED_FILE_CORRUPT;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0069
* @tc.desc: UpdatePrintJobState: invalid substate of PRINT_JOB_BLOCKED 2
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0069, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string jobId = "";
    uint32_t state = PRINT_JOB_BLOCKED;
    uint32_t subState = PRINT_JOB_BLOCKED_UNKNOWN + 100;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PARAMETER);
}

/**
* @tc.name: PrintServiceAbilityTest_0070
* @tc.desc: UpdatePrintJobState: invalid print job
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0070, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string jobId = GetDefaultJobId();
    uint32_t state = PRINT_JOB_BLOCKED;
    uint32_t subState = PRINT_JOB_BLOCKED_OFFLINE;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_INVALID_PRINTJOB);
}

/**
* @tc.name: PrintServiceAbilityTest_0071
* @tc.desc: UpdatePrintJobState: ok - blocked without start print job
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0071, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::string jobId = GetDefaultJobId();
    uint32_t state = PRINT_JOB_BLOCKED;
    uint32_t subState = PRINT_JOB_BLOCKED_OFFLINE;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0072
* @tc.desc: UpdatePrintJobState: ok - completed without start print job
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0072, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::string jobId = GetDefaultJobId();
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0073
* @tc.desc: UpdatePrintJobState:  ok - completed with start print job
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0073, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NONE);

    std::string jobId = GetDefaultJobId();
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0074
* @tc.desc: UpdateExtensionInfo: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0074, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string info = "";
    EXPECT_EQ(service->UpdateExtensionInfo(info), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0075
* @tc.desc: UpdateExtensionInfo: empty extension list
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0075, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string info = "";
    EXPECT_EQ(service->UpdateExtensionInfo(info), E_PRINT_INVALID_EXTENSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0076
* @tc.desc: UpdateExtensionInfo: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0076, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::string extInfo = DEFAULT_EXT_INFO;
    EXPECT_EQ(service->UpdateExtensionInfo(extInfo), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0077
* @tc.desc: RequestPreview: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0077, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    PrintJob job;
    std::string result = "";
    EXPECT_EQ(service->RequestPreview(job, result), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0078
* @tc.desc: RequestPreview: no print job
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0078, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    PrintJob job;
    job.SetJobId(GetDefaultJobId());
    std::string result = "";
    EXPECT_EQ(service->RequestPreview(job, result), E_PRINT_INVALID_PRINTJOB);
}

/**
* @tc.name: PrintServiceAbilityTest_0079
* @tc.desc: RequestPreview: print job not started yet
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0079, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    PrintJob job;
    job.SetJobId(GetDefaultJobId());
    std::string result = "";
    EXPECT_EQ(service->RequestPreview(job, result), E_PRINT_INVALID_PRINTJOB);
}

/**
* @tc.name: PrintServiceAbilityTest_0080
* @tc.desc: RequestPreview: print job with invalid printerId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0080, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob job;
    job.SetJobId(GetDefaultJobId());
    job.SetPrinterId(GetInvalidPrinterId());
    std::string result = "";
    EXPECT_EQ(service->RequestPreview(job, result), E_PRINT_INVALID_PRINTJOB);
}

/**
* @tc.name: PrintServiceAbilityTest_0081
* @tc.desc: RequestPreview: without request preview cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0081, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_REQUEST_PREVIEW);
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob job;
    job.SetJobId(GetDefaultJobId());
    job.SetPrinterId(GetDefaultPrinterId());
    std::string result = "";
    service->RequestPreview(job, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0082
* @tc.desc: RequestPreview: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0082, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob job;
    job.SetJobId(GetDefaultJobId());
    job.SetPrinterId(GetDefaultPrinterId());
    std::string result = "";
    service->RequestPreview(job, result);
}

/**
* @tc.name: PrintServiceAbilityTest_0083
* @tc.desc: QueryPrinterCapability: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0083, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string printerId = "";
    EXPECT_EQ(service->QueryPrinterCapability(printerId), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0084
* @tc.desc: RequestPreview: invalid printerId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0084, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string printerId = GetDefaultPrinterId();
    EXPECT_EQ(service->QueryPrinterCapability(printerId), E_PRINT_INVALID_PRINTER);
}

/**
* @tc.name: PrintServiceAbilityTest_0085
* @tc.desc: QueryPrinterCapability: without request cap cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0085, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_REQUEST_CAP);
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    std::string printerId = GetDefaultPrinterId();
    EXPECT_EQ(service->QueryPrinterCapability(printerId), E_PRINT_SERVER_FAILURE);
}

/**
* @tc.name: PrintServiceAbilityTest_0086
* @tc.desc: QueryPrinterCapability: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0086, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    std::string printerId = GetDefaultPrinterId();
    EXPECT_EQ(service->QueryPrinterCapability(printerId), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0087
* @tc.desc: StopDiscoverPrinter: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0087, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0088
* @tc.desc: StopDiscoverPrinter: without stop discovery cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0088, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_STOP_DISCOVERY);
    EXPECT_NE(service, nullptr);

    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0089
* @tc.desc: StopDiscoverPrinter: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0089, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    EXPECT_EQ(service->StopDiscoverPrinter(), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0090
* @tc.desc: QueryAllPrintJob: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0090, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::vector<PrintJob> printJobs;
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0091
* @tc.desc: QueryAllPrintJob: empty print job
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0091, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<PrintJob> printJobs;
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0092
* @tc.desc: QueryAllPrintJob: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0092, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NONE);

    std::vector<PrintJob> printJobs;
    EXPECT_EQ(service->QueryAllPrintJob(printJobs), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0093
* @tc.desc: QueryPrintJobById: no permission
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0093, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(false, false, false, false));

    std::string jobId = "";
    PrintJob testJob;
    EXPECT_EQ(service->QueryPrintJobById(jobId, testJob), E_PRINT_NO_PERMISSION);
}

/**
* @tc.name: PrintServiceAbilityTest_0094
* @tc.desc: QueryPrintJobById: no print job
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0094, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::string jobId = "";
    PrintJob testJob;
    EXPECT_EQ(service->QueryPrintJobById(jobId, testJob), E_PRINT_INVALID_PRINTJOB);
}

/**
* @tc.name: PrintServiceAbilityTest_0095
* @tc.desc: QueryPrintJobById: invalid job id
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0095, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::string jobId = GetInvalidJobId();
    PrintJob testJob;
    EXPECT_EQ(service->QueryPrintJobById(jobId, testJob), E_PRINT_INVALID_PRINTJOB);
}

/**
* @tc.name: PrintServiceAbilityTest_0096
* @tc.desc: QueryPrintJobById: ok
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0096, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::string jobId = GetDefaultJobId();
    PrintJob testJob;
    EXPECT_EQ(service->QueryPrintJobById(jobId, testJob), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0097
* @tc.desc: UpdateExtensionInfo: without extension cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0097, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);
    EXPECT_EQ(service->Off("", EXTINFO_EVENT_TYPE), E_PRINT_NONE);

    std::string extInfo = DEFAULT_EXT_INFO;
    EXPECT_EQ(service->UpdateExtensionInfo(extInfo), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0098
* @tc.desc: UpdatePrintJobState: without destroy extension cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0098, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_DESTROY_EXTENSION);
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NONE);

    std::string jobId = GetDefaultJobId();
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0099
* @tc.desc: UpdatePrintJobState: without print job cb for spooler
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0099, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);
    EXPECT_EQ(service->Off("", PRINTJOB_EVENT_TYPE), E_PRINT_NONE);

    std::string jobId = GetDefaultJobId();
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = PRINT_JOB_COMPLETED_SUCCESS;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0100
* @tc.desc: UpdatePrintJobState: without event fail cb
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0100, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);
    EXPECT_EQ(service->Off(GetDefaultJobId(), EVENT_FAIL), E_PRINT_NONE);

    std::string jobId = GetDefaultJobId();
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = PRINT_JOB_COMPLETED_FAILED;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_NONE);
}

/**
* @tc.name: PrintServiceAbilityTest_0101
* @tc.desc: UpdatePrintJobState: print job substate is cancel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0101, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::string jobId = GetDefaultJobId();
    uint32_t state = PRINT_JOB_COMPLETED;
    uint32_t subState = PRINT_JOB_COMPLETED_CANCELLED;
    EXPECT_EQ(service->UpdatePrintJobState(jobId, state, subState), E_PRINT_NONE);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0102, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    sptr<IRemoteObject> token;
    int result = PrintServiceAbility::GetInstance()->StartPrint(fileList, fdList, taskId, token);
    EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
    std::shared_ptr<PrintServiceHelper> helper = nullptr;
    PrintServiceAbility::GetInstance()->SetHelper(helper);
    result = PrintServiceAbility::GetInstance()->StartPrint(fileList, fdList, taskId, token);
    EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0103, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    sptr<IRemoteObject> token;
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId, token), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0104, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<std::string> fileList = {};
    InitFileList(fileList);
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    sptr<IRemoteObject> token;
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId, token), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0105, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service->SetHelper(CreatePrintServiceHelper(true, false, false, false));

    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    InitFdList(fdList);
    std::string taskId = "";
    sptr<IRemoteObject> token;
    EXPECT_EQ(service->StartPrint(fileList, fdList, taskId, token), E_PRINT_INVALID_PARAMETER);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0106, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(true, true, false, true);
    service->SetHelper(helper);

    std::vector<std::string> fileList = {};
    InitFileList(fileList);
    std::vector<uint32_t> fdList = {};
    InitFdList(fdList);
    std::string taskId = "";
    sptr<IRemoteObject> token = helper -> GetBundleMgr();
    service->StartPrint(fileList, fdList, taskId, token);
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0107, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service -> ConnectPrinter(GetDefaultPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0108, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(true, true, true, true);
    service->SetHelper(helper);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
    EXPECT_CALL(*helper, IsSyncMode()).WillRepeatedly(Return(false));

    service -> ConnectPrinter(GetDefaultPrinterId());
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0109, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_CONNECT_PRINTER);
    EXPECT_NE(service, nullptr);
    service -> ConnectPrinter(GetDefaultPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0110, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_CONNECT_PRINTER);
    EXPECT_NE(service, nullptr);
    service -> ConnectPrinter(GetInvalidPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0111, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_CONNECT_PRINTER);
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    service -> ConnectPrinter(GetDefaultPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0112, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    service -> ConnectPrinter(GetDefaultPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0113, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    service -> ConnectPrinter(GetInvalidPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0114, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    service -> DisconnectPrinter(GetDefaultPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0115, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(true, true, true, true);
    service->SetHelper(helper);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);
    EXPECT_CALL(*helper, IsSyncMode()).WillRepeatedly(Return(false));

    service -> DisconnectPrinter(GetDefaultPrinterId());
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0116, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_DISCONNECT_PRINTER);
    EXPECT_NE(service, nullptr);
    service -> DisconnectPrinter(GetDefaultPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0117, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_DISCONNECT_PRINTER);
    EXPECT_NE(service, nullptr);
    service -> DisconnectPrinter(GetInvalidPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0118, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateServiceWithoutEvent(PRINT_EXTCB_DISCONNECT_PRINTER);
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    service -> DisconnectPrinter(GetDefaultPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0119, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    service -> DisconnectPrinter(GetDefaultPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0120, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    service -> DisconnectPrinter(GetInvalidPrinterId());
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0121, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);

    std::string printerUrl;
    std::string printerName;
    std::string printerMake;

    service -> AddPrinterToCups(printerUrl, printerName, printerMake);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0122, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::string printerUrl;
    std::string printerName;
    std::string printerMake;

    service -> AddPrinterToCups(printerUrl, printerName, printerMake);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0123, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);

    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;

    service -> QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0124, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);

    std::string printerUri;
    std::string printerId;
    PrinterCapability printerCaps;

    service -> QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0125, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(true, true, true, true);
    service->SetHelper(helper);

    std::vector<PrintExtensionInfo> infoList;
    EXPECT_EQ(service->QueryAllExtension(infoList), E_PRINT_NONE);

    std::vector<std::string> extensionIds;
    extensionIds.emplace_back(GetExtensionId(TYPE_DEFAULT));
    EXPECT_EQ(service->StartDiscoverPrinter(extensionIds), E_PRINT_NONE);
    EXPECT_CALL(*helper, IsSyncMode()).WillRepeatedly(Return(false));

    service->LoadExtSuccess(GetExtensionId(TYPE_DEFAULT));
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0126, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(true, true, true, true);
    service->SetHelper(helper);

    EXPECT_CALL(*helper, IsSyncMode()).WillRepeatedly(Return(false));
    service->StopDiscoverPrinter();
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0128, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(true, true, true, true);
    service->SetHelper(helper);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    PrintJob testJob;
    testJob.SetJobId(GetDefaultJobId());
    testJob.SetPrinterId(GetDefaultPrinterId());
    EXPECT_EQ(service->StartPrintJob(testJob), E_PRINT_NONE);

    EXPECT_CALL(*helper, IsSyncMode()).WillRepeatedly(Return(false));
    service->CancelPrintJob(GetDefaultJobId());
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0129, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = CreateService();
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(true, true, true, true);
    service->SetHelper(helper);

    std::vector<PrinterInfo> printerInfos;
    InitExtPrinterList(printerInfos, 1);
    EXPECT_EQ(service->AddPrinters(printerInfos), E_PRINT_NONE);

    std::string printerId = GetDefaultPrinterId();
    EXPECT_CALL(*helper, IsSyncMode()).WillRepeatedly(Return(false));
    service->QueryPrinterCapability(printerId);
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0130, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    std::vector<std::string> fileList = {};
    std::vector<uint32_t> fdList = {};
    std::string taskId = "";
    int result = PrintServiceAbility::GetInstance()->StartPrint(fileList, fdList, taskId);
    EXPECT_EQ(result, E_PRINT_NO_PERMISSION);
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0131, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(false, false, false, false);
    service->SetHelper(helper);
    OHOS::Print::PrintAttributes printAttributes;
    std::string jobName = "123.jpg";
    std::string taskId = "";
    EXPECT_EQ(service->PrintByAdapter(jobName, printAttributes, taskId, nullptr), E_PRINT_NO_PERMISSION);

    EXPECT_CALL(*helper, CheckPermission(_)).WillRepeatedly(Return(true));
    EXPECT_EQ(service->PrintByAdapter(jobName, printAttributes, taskId, nullptr), E_PRINT_SERVER_FAILURE);

    printAttributes.SetCopyNumber(1);
    OHOS::Print::PrintRange range;
    range.SetStartPage(1);
    range.SetEndPage(3);
    std::vector<uint32_t> pages = {1, 2, 3};
    range.SetPages(pages);
    printAttributes.SetPageRange(range);
    printAttributes.SetIsSequential(true);
    OHOS::Print::PrintPageSize pageSize;
    pageSize.SetId("1");
    printAttributes.SetPageSize(pageSize);
    printAttributes.SetIsLandscape(true);
    printAttributes.SetDirectionMode(1);
    printAttributes.SetColorMode(1);
    printAttributes.SetDuplexMode(1);
    OHOS::Print::PrintMargin margin;
    margin.SetTop(1);
    margin.SetBottom(1);
    margin.SetLeft(1);
    margin.SetRight(1);
    printAttributes.SetMargin(margin);
    printAttributes.SetOption("1");
    EXPECT_EQ(service->PrintByAdapter(jobName, printAttributes, taskId, nullptr), E_PRINT_SERVER_FAILURE);
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0132, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(false, false, false, false);
    service->SetHelper(helper);
    std::string jobID = "1";
    OHOS::Print::PrintAttributes printAttributes;
    uint32_t fd = 2;
    EXPECT_EQ(service->StartGetPrintFile(jobID, printAttributes, fd), E_PRINT_NO_PERMISSION);

    EXPECT_CALL(*helper, CheckPermission(_)).WillRepeatedly(Return(true));
    EXPECT_EQ(service->StartGetPrintFile(jobID, printAttributes, fd), E_PRINT_NONE);
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0133, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(false, false, false, false);
    service->SetHelper(helper);
    std::string jobID = "1";
    std::string type = "-1";
    EXPECT_EQ(service->NotifyPrintService(jobID, type), E_PRINT_NO_PERMISSION);

    EXPECT_CALL(*helper, CheckPermission(_)).WillRepeatedly(Return(true));
    EXPECT_EQ(service->NotifyPrintService(jobID, type), E_PRINT_INVALID_PARAMETER);

    type = "spooler_closed_for_cancelled";
    EXPECT_EQ(service->NotifyPrintService(jobID, type), E_PRINT_NONE);

    type = "spooler_closed_for_started";
    EXPECT_EQ(service->NotifyPrintService(jobID, type), E_PRINT_NONE);
    helper = nullptr;
}

HWTEST_F(PrintServiceAbilityTest, PrintServiceAbilityTest_0134, TestSize.Level1)
{
    PrintServiceMockPermission::MockPermission();
    auto service = std::make_shared<PrintServiceAbility>(PRINT_SERVICE_ID, true);
    EXPECT_NE(service, nullptr);
    auto helper = CreatePrintServiceHelper(false, false, false, false);
    service->SetHelper(helper);
    std::string jobID = "1";
    uint32_t state = PRINT_JOB_CREATE_FILE_COMPLETED;
    uint32_t subState = PRINT_FILE_CREATED_SUCCESS;
    EXPECT_EQ(service->UpdatePrintJobState(jobID, state, subState), E_PRINT_NO_PERMISSION);

    EXPECT_CALL(*helper, CheckPermission(_)).WillRepeatedly(Return(true));
    EXPECT_EQ(service->UpdatePrintJobState(jobID, state, subState), E_PRINT_NONE);
    helper = nullptr;
}
}  // namespace Print
}  // namespace OHOS
