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

#ifndef PRINT_SERVICE_ABILITY_TEST_COMMON_H
#define PRINT_SERVICE_ABILITY_TEST_COMMON_H

#include <gtest/gtest.h>
#include "print_service_mock_permission.h"
#include "mock_remote_object.h"
#include "mock_watermark_callback.h"
#include "iwatermark_callback.h"
#define private public
#define protected public
#include "print_service_ability.h"
#include "print_bms_helper.h"
#include "event_listener_mgr.h"
#undef protected
#undef private
#ifdef CUPS_ENABLE
#include "print_cups_client.h"
#endif  // CUPS_ENABLE
#include "accesstoken_kit.h"
#include "array_wrapper.h"
#include "int_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "print_constant.h"
#include "print_log.h"
#include "printer_info.h"
#include "print_utils.h"
#include "print_util.h"
#include "string_wrapper.h"
#include "system_ability_definition.h"
#include "want_params_wrapper.h"
#include "print_extension_callback_stub.h"
#include "print_security_guard_manager.h"
#include "hisys_event_util.h"
#include <json/json.h>
#include "mock_print_callback_proxy.h"
#include "mock_print_extension_callback_proxy.h"
#include "parameter.h"
#ifdef REMOTE_SERVICE_ENABLE
#include "remote_constants.h"
#endif  // REMOTE_SERVICE_ENABLE

using namespace testing;
using namespace testing::ext;


namespace OHOS {
extern uint32_t uid_;

namespace Print {
using namespace std;
using namespace OHOS::HiviewDFX;
using namespace Security::AccessToken;
static constexpr const char *DEFAULT_EXTENSION_ID = "com.example.ext";
static constexpr const char *UNLOAD_EXTENSION_ID = "com.example.ext.unload";
static constexpr const char *NONEXIST_EXTENSION_ID = "com.example.ext.nonexist";
static constexpr const char *DEFAULT_EXT_PRINTER_ID = "https://10.10.10.10/FE8083DCD35F";
static constexpr const char *DEFAULT_EXT_PRINTER_ID2 = "https://10.10.10.10/0FDA6E208473";
static constexpr const char *DEFAULT_PRINT_FILE_A = "file://data/print/a.png";
static constexpr const char *DEFAULT_PRINT_FILE_B = "file://data/print/b.png";
static constexpr const char *DEFAULT_PRINT_FILE_C = "file://data/print/c.png";
static const std::string CUSTOM_PRINTER_NAME = "HUAWEI CV81";
static const std::string PRINT_EXTENSION_BUNDLE_NAME = "com.huawei.hmos.hwprintext";
static const std::string PARAMETER_SUPPORT_WINDOW_PCMODE_SWITCH = "const.window.support_window_pcmode_switch";
static const std::string PARAMETER_CHANGE_MODE_ANIMATION_READY = "persist.sceneboard.changeModeAnimationReady";
static const std::string CHANGE_MODE_DEFAULT_VALUE = "-1";
static const std::string PRINT_GET_FILE_EVENT_TYPE = "getPrintFileCallback_adapter";
static const std::string PRINTER_EVENT_TYPE = "printerStateChange";
static const std::string PRINTJOB_EVENT_TYPE = "jobStateChange";
static const std::string EXTINFO_EVENT_TYPE = "extInfoChange";
static const std::string PRINT_ADAPTER_EVENT_TYPE = "printCallback_adapter";
static const std::string PRINT_CALLBACK_JOB_STATE_TYPE = "printCallback_jobstate";
static const std::string EVENT_CANCEL = "cancel";
const uint32_t MAX_JOBQUEUE_NUM = 512;
static constexpr uint32_t ISO_A4_WIDTH = 8268;
static constexpr uint32_t ISO_A4_HEIGHT = 11692;
static const std::string IS_ENTERPRISE_ENABLE = "true";
static const std::string ENTERPRISE_SPACE_PARAM = "persist.space_mgr_service.enterprise_space_enable";
static const std::string PRINT_QUERY_INFO_EVENT_TYPE = "printerInfoQuery";
static const std::string CUPSD_CONTROL_PARAM = "print.cupsd.ready";
static const std::string CUPSD_ENTERPRISE_CONTROL_PARAM = "print.cupsd_enterprise.ready";

enum EXTENSION_ID_TYPE {
    TYPE_DEFAULT,
    TYPE_UNLOAD,
    TYPE_NON_EXIST,
};

class MockPrintServiceAbility final : public PrintServiceAbility {
public:
    MockPrintServiceAbility(int32_t systemAbilityId, bool runOnCreate)
        : PrintServiceAbility(systemAbilityId, runOnCreate) {}
    MOCK_METHOD2(QueryPrinterInfoByPrinterId, int32_t(const std::string &printerId, PrinterInfo &info));
    MOCK_METHOD2(QueryPPDInformation, bool(const std::string &makeModel, std::string &ppdName));
    MOCK_METHOD0(GetCallerBundleName, std::string());
    MOCK_METHOD5(DoAddPrinterToCupsEnable, bool(const std::string &printerUri, const std::string &printerName,
        std::shared_ptr<PrinterInfo> printerInfo, const std::string &ppdName, const std::string &ppdData));
    MOCK_METHOD1(IsPpdNameValid, bool(const std::string &ppdName));
    MOCK_METHOD3(QueryPrinterCapabilityFromPPD, int32_t(const std::string &name, PrinterCapability &printerCaps,
        const std::string &ppdName));
};

class MockPrintServiceHelper final : public PrintServiceHelper {
public:
    MOCK_METHOD1(QueryAccounts, bool(std::vector<int> &accountList));
    MOCK_METHOD1(CheckPermission, bool(const std::string &name));
    MOCK_METHOD0(IsSyncMode, bool());
};

class MockKiaInterceptorCallback final : public IRemoteStub<IKiaInterceptorCallback> {
public:
    MockKiaInterceptorCallback() = default;
    virtual ~MockKiaInterceptorCallback() = default;
    sptr<IRemoteObject> AsObject() override
    {
        return this;
    }
    MOCK_METHOD2(OnCheckPrintJobNeedReject, bool(const int32_t &pid, const std::string &callerAppId));
};

class PrintServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::shared_ptr<PrintServiceAbility> CreateService();
    static std::shared_ptr<PrintServiceAbility> CreateMockService(
        std::shared_ptr<MockPrintServiceHelper> &mockHelper);
    std::string GetExtensionId(EXTENSION_ID_TYPE type);
    std::string GetDefaultTaskId();
    std::string GetDefaultJobId();
    std::string GetDefaultPrinterId();
    std::string GetInvalidPrinterId();
    void InitExtPrinterList(std::vector<PrinterInfo> &printerList, size_t count);
    void InitPrinterList(std::vector<PrinterInfo> &printerList, size_t count);
    void InitExtPrinterIdList(std::vector<std::string> &idList, size_t count);
    void InitFileList(std::vector<std::string> &fileList);
    void InitExtensionList(std::vector<AppExecFwk::ExtensionAbilityInfo> &extList);

private:
    std::string parameterSaved;
};

}  // namespace Print
}  // namespace OHOS

#endif  // PRINT_SERVICE_ABILITY_TEST_COMMON_H
