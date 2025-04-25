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
#include "mock_bundle_mgr.h"
#include "scan_service_ability.h"
#include "scan_constant.h"
#include "system_ability_definition.h"
#include "scan_utils.h"
#include "mock_scan_callback_proxy.h"

namespace OHOS {
namespace Scan {
class ScanServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<ScanServiceStub> stubSpr;

    using ScanCmdHandler = bool (ScanServiceStub::*)(MessageParcel &, MessageParcel &);
    std::map<uint32_t, ScanCmdHandler> cmdMap_;
    sptr<ScanServiceAbility> scanSa;
};

void ScanServiceStubTest::SetUpTestCase(void) {}

void ScanServiceStubTest::TearDownTestCase(void) {}

void ScanServiceStubTest::SetUp(void)
{
    stubSpr = std::make_shared<ScanServiceStub>();
    EXPECT_NE(stubSpr, nullptr);
    cmdMap_[CMD_INIT_SCAN] = &ScanServiceStub::OnInitScan;
    cmdMap_[CMD_EXIT_SCAN] = &ScanServiceStub::OnExitScan;
    cmdMap_[CMD_GET_SCANNER_LIST] = &ScanServiceStub::OnGetScannerList;
    cmdMap_[CMD_STOP_DISCOVER] = &ScanServiceStub::OnStopDiscover;
    cmdMap_[CMD_OPEN_SCANNER] = &ScanServiceStub::OnOpenScanner;
    cmdMap_[CMD_CLOSE_SCANNER] = &ScanServiceStub::OnCloseScanner;
    cmdMap_[CMD_GET_SCAN_OPTION_DESC] = &ScanServiceStub::OnGetScanOptionDesc;
    cmdMap_[CMD_OP_SCAN_OPTION_VALUE] = &ScanServiceStub::OnOpScanOptionValue;
    cmdMap_[CMD_GET_SCAN_PARAMETERS] = &ScanServiceStub::OnGetScanParameters;
    cmdMap_[CMD_START_SCAN] = &ScanServiceStub::OnStartScan;
    cmdMap_[CMD_GET_SINGLE_FRAME_FD] = &ScanServiceStub::OnGetSingleFrameFD;
    cmdMap_[CMD_CANCEL_SCAN] = &ScanServiceStub::OnCancelScan;
    cmdMap_[CMD_SET_SCAN_IO_MODE] = &ScanServiceStub::OnSetScanIOMode;
    cmdMap_[CMD_GET_SCAN_SELECT_FD] = &ScanServiceStub::OnGetScanSelectFd;
    cmdMap_[CMD_GET_SCANNER_STATE] = &ScanServiceStub::OnGetScannerState;
    cmdMap_[CMD_GET_SCAN_PROGRESS] = &ScanServiceStub::OnGetScanProgress;
    cmdMap_[CMD_ON] = &ScanServiceStub::OnEventOn;
    cmdMap_[CMD_OFF] = &ScanServiceStub::OnEventOff;
    scanSa = ScanServiceAbility::GetInstance();
    EXPECT_TRUE(scanSa != nullptr);
    EXPECT_TRUE(scannerId != nullptr && scannerId != "")
}

void ScanServiceStubTest::TearDown(void) {}

/**
 * @tc.name: ScanMdnsServiceTest_0001
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, ScanMdnsServiceTest_0001, TestSize.Level1) {
    auto itFunc = cmdMap_.find(CMD_INIT_SCAN);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
        }
    }
    EXPECT_EQ(scanSa->appCount_, 1);
}

/**
 * @tc.name: ScanMdnsServiceTest_0002
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, ScanMdnsServiceTest_0002, TestSize.Level1) {
    auto itFunc = cmdMap_.find(CMD_EXIT_SCAN);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
        }
    }
    EXPECT_EQ(scanSa->appCount_, 0);
}

/**
 * @tc.name: ScanMdnsServiceTest_0003
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, ScanMdnsServiceTest_0003, TestSize.Level1) {
    auto itFunc = cmdMap_.find(CMD_INIT_SCAN);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
        }
    }
    itFunc = cmdMap_.find(CMD_EXIT_SCAN);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
        }
    }
    EXPECT_GE(scanSa->appCount_, 0);
}

/**
 * @tc.name: ScanMdnsServiceTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, ScanMdnsServiceTest_0004, TestSize.Level1) {

    for (int i = 0; i < 5; i++) {
        auto itFunc = cmdMap_.find(CMD_INIT_SCAN);
        if (itFunc != cmdMap_.end()) {
            auto requestFunc = itFunc->second;
            if (requestFunc != nullptr) {
                (this->*requestFunc)(data, reply);
            }
        }
    }
    EXPECT_EQ(scanSa->appCount_, 5);
}

/**
 * @tc.name: ScanMdnsServiceTest_0004
 * @tc.desc: Verify the capability function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScanServiceStubTest, ScanMdnsServiceTest_0004, TestSize.Level1) {

    for (int i = 0; i < 5; i++) {
        auto itFunc = cmdMap_.find(CMD_EXIT_SCAN);
        if (itFunc != cmdMap_.end()) {
            auto requestFunc = itFunc->second;
            if (requestFunc != nullptr) {
                return (this->*requestFunc)(data, reply);
            }
        }
    }
    EXPECT_EQ(scanSa->appCount_, 0);
}
} // namespace Scan
} // namespace OHOS