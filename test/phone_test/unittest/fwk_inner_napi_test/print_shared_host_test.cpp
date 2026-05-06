/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#define private public
#include "print_preview_attribute.h"
#include "print_shared_host.h"
#undef private
#include "print_log.h"
#include "print_constant.h"
#include "print_shared_host_helper.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintSharedHostTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void PrintSharedHostTest::SetUpTestCase(void)
{}

void PrintSharedHostTest::TearDownTestCase(void)
{}

/**
 * @tc.name: PrintJobTest_0002_NeedRename
 * @tc.desc: Verify the PrintExtensionInfo function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSharedHostTest, PrintJobTest_0002_NeedRename, TestSize.Level1)
{
    PrintSharedHost host;
    std::string ip = "192.168.2.3";
    std::string name = "192.168.2.3";
    std::string workgroupName = "workgroup";
    host.SetIp(ip);
    host.SetShareName(name);
    host.SetWorkgroupName(workgroupName);
    EXPECT_EQ(ip, host.GetIp());
    EXPECT_EQ(name, host.GetShareName());
    EXPECT_EQ(workgroupName, host.GetWorkgroupName());
    host.Dump();
    Parcel parcel;
    host.Marshalling(parcel);
    auto copyHost = PrintSharedHost::Unmarshalling(parcel);
    EXPECT_NE(copyHost, nullptr);
    EXPECT_EQ(ip, copyHost->GetIp());
    EXPECT_EQ(name, copyHost->GetShareName());
    EXPECT_EQ(workgroupName, copyHost->GetWorkgroupName());
}

/**
 * @tc.name: MakeJsObjectArray_NullEnvAndEmptyVector_ReturnsNull
 * @tc.desc: Test that MakeJsObjectArray returns nullptr when napi_env is nullptr and the vector is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintSharedHostTest, MakeJsObjectArray_NullEnvAndEmptyVector_ReturnsNull, TestSize.Level1)
{
    napi_env env = nullptr;
    std::vector<PrintSharedHost> sharedHosts;
    EXPECT_EQ(PrintSharedHostHelper::MakeJsObjectArray(env, sharedHosts), nullptr);
}
}  // namespace Print
}  // namespace OHOS
