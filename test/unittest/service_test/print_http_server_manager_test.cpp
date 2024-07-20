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

#ifdef IPPOVERUSB_ENABLE
#include <gtest/gtest.h>
#define private public
#include "print_http_server_manager.h"
#undef private
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
using namespace httplib;

static const std::string IPP_PRINTER =
    R"({"busNum":2,"clazz":0,"configs":[{"attributes":192,"id":1,"interfaces":[{"alternateSetting":0,"clazz":7,)"\
    R"("endpoints":[{"address":1,"attributes":2,"direction":0,"interfaceId":0,"interval":0,"maxPacketSize":512,)"\
    R"("number":1,"type":2},{"address":129,"attributes":2,"direction":128,"interfaceId":0,"interval":0,)"\
    R"("maxPacketSize":512,"number":1,"type":2}],"id":0,"name":"","protocol":2,"subClass":1},{"alternateSetting":0,)"\
    R"("clazz":255,"endpoints":[{"address":2,"attributes":2,"direction":0,"interfaceId":1,"interval":0,)"\
    R"("maxPacketSize":512,"number":2,"type":2},{"address":130,"attributes":2,"direction":128,"interfaceId":1,)"\
    R"("interval":0,"maxPacketSize":512,"number":2,"type":2}],"id":1,"name":"","protocol":255,"subClass":255},)"\
    R"({"alternateSetting":0,"clazz":7,"endpoints":[{"address":3,"attributes":2,"direction":0,"interfaceId":2,)"\
    R"("interval":0,"maxPacketSize":512,"number":3,"type":2},{"address":131,"attributes":2,"direction":128,)"\
    R"("interfaceId":2,"interval":0,"maxPacketSize":512,"number":3,"type":2}],"id":2,"name":"","protocol":4,)"\
    R"("subClass":1},{"alternateSetting":0,"clazz":7,"endpoints":[{"address":4,"attributes":2,"direction":0,)"\
    R"("interfaceId":3,"interval":0,"maxPacketSize":512,"number":4,"type":2},{"address":132,"attributes":2,)"\
    R"("direction":128,"interfaceId":3,"interval":0,"maxPacketSize":512,"number":4,"type":2}],"id":3,"name":"",)"\
    R"("protocol":4,"subClass":1},{"alternateSetting":0,"clazz":7,"endpoints":[{"address":5,"attributes":2,)"\
    R"("direction":0,"interfaceId":4,"interval":0,"maxPacketSize":512,"number":5,"type":2},{"address":133,)"\
    R"("attributes":2,"direction":128,"interfaceId":4,"interval":0,"maxPacketSize":512,"number":5,"type":2}],)"\
    R"("id":4,"name":"","protocol":4,"subClass":1},{"alternateSetting":0,"clazz":7,"endpoints":[{"address":6,)"\
    R"("attributes":2,"direction":0,"interfaceId":5,"interval":0,"maxPacketSize":512,"number":6,"type":2},)"\
    R"({"address":134,"attributes":2,"direction":128,"interfaceId":5,"interval":0,"maxPacketSize":512,)"\
    R"("number":6,"type":2}],"id":5,"name":" ","protocol":4,"subClass":1}],"isRemoteWakeup":false,)"\
    R"("isSelfPowered":true,"maxPower":1,"name":" "}],"devAddress":5,"manufacturerName":" ","name":"2-5",)"\
    R"("productId":4293,"productName":" ","protocol":0,"serial":"","subClass":0,"vendorId":4817,"version":"0404"})";

class PrintHttpServerManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintHttpServerManagerTest::SetUpTestCase(void)
{}

void PrintHttpServerManagerTest::TearDownTestCase(void)
{}

void PrintHttpServerManagerTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintHttpServerManagerTest_%{public}d", ++testNo);
}

void PrintHttpServerManagerTest::TearDown(void)
{}

/**
 * @tc.name: PrintHttpServerManagerTest_001
 * @tc.desc: Verify the CreateServer function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpServerManagerTest, PrintHttpServerManagerTest_001, TestSize.Level1)
{
    auto service = std::make_shared<PrintHttpServerManager>();
    std::string printerName = "HUAWEI PixLab V1-0105";
    int32_t port;
    EXPECT_TRUE(service->CreateServer(printerName, port));
}

/**
 * @tc.name: PrintHttpServerManagerTest_002
 * @tc.desc: Verify the CreateServer function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpServerManagerTest, PrintHttpServerManagerTest_002, TestSize.Level1)
{
    auto service = std::make_shared<PrintHttpServerManager>();
    std::string printerName = "HUAWEI PixLab V1-0105";
    int32_t port;
    std::shared_ptr<httplib::Server> newServer = std::make_shared<httplib::Server>();
    EXPECT_NE(newServer, nullptr);
    service->printHttpServerMap[printerName] = newServer;
    service->CreateServer(printerName, port);
}

/**
 * @tc.name: PrintHttpServerManagerTest_003
 * @tc.desc: Verify the CreateServer function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpServerManagerTest, PrintHttpServerManagerTest_003, TestSize.Level1)
{
    auto service = std::make_shared<PrintHttpServerManager>();
    std::string printerName = "HUAWEI PixLab V1-0105";
    int32_t port;
    std::shared_ptr<httplib::Server> newServer = std::make_shared<httplib::Server>();
    EXPECT_NE(newServer, nullptr);
    service->printHttpServerMap[printerName] = newServer;
    service->printHttpPortMap[printerName] = 60000;
    service->CreateServer(printerName, port);
}


/**
 * @tc.name: PrintHttpServerManagerTest_004
 * @tc.desc: Verify the StopServer function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpServerManagerTest, PrintHttpServerManagerTest_004, TestSize.Level1)
{
    OHOS::Print::PrintHttpServerManager printHttpServerManager;
    std::string printerName = "HUAWEI PixLab V1-0105";
    std::shared_ptr<httplib::Server> newServer = std::make_shared<httplib::Server>();
    EXPECT_NE(newServer, nullptr);
    std::shared_ptr<PrintHttpRequestProcess> newProcess = std::make_shared<PrintHttpRequestProcess>();
    EXPECT_NE(newProcess, nullptr);
    printHttpServerManager.printHttpServerMap[printerName] = newServer;
    printHttpServerManager.printHttpPortMap[printerName] = 60000;
    printHttpServerManager.printHttpProcessMap[printerName] = newProcess;
    printHttpServerManager.StopServer(printerName);
}

}  // namespace Print
}  // namespace OHOS
#endif // IPPOVERUSB_ENABLE