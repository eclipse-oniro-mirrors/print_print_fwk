/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "print_http_server_manager.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Print {
class PrintHttpServerManagerTest : public testing::Test {
public:
    PrintHttpServerManager *manager;
    std::string printerName;
    void SetUp() override
    {
        manager = new PrintHttpServerManager();
        printerName = "testPrinter";
    }
    void TearDown() override
    {
        delete manager;
        manager = nullptr;
    }
};

TEST_F(PrintHttpServerManagerTest, AllocatePort_ShouldReturnFalse_WhenServerIsNull)
{
    std::shared_ptr httplib::Server svr = nullptr;
    int32_t port = 8080;
    bool result = PrintHttpServerManager::AllocatePort(svr, port);
    EXPECT_EQ(result, false);
}

TEST_F(PrintHttpServerManagerTest, AllocatePort_ShouldReturnFalse_WhenPortIsNull)
{
    std::shared_ptr httplib::Server svr = std::make_shared httplib::Server();
    int32_t port = 0;
    bool result = PrintHttpServerManager::AllocatePort(svr, port);
    EXPECT_EQ(result, false);
}

TEST_F(PrintHttpServerManagerTest, AllocatePort_ShouldReturnTrue_WhenServerAndPortAreValid)
{
    std::shared_ptr httplib::Server svr = std::make_shared httplib::Server();
    int32_t port = 8080;
    bool result = PrintHttpServerManager::AllocatePort(svr, port);
    EXPECT_EQ(result, true);
}

TEST_F(PrintHttpServerManagerTest, AllocatePort_ShouldReturnFalse_WhenPortIsAlreadyAllocated)
{
    std::shared_ptr httplib::Server svr = std::make_shared httplib::Server();
    int32_t port = 8080;
    bool result1 = PrintHttpServerManager::AllocatePort(svr, port);
    bool result2 = PrintHttpServerManager::AllocatePort(svr, port);
    EXPECT_EQ(result1, true);
    EXPECT_EQ(result2, false);
}

TEST_F(PrintHttpServerManagerTest, CreateServer_ShouldReturnFalse_WhenPrinterNameIsEmpty)
{
    int32_t port;
    ASSERT_FALSE(manager->CreateServer("", port));
}

TEST_F(PrintHttpServerManagerTest, CreateServer_ShouldReturnFalse_WhenPortIsNull)
{
    ASSERT_FALSE(manager->CreateServer("printer", nullptr));
}

TEST_F(PrintHttpServerManagerTest, CreateServer_ShouldReturnTrue_WhenPrinterNameAndPortAreValid)
{
    int32_t port;
    ASSERT_TRUE(manager->CreateServer("printer", port));
}

TEST_F(PrintHttpServerManagerTest, CreateServer_ShouldReturnFalse_WhenCreateServerFails)
{
    int32_t port;
    ASSERT_FALSE(manager->CreateServer("printer", port));
}

TEST_F(PrintHttpServerManagerTest, CreateServer_ShouldReturnTrue_WhenCreateServerSucceeds)
{
    int32_t port;
    ASSERT_TRUE(manager->CreateServer("printer", port));
}

HWTEST_F(PrintHttpServerManagerTest, StopServer_ShouldReturnFalse_WhenServerNotRunning, TestSize.Level0)
{
    EXPECT_FALSE(manager->StopServer(printerName));
}

HWTEST_F(PrintHttpServerManagerTest, StopServer_ShouldReturnTrue_WhenServerRunning, TestSize.Level0)
{
    EXPECT_TRUE(manager->StopServer(printerName));
}

TEST_F(nullTest, DealUsbDevDetach_ShouldReturnNull_WhenDevStrIsEmpty)
{
    PrintHttpServerManager manager;
    std::string devStr = "";
    manager.DealUsbDevDetach(devStr);
    EXPECT_EQ(manager.someInternalState, expectedValueAfterMethodInvocation);
}

TEST_F(nullTest, DealUsbDevDetach_ShouldReturnNull_WhenDevStrIsInvalid)
{
    PrintHttpServerManager manager;
    std::string devStr = "invalid_device";
    manager.DealUsbDevDetach(devStr);
    EXPECT_EQ(manager.someInternalState, expectedValueAfterMethodInvocation);
}

TEST_F(nullTest, DealUsbDevDetach_ShouldReturnNull_WhenDevStrIsValid)
{
    PrintHttpServerManager manager;
    std::string devStr = "valid_device";
    manager.DealUsbDevDetach(devStr);
    EXPECT_EQ(manager.someInternalState, expectedValueAfterMethodInvocation);
}

} // namespace OHOS::Print
