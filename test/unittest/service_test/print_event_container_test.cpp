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

#include <gtest/gtest.h>
#define private public
#include "print_event_container.h"
#undef private
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintEventContainerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintEventContainerTest::SetUpTestCase(void)
{}

void PrintEventContainerTest::TearDownTestCase(void)
{}

void PrintEventContainerTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintEventContainerTest_%{public}d", ++testNo);
}

void PrintEventContainerTest::TearDown(void)
{}

HWTEST_F(PrintEventContainerTest, PrintEventContainerTest_Constructor_Test, TestSize.Level0)
{
    std::string id = "12345";
    PrintEventContainer container(id);
    EXPECT_EQ(container.printerId, id);
}
HWTEST_F(PrintEventContainerTest, PrintEventContainerTest_ShouldAddNewEvent_WhenTypeNotExists, TestSize.Level0)
{
    PrintEventContainer container("test_id");
    std::string type = "new_type";
    int32_t code = 123;
    container.AddEventCode(type, code);
    auto iter = container.eventTypeMap.find(type);
    EXPECT_NE(iter, container.eventTypeMap.end());
    EXPECT_NE(iter->second, nullptr);
    EXPECT_EQ(iter->second->size(), 1);
    EXPECT_EQ(iter->second->at(0), code);
}

HWTEST_F(PrintEventContainerTest, PrintEventContainerTest_ShouldAddToExistingEvent_WhenTypeExists, TestSize.Level1)
{
    PrintEventContainer container("test_id");
    std::string type = "existing_type";
    int32_t code1 = 123;
    int32_t code2 = 456;
    container.AddEventCode(type, code1);
    container.AddEventCode(type, code2);
    auto iter = container.eventTypeMap.find(type);
    EXPECT_NE(iter, container.eventTypeMap.end());
    EXPECT_NE(iter->second, nullptr);
    EXPECT_EQ(iter->second->size(), 2);
    EXPECT_EQ(iter->second->at(1), code2);
}

HWTEST_F(PrintEventContainerTest, PrintEventContainerTest_ShouldHandleNullVector_WhenTypeExistsButVectorIsNull,
    TestSize.Level1)
{
    PrintEventContainer container("test_id");
    std::string type = "null_type";
    int32_t code = 123;
    container.eventTypeMap[type] = nullptr;
    container.AddEventCode(type, code);
    auto iter = container.eventTypeMap.find(type);
    EXPECT_NE(iter, container.eventTypeMap.end());
    EXPECT_NE(iter->second, nullptr);
    EXPECT_EQ(iter->second->size(), 1);
    EXPECT_EQ(iter->second->at(0), code);
}

HWTEST_F(PrintEventContainerTest, PrintEventContainerTest_ShouldClearEvents_WhenTypeExistsAndNotNull,
    TestSize.Level1)
{
    PrintEventContainer container("test_id");
    std::string type = "exist_type";
    int32_t code = 123;
    container.AddEventCode(type, code);
    container.ClearEventType(type);
    auto iter = container.eventTypeMap.find(type);
    EXPECT_NE(iter, container.eventTypeMap.end());
    EXPECT_NE(iter->second, nullptr);
    EXPECT_EQ(iter->second->size(), 0);
}

HWTEST_F(PrintEventContainerTest, PrintEventContainerTest_ShouldDoNothing_WhenTypeNotExists,
    TestSize.Level1)
{
    PrintEventContainer container("test_id");
    std::string type = "null_type";
    container.eventTypeMap[type] = nullptr;
    container.ClearEventType(type);
    container.ClearEventType("not_exist_type");
    auto iter = container.eventTypeMap.find(type);
    EXPECT_NE(iter, container.eventTypeMap.end());
    EXPECT_EQ(iter->second, nullptr);
}

HWTEST_F(PrintEventContainerTest, PrintEventContainerTest_ShouldReturnJsonString_WhenTypeExists,
    TestSize.Level1)
{
    PrintEventContainer container("test_id");
    std::string type = "test_type";
    int32_t code = 123;
    container.AnalyzeEventCodes(type);
    container.AddEventCode(type, code);
    std::string result = container.AnalyzeEventCodes(type);
    EXPECT_FALSE(result.empty());
}
}  // namespace Print
}  // namespace OHOS
