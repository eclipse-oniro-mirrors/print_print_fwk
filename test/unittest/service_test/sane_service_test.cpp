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

#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include "sane/sane.h"
#include "safe_sane_api.h"
#include "sane_service_ability.h"

using namespace testing::ext;

namespace {
std::mutex g_saneStateMutex;
std::condition_variable g_saneStateCv;
const SANE_Option_Descriptor* g_saneDescriptor = nullptr;
SANE_Option_Descriptor* g_mutableSaneDescriptor = nullptr;
bool g_saneCloseCalled = false;
bool g_blockDescriptorGet = false;
bool g_descriptorGetEntered = false;
bool g_releaseDescriptorGet = false;
bool g_shrinkDescriptorAfterGet = false;
int32_t g_saneControlValue = 0;
int32_t g_saneControlInfo = 0;
int32_t g_saneControlCalls = 0;
int32_t g_saneLastControlValue = 0;
SANE_Action g_saneLastControlAction = SANE_ACTION_GET_VALUE;
}

extern "C" const SANE_Option_Descriptor* sane_get_option_descriptor(SANE_Handle, SANE_Int)
{
    std::unique_lock<std::mutex> lock(g_saneStateMutex);
    if (g_blockDescriptorGet) {
        g_descriptorGetEntered = true;
        g_saneStateCv.notify_all();
        g_saneStateCv.wait(lock, []() { return g_releaseDescriptorGet; });
    }
    return g_saneDescriptor;
}

extern "C" void sane_close(SANE_Handle)
{
    std::lock_guard<std::mutex> lock(g_saneStateMutex);
    g_saneCloseCalled = true;
}

extern "C" SANE_Status sane_control_option(SANE_Handle, SANE_Int, SANE_Action action,
    void* value, SANE_Int* info)
{
    std::lock_guard<std::mutex> lock(g_saneStateMutex);
    g_saneControlCalls++;
    g_saneLastControlAction = action;
    if (action == SANE_ACTION_GET_VALUE) {
        const auto* bytes = reinterpret_cast<const unsigned char*>(&g_saneControlValue);
        std::copy_n(bytes, sizeof(g_saneControlValue), static_cast<unsigned char*>(value));
        if (g_shrinkDescriptorAfterGet && g_mutableSaneDescriptor != nullptr) {
            g_mutableSaneDescriptor->size = 1;
        }
    } else {
        std::copy_n(static_cast<const unsigned char*>(value), sizeof(g_saneLastControlValue),
            reinterpret_cast<unsigned char*>(&g_saneLastControlValue));
        if (info != nullptr) {
            *info = g_saneControlInfo;
        }
    }
    return SANE_STATUS_GOOD;
}

namespace OHOS {
namespace Scan {
class SafeSaneApiTest : public testing::Test {
protected:
    void SetUp() override
    {
        {
            std::lock_guard<std::mutex> lock(g_saneStateMutex);
            g_saneDescriptor = &descriptor_;
            g_mutableSaneDescriptor = &descriptor_;
            g_saneCloseCalled = false;
            g_blockDescriptorGet = false;
            g_descriptorGetEntered = false;
            g_releaseDescriptorGet = false;
            g_shrinkDescriptorAfterGet = false;
            g_saneControlValue = 0;
            g_saneControlInfo = 0;
            g_saneControlCalls = 0;
            g_saneLastControlValue = 0;
            g_saneLastControlAction = ::SANE_ACTION_GET_VALUE;
        }
        handle_ = &handleStorage_;
        SafeSANEAPI::GetInstance().AddHandleMutex(handle_);
    }

    void TearDown() override
    {
        SafeSANEAPI::GetInstance().RemoveHandleMutex(handle_);
    }

    int32_t handleStorage_ = 0;
    SANE_Handle handle_ = nullptr;
    SANE_Option_Descriptor descriptor_ = {};
    std::optional<SaneOptionDescriptor> descriptorResult_;
};

HWTEST_F(SafeSaneApiTest, NullDescriptorReturnsNoValue, TestSize.Level1)
{
    {
        std::lock_guard<std::mutex> lock(g_saneStateMutex);
        g_saneDescriptor = nullptr;
    }
    auto result = SafeSANEAPI::GetInstance().SaneGetOptionDescriptor(handle_, 0);
    EXPECT_FALSE(result.has_value());

    SaneControlParam controlParam;
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = SCAN_VALUE_NUM;
    SaneOutParam outParam;
    SaneServerManager manager(3709, false);
    EXPECT_EQ(manager.GetControlOption(handle_, controlParam, outParam), SANE_STATUS_INVAL);
    EXPECT_EQ(g_saneControlCalls, 0);
    controlParam.action_ = SANE_ACTION_SET_VALUE;
    EXPECT_EQ(manager.SetControlOption(handle_, controlParam, outParam), SANE_STATUS_INVAL);
    EXPECT_EQ(g_saneControlCalls, 0);
}

HWTEST_F(SafeSaneApiTest, CloseWaitsForDescriptorRead, TestSize.Level1)
{
    auto handleMutex = SafeSANEAPI::GetInstance().GetHandleMutex(handle_);
    ASSERT_NE(handleMutex, nullptr);
    descriptor_.size = sizeof(int32_t);
    {
        std::lock_guard<std::mutex> lock(g_saneStateMutex);
        g_blockDescriptorGet = true;
    }
    std::thread reader([this]() {
        descriptorResult_ = SafeSANEAPI::GetInstance().SaneGetOptionDescriptor(handle_, 0);
    });
    {
        std::unique_lock<std::mutex> lock(g_saneStateMutex);
        EXPECT_TRUE(g_saneStateCv.wait_for(lock, std::chrono::seconds(5), []() { return g_descriptorGetEntered; }));
    }
    {
        std::unique_lock<std::mutex> handleLock(*handleMutex, std::try_to_lock);
        EXPECT_FALSE(handleLock.owns_lock());
    }

    std::thread closer([this]() {
        SafeSANEAPI::GetInstance().SaneClose(handle_);
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (SafeSANEAPI::GetInstance().GetHandleMutex(handle_) != nullptr &&
        std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    EXPECT_EQ(SafeSANEAPI::GetInstance().GetHandleMutex(handle_), nullptr);
    {
        std::lock_guard<std::mutex> lock(g_saneStateMutex);
        EXPECT_FALSE(g_saneCloseCalled);
        g_releaseDescriptorGet = true;
    }
    g_saneStateCv.notify_all();
    reader.join();
    closer.join();

    ASSERT_TRUE(descriptorResult_.has_value());
    EXPECT_EQ(descriptorResult_->optionSize_, sizeof(int32_t));
    EXPECT_TRUE(g_saneCloseCalled);
}

HWTEST_F(SafeSaneApiTest, DescriptorDtoRemainsIndependentAfterClose, TestSize.Level1)
{
    std::string name = "resolution";
    std::string title = "Resolution";
    std::string description = "Scan resolution";
    SANE_Word wordList[]{3, 75, 150, 300};
    descriptor_.name = name.c_str();
    descriptor_.title = title.c_str();
    descriptor_.desc = description.c_str();
    descriptor_.type = SANE_TYPE_INT;
    descriptor_.unit = SANE_UNIT_DPI;
    descriptor_.size = sizeof(int32_t);
    descriptor_.cap = SANE_CAP_SOFT_SELECT;
    descriptor_.constraint_type = ::SANE_CONSTRAINT_WORD_LIST;
    descriptor_.constraint.word_list = wordList;

    auto converted = SafeSANEAPI::GetInstance().SaneGetOptionDescriptor(handle_, 0);
    ASSERT_TRUE(converted.has_value());
    SafeSANEAPI::GetInstance().SaneClose(handle_);

    name.clear();
    title.clear();
    description.clear();
    descriptor_ = {};
    for (auto& value : wordList) {
        value = 0;
    }

    EXPECT_EQ(converted->optionName_, "resolution");
    EXPECT_EQ(converted->optionTitle_, "Resolution");
    EXPECT_EQ(converted->optionDesc_, "Scan resolution");
    EXPECT_EQ(converted->optionType_, static_cast<int32_t>(SANE_TYPE_INT));
    EXPECT_EQ(converted->optionUnit_, static_cast<int32_t>(SANE_UNIT_DPI));
    EXPECT_EQ(converted->optionSize_, sizeof(int32_t));
    EXPECT_EQ(converted->optionCap_, SANE_CAP_SOFT_SELECT);
    EXPECT_EQ(converted->optionConstraintType_, static_cast<int32_t>(SANE_CONSTRAINT_WORD_LIST));
    const std::vector<int32_t> expectedValues{75, 150, 300};
    EXPECT_EQ(converted->optionConstraintNumber_, expectedValues);
}

HWTEST_F(SafeSaneApiTest, GetNumericOptionUsesSnapshotSizeAfterControl, TestSize.Level1)
{
    descriptor_.type = SANE_TYPE_INT;
    descriptor_.size = sizeof(int32_t);
    SaneControlParam controlParam;
    controlParam.option_ = 7;
    controlParam.action_ = SANE_ACTION_GET_VALUE;
    controlParam.valueType_ = SCAN_VALUE_NUM;
    constexpr int32_t expectedValue = 0x12345678;
    {
        std::lock_guard<std::mutex> lock(g_saneStateMutex);
        g_saneControlValue = expectedValue;
        g_shrinkDescriptorAfterGet = true;
    }

    SaneOutParam outParam;
    SaneServerManager manager(3709, false);
    SaneStatus status = manager.GetControlOption(handle_, controlParam, outParam);

    EXPECT_EQ(status, SANE_STATUS_GOOD);
    EXPECT_EQ(outParam.valueNumber_, expectedValue);
    EXPECT_EQ(descriptor_.size, 1);
    EXPECT_EQ(g_saneControlCalls, 1);
    EXPECT_EQ(g_saneLastControlAction, ::SANE_ACTION_GET_VALUE);
}

HWTEST_F(SafeSaneApiTest, SetNumericOptionUsesSnapshotPath, TestSize.Level1)
{
    descriptor_.type = SANE_TYPE_INT;
    descriptor_.size = sizeof(int32_t);
    SaneControlParam controlParam;
    controlParam.option_ = 8;
    controlParam.action_ = SANE_ACTION_SET_VALUE;
    controlParam.valueType_ = SCAN_VALUE_NUM;
    constexpr int32_t inputValue = 0x0A0B0C0D;
    controlParam.valueNumber_ = inputValue;
    constexpr int32_t expectedInfo = 23;
    {
        std::lock_guard<std::mutex> lock(g_saneStateMutex);
        g_saneControlInfo = expectedInfo;
    }

    SaneOutParam outParam;
    SaneServerManager manager(3709, false);
    SaneStatus status = manager.SetControlOption(handle_, controlParam, outParam);

    EXPECT_EQ(status, SANE_STATUS_GOOD);
    EXPECT_EQ(outParam.info_, expectedInfo);
    EXPECT_EQ(g_saneLastControlValue, inputValue);
    EXPECT_EQ(g_saneControlCalls, 1);
    EXPECT_EQ(g_saneLastControlAction, ::SANE_ACTION_SET_VALUE);
}

HWTEST_F(SafeSaneApiTest, StringListStopsAtOneThousandEntries, TestSize.Level1)
{
    constexpr size_t maxStringListSize = 1000;
    std::vector<std::string> values;
    std::vector<SANE_String_Const> stringList;
    for (size_t i = 0; i <= maxStringListSize; ++i) {
        values.push_back("value-" + std::to_string(i));
    }
    for (const auto& value : values) {
        stringList.push_back(value.c_str());
    }
    stringList.push_back(nullptr);

    descriptor_.constraint_type = ::SANE_CONSTRAINT_STRING_LIST;
    descriptor_.constraint.string_list = stringList.data();
    auto converted = SafeSANEAPI::GetInstance().SaneGetOptionDescriptor(handle_, 0);
    ASSERT_TRUE(converted.has_value());
    SafeSANEAPI::GetInstance().SaneClose(handle_);
    values.clear();
    stringList.clear();
    descriptor_ = {};

    ASSERT_EQ(converted->optionConstraintString_.size(), maxStringListSize);
    EXPECT_EQ(converted->optionConstraintString_.front(), "value-0");
    EXPECT_EQ(converted->optionConstraintString_.back(), "value-999");
}
} // namespace Scan
} // namespace OHOS
