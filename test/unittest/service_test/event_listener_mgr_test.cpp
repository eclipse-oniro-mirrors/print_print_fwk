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
#include <string>
#include <fstream>
#include <map>
#define private public
#include "event_listener_mgr.h"
#undef private
#include "print_log.h"
#include "print_constant.h"
#include "mock_remote_object.h"
#include "mock_print_callback_proxy.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Print {
const std::string EVENT_TYPE_TEST = "testEvent";
const int32_t MAX_LISTENERS_COUNT = 1000;

class EventListenerMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
};

void EventListenerMgrTest::SetUpTestCase(void)
{}

void EventListenerMgrTest::TearDownTestCase(void)
{}

void EventListenerMgrTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("EventListenerMgrTest_%{public}d", ++testNo);
}

HWTEST_F(EventListenerMgrTest, RegisterEventListener_ShouldReturnTrue_WhenValidListener, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
}

HWTEST_F(EventListenerMgrTest, RegisterEventListener_ShouldReturnFalse_WhenNullListener, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, nullptr));
}

HWTEST_F(EventListenerMgrTest, RegisterEventListener_ShouldReturnTrue_WhenListenerExist, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
}

HWTEST_F(EventListenerMgrTest, RegisterEventListener_ShouldReturnFalse_WhenExceedMaxListeners, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    for (int i = 0; i < MAX_LISTENERS_COUNT; ++i) {
        EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST + std::to_string(i), listener));
    }
    EXPECT_FALSE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
}

HWTEST_F(EventListenerMgrTest, UnRegisterEventListener_ShouldReturnTrue_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    EXPECT_TRUE(eventListenerMgr.UnRegisterEventListener(EVENT_TYPE_TEST));
}

HWTEST_F(EventListenerMgrTest, UnRegisterEventListener_ShouldReturnFalse_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.UnRegisterEventListener(EVENT_TYPE_TEST));
}

HWTEST_F(EventListenerMgrTest, FindEventListener_ShouldReturnListener_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    EXPECT_TRUE(eventListenerMgr.FindEventListener(EVENT_TYPE_TEST) != nullptr);
}

HWTEST_F(EventListenerMgrTest, FindEventListener_ShouldReturnNull_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_TRUE(eventListenerMgr.FindEventListener(EVENT_TYPE_TEST) == nullptr);
}

HWTEST_F(EventListenerMgrTest, FindEventListeners_ShouldReturnNotEmptyList_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    EXPECT_FALSE(eventListenerMgr.FindEventListeners([](const std::string &type) -> bool {
        return type == EVENT_TYPE_TEST;
    }).empty());
}

HWTEST_F(EventListenerMgrTest, FindEventListeners_ShouldReturnEmptyList_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_TRUE(eventListenerMgr.FindEventListeners([](const std::string &type) -> bool {
        return type == EVENT_TYPE_TEST;
    }).empty());
}

HWTEST_F(EventListenerMgrTest, FindEventTypes_ShouldReturnNotEmptyList_WhenListenerExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    EXPECT_FALSE(eventListenerMgr.FindEventTypes([](const std::string &type) -> bool {
        return type == EVENT_TYPE_TEST;
    }).empty());
}

HWTEST_F(EventListenerMgrTest, FindEventTypes_ShouldReturnEmptyList_WhenListenerNotExist, TestSize.Level0)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_TRUE(eventListenerMgr.FindEventTypes([](const std::string &type) -> bool {
        return type == EVENT_TYPE_TEST;
    }).empty());
}

HWTEST_F(EventListenerMgrTest, OnRemoteListenerDied_ShouldDoNothing_WhenListenerNull, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<IPrintCallback> listener = new MockPrintCallbackProxy();
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    eventListenerMgr.OnRemoteListenerDied(nullptr);
    EXPECT_FALSE(eventListenerMgr.FindEventTypes([](const std::string &type) -> bool {
        return type == EVENT_TYPE_TEST;
    }).empty());
}

HWTEST_F(EventListenerMgrTest, OnRemoteListenerDied_ShouldEraseListener_WhenListenerRegistered, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_CALL(*listener, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    eventListenerMgr.OnRemoteListenerDied(listener->AsObject());
    EXPECT_TRUE(eventListenerMgr.FindEventTypes([](const std::string &type) -> bool {
        return type == EVENT_TYPE_TEST;
    }).empty());
}

HWTEST_F(EventListenerMgrTest, OnRemoteListenerDied_ShouldKeepOther_WhenListenerDied, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_CALL(*listener, AsObject()).WillRepeatedly(Return(obj));
    sptr<MockPrintCallbackProxy> listenerOther = new MockPrintCallbackProxy();
    sptr<MockRemoteObject> objOther = new MockRemoteObject();
    EXPECT_CALL(*listenerOther, AsObject()).WillRepeatedly(Return(objOther));
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener("Other", listenerOther));
    eventListenerMgr.OnRemoteListenerDied(listener->AsObject());
    EXPECT_TRUE(eventListenerMgr.FindEventListener(EVENT_TYPE_TEST) == nullptr);
    EXPECT_TRUE(eventListenerMgr.FindEventListener("Other") != nullptr);
}

HWTEST_F(EventListenerMgrTest, RemoveDeathRecipient_ShouldReturnFalse_WhenListenerNull, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.RemoveDeathRecipient(nullptr));
}

HWTEST_F(EventListenerMgrTest, AddDeathRecipient_ShouldReturnFalse_WhenListenerNull, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    EXPECT_FALSE(eventListenerMgr.AddDeathRecipient(nullptr));
}

HWTEST_F(EventListenerMgrTest, OnRemoteDied_ShouldErase_WhenListenerDied, TestSize.Level1)
{
    EventListenerMgr eventListenerMgr;
    sptr<MockPrintCallbackProxy> listener = new MockPrintCallbackProxy();
    sptr<MockRemoteObject> obj = new MockRemoteObject();
    EXPECT_CALL(*listener, AsObject()).WillRepeatedly(Return(obj));
    EXPECT_TRUE(eventListenerMgr.RegisterEventListener(EVENT_TYPE_TEST, listener));
    eventListenerMgr.eventListenerDeathRecipient_->OnRemoteDied(nullptr);
    eventListenerMgr.eventListenerDeathRecipient_->OnRemoteDied(obj);
    EXPECT_TRUE(eventListenerMgr.FindEventTypes([](const std::string &type) -> bool {
        return type == EVENT_TYPE_TEST;
    }).empty());
}
}  // namespace Print
}  // namespace OHOS
