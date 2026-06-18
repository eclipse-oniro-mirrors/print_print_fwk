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
#define private public
#include "js_print_extension.h"
#include "print_manager_client.h"
#undef private
#include "mock_runtime.h"
#include "mock_print_service.h"
#include "mock_remote_object.h"
#include "print_extension_callback_stub.h"
#include "iprint_extension_callback.h"
#include "print_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::Print;

class JsPrintExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUpProxy(void);
    void TearDownProxy(void);
private:
    sptr<MockRemoteObject> proxyObj_ = nullptr;
};

void JsPrintExtensionTest::SetUpTestCase(void)
{}

void JsPrintExtensionTest::TearDownTestCase(void)
{}

void JsPrintExtensionTest::SetUpProxy(void)
{
    auto service = std::make_shared<MockPrintService>();
    EXPECT_NE(service, nullptr);
    EXPECT_CALL(*service, RegisterExtCallback(_, _)).WillRepeatedly(Return(E_PRINT_NONE));
    proxyObj_ = new (std::nothrow) MockRemoteObject();
    EXPECT_NE(proxyObj_, nullptr);
    EXPECT_CALL(*proxyObj_, IsProxyObject()).WillRepeatedly(Return(true));
    EXPECT_CALL(*proxyObj_, RemoveDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*proxyObj_, AddDeathRecipient(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*proxyObj_, SendRequest(_, _, _, _)).WillRepeatedly(
        [service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service->OnRemoteRequest(code, data, reply, option);
            return E_PRINT_NONE;
        });
    PrintManagerClient::GetInstance()->SetProxy(proxyObj_);
    PrintManagerClient::GetInstance()->LoadServerSuccess(nullptr);
}

void JsPrintExtensionTest::TearDownProxy(void)
{
    if (PrintManagerClient::GetInstance()->deathRecipient_ != nullptr && proxyObj_ != nullptr) {
        PrintManagerClient::GetInstance()->deathRecipient_->OnRemoteDied(proxyObj_);
    }
    proxyObj_ = nullptr;
}

/**
 * @tc.name: JsPrintExtensionTest_Callback_WeakPtrEmpty_0001
 * @tc.desc: Callback(string) returns false when jsExtension_ weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_Callback_WeakPtrEmpty_0001, TestSize.Level0)
{
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    EXPECT_FALSE(ext->Callback("testFunc"));
    delete ext;
}

/**
 * @tc.name: JsPrintExtensionTest_Callback_WeakPtrEmpty_0002
 * @tc.desc: Callback(string, string) returns false when jsExtension_ weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_Callback_WeakPtrEmpty_0002, TestSize.Level0)
{
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    EXPECT_FALSE(ext->Callback("testFunc", std::string("printer1")));
    delete ext;
}

/**
 * @tc.name: JsPrintExtensionTest_Callback_WeakPtrEmpty_0003
 * @tc.desc: Callback(string, PrintJob) returns false when jsExtension_ weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_Callback_WeakPtrEmpty_0003, TestSize.Level0)
{
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    PrintJob job;
    EXPECT_FALSE(ext->Callback("testFunc", job));
    delete ext;
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterDiscoveryCb_Lambda_EmptyPath_0001
 * @tc.desc: onStartDiscoverPrinter lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterDiscoveryCb_Lambda_EmptyPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterDiscoveryCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_START_DISCOVERY);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    EXPECT_FALSE(it->second->OnCallback());
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterDiscoveryCb_Lambda_EmptyPath_0002
 * @tc.desc: onStopDiscoverPrinter lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterDiscoveryCb_Lambda_EmptyPath_0002, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterDiscoveryCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_STOP_DISCOVERY);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    EXPECT_FALSE(it->second->OnCallback());
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterConnectionCb_Lambda_EmptyPath_0001
 * @tc.desc: onConnectPrinter lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterConnectionCb_Lambda_EmptyPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterConnectionCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_CONNECT_PRINTER);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    EXPECT_FALSE(it->second->OnCallback("testPrinterId"));
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterConnectionCb_Lambda_EmptyPath_0002
 * @tc.desc: onDisconnectPrinter lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterConnectionCb_Lambda_EmptyPath_0002, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterConnectionCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_DISCONNECT_PRINTER);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    EXPECT_FALSE(it->second->OnCallback("testPrinterId"));
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterPrintJobCb_Lambda_EmptyPath_0001
 * @tc.desc: onStartPrintJob lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterPrintJobCb_Lambda_EmptyPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterPrintJobCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_START_PRINT);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    PrintJob job;
    EXPECT_FALSE(it->second->OnCallback(job));
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterPrintJobCb_Lambda_EmptyPath_0002
 * @tc.desc: onCancelPrintJob lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterPrintJobCb_Lambda_EmptyPath_0002, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterPrintJobCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_CANCEL_PRINT);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    PrintJob job;
    EXPECT_FALSE(it->second->OnCallback(job));
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterPreviewCb_Lambda_EmptyPath_0001
 * @tc.desc: onRequestPreview lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterPreviewCb_Lambda_EmptyPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterPreviewCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_REQUEST_PREVIEW);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    PrintJob job;
    EXPECT_FALSE(it->second->OnCallback(job));
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterQueryCapCb_Lambda_EmptyPath_0001
 * @tc.desc: onRequestPrinterCapability lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterQueryCapCb_Lambda_EmptyPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterQueryCapCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_REQUEST_CAP);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    EXPECT_FALSE(it->second->OnCallback("testPrinterId"));
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterExtensionCb_Lambda_EmptyPath_0001
 * @tc.desc: destroy extension lambda returns false when weak_ptr is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterExtensionCb_Lambda_EmptyPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    ext->RegisterExtensionCb();

    std::string cid = PrintUtils::EncodeExtensionCid(ext->extensionId_, PRINT_EXTCB_DESTROY_EXTENSION);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    EXPECT_FALSE(it->second->OnCallback());
    delete ext;
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterHelper_0001
 * @tc.desc: RegisterHelper with empty list returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterHelper_0001, TestSize.Level0)
{
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    auto *ext = JsPrintExtension::Create(runtime);
    ASSERT_NE(ext, nullptr);
    EXPECT_TRUE(ext->RegisterHelper({}));
    delete ext;
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterDiscoveryCb_Lambda_ValidPath_0001
 * @tc.desc: onStartDiscoverPrinter lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterDiscoveryCb_Lambda_ValidPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterDiscoveryCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_START_DISCOVERY);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    it->second->OnCallback();

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterDiscoveryCb_Lambda_ValidPath_0002
 * @tc.desc: onStopDiscoverPrinter lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterDiscoveryCb_Lambda_ValidPath_0002, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterDiscoveryCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_STOP_DISCOVERY);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    it->second->OnCallback();

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterConnectionCb_Lambda_ValidPath_0001
 * @tc.desc: onConnectPrinter lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterConnectionCb_Lambda_ValidPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterConnectionCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_CONNECT_PRINTER);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    it->second->OnCallback("testPrinterId");

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterConnectionCb_Lambda_ValidPath_0002
 * @tc.desc: onDisconnectPrinter lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterConnectionCb_Lambda_ValidPath_0002, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterConnectionCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_DISCONNECT_PRINTER);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    it->second->OnCallback("testPrinterId");

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterPrintJobCb_Lambda_ValidPath_0001
 * @tc.desc: onStartPrintJob lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterPrintJobCb_Lambda_ValidPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterPrintJobCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_START_PRINT);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    PrintJob job;
    it->second->OnCallback(job);

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterPrintJobCb_Lambda_ValidPath_0002
 * @tc.desc: onCancelPrintJob lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterPrintJobCb_Lambda_ValidPath_0002, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterPrintJobCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_CANCEL_PRINT);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    PrintJob job;
    it->second->OnCallback(job);

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterPreviewCb_Lambda_ValidPath_0001
 * @tc.desc: onRequestPreview lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterPreviewCb_Lambda_ValidPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterPreviewCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_REQUEST_PREVIEW);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    PrintJob job;
    it->second->OnCallback(job);

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterQueryCapCb_Lambda_ValidPath_0001
 * @tc.desc: onRequestPrinterCapability lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterQueryCapCb_Lambda_ValidPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterQueryCapCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_REQUEST_CAP);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    it->second->OnCallback("testPrinterId");

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

/**
 * @tc.name: JsPrintExtensionTest_RegisterExtensionCb_Lambda_ValidPath_0001
 * @tc.desc: destroy extension lambda executes with valid jsExtension_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JsPrintExtensionTest, JsPrintExtensionTest_RegisterExtensionCb_Lambda_ValidPath_0001, TestSize.Level0)
{
    SetUpProxy();
    std::unique_ptr<Runtime> runtime = std::make_unique<MockRuntimeJS>();
    std::shared_ptr<JsPrintExtension> extPtr(new JsPrintExtension(static_cast<JsRuntime &>(*runtime)));
    JsPrintExtension::jsExtension_ = extPtr;
    extPtr->RegisterExtensionCb();

    std::string cid = PrintUtils::EncodeExtensionCid(extPtr->extensionId_, PRINT_EXTCB_DESTROY_EXTENSION);
    auto it = PrintManagerClient::GetInstance()->extCallbackMap_.find(cid);
    ASSERT_NE(it, PrintManagerClient::GetInstance()->extCallbackMap_.end());
    it->second->OnCallback();

    JsPrintExtension::jsExtension_.reset();
    TearDownProxy();
}

}  // namespace AbilityRuntime
}  // namespace OHOS
