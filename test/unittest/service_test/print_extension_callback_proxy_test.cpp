#include <gtest/gtest.h>
#include "print_extension_callback_proxy.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintExtensionCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintExtensionCallbackProxyTest::SetUpTestCase(void) {}

void PrintExtensionCallbackProxyTest::TearDownTestCase(void) {}

void PrintExtensionCallbackProxyTest::SetUp(void) {}

void PrintExtensionCallbackProxyTest::TearDown(void) {}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0001
 * @tc.desc: PrintExtensionCallbackProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0001, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintExtensionCallbackProxy printExtensionCallbackProxy(impl);
    printExtensionCallbackProxy.~PrintExtensionCallbackProxy();
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0002
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0002, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintExtensionCallbackProxy printExtensionCallbackProxy(impl);
    EXPECT_TRUE(printExtensionCallbackProxy.OnCallback());
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0003
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0003, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintExtensionCallbackProxy printExtensionCallbackProxy(impl);
    EXPECT_TRUE(printExtensionCallbackProxy.OnCallback("print-1"));
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0004
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0004, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintExtensionCallbackProxy printExtensionCallbackProxy(impl);
    OHOS::Print::PrintJob printJob;
    EXPECT_TRUE(printExtensionCallbackProxy.OnCallback(printJob));
}

/**
 * @tc.name: PrintExtensionCallbackProxyTest_0005
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintExtensionCallbackProxyTest, PrintExtensionCallbackProxyTest_0005, TestSize.Level1)
{
    const sptr<IRemoteObject> impl;
    OHOS::Print::PrintExtensionCallbackProxy printExtensionCallbackProxy(impl);
    OHOS::Print::PrinterCapability printerCapability;
    EXPECT_TRUE(printExtensionCallbackProxy.OnCallback("print-1", printerCapability));
}
} // namespace Print
} // namespace OHOS