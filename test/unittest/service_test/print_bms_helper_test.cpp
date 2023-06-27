#include <gtest/gtest.h>
#include "print_bms_helper.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintBMSHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintBMSHelperTest::SetUpTestCase(void) {}

void PrintBMSHelperTest::TearDownTestCase(void) {}

void PrintBMSHelperTest::SetUp(void) {}

void PrintBMSHelperTest::TearDown(void) {}

/**
* @tc.name: PrintBMSHelperTest_0001
* @tc.desc: PrintBMSHelper
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintBMSHelper printBMSHelper;
    printBMSHelper.ResetProxy();
    printBMSHelper.~PrintBMSHelper();
}

/**
* @tc.name: PrintBMSHelperTest_0002
* @tc.desc: QueryExtensionInfos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintBMSHelper printBMSHelper;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfo;
    EXPECT_TRUE(printBMSHelper.QueryExtensionInfos(extensionInfo));
}

/**
* @tc.name: PrintBMSHelperTest_0003
* @tc.desc: QueryCallerBundleName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintBMSHelperTest, PrintBMSHelperTest_0003, TestSize.Level1)
{
    OHOS::Print::PrintBMSHelper printBMSHelper;
    EXPECT_EQ("", printBMSHelper.QueryCallerBundleName());
}
} // namespace Print
} // namespace OHOS