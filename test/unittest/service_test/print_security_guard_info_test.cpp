#include <gtest/gtest.h>
#include "print_security_guard_info.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintSecurityGuardInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintSecurityGuardInfoTest::SetUpTestCase(void) {}

void PrintSecurityGuardInfoTest::TearDownTestCase(void) {}

void PrintSecurityGuardInfoTest::SetUp(void) {}

void PrintSecurityGuardInfoTest::TearDown(void) {}

/**
* @tc.name: PrintSecurityGuardInfoTest_0001
* @tc.desc: OnRemoteRequest
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(PrintSecurityGuardInfoTest, PrintSecurityGuardInfoTest_0001, TestSize.Level1)
{
    std::vector<std::string> fileList;
    OHOS::Print::PrintSecurityGuardInfo printSecurityGuardInfo("callPkg", fileList);
    OHOS::Print::PrinterInfo printerInfo;
    OHOS::Print::PrintJob printJob;
    printSecurityGuardInfo.setPrintTypeInfo(printerInfo, printJob);
    EXPECT_NE("", printSecurityGuardInfo.ToJsonStr());
}
} // namespace Print
} // namespace OHOS