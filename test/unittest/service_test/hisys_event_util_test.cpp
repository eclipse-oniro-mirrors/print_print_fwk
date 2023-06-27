#include <gtest/gtest.h>
#include "hisys_event_util.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class HisysEventUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HisysEventUtilTest::SetUpTestCase(void) {}

void HisysEventUtilTest::TearDownTestCase(void) {}

void HisysEventUtilTest::SetUp(void) {}

void HisysEventUtilTest::TearDown(void) {}

/**
* @tc.name: HisysEventUtilTest_0001
* @tc.desc: OnRemoteRequest
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(HisysEventUtilTest, HisysEventUtilTest_0001, TestSize.Level1)
{
    OHOS::Print::HisysEventUtil::reportPrintSuccess("printSuccess");
    OHOS::Print::HisysEventUtil::faultPrint("printfault", "errCode");
}
} // namespace Print
} // namespace OHOS