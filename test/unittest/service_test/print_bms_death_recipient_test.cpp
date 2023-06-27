#include <gtest/gtest.h>
#include "hisys_event_util.h"
#include "print_constant.h"
#include "print_log.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintBMSDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintBMSDeathRecipientTest::SetUpTestCase(void) {}

void PrintBMSDeathRecipientTest::TearDownTestCase(void) {}

void PrintBMSDeathRecipientTest::SetUp(void) {}

void PrintBMSDeathRecipientTest::TearDown(void) {}

/**
* @tc.name: PrintBMSDeathRecipientTest_0001
* @tc.desc: OnRemoteRequest
* @tc.type: FUNC
* @tc.require:
*/
// HWTEST_F(PrintBMSDeathRecipientTest, PrintBMSDeathRecipientTest_0001, TestSize.Level1)
// {
//     OHOS::Print::PrintBMSDeathRecipient::OnRemoteDied("printSuccess");
// }
} // namespace Print
} // namespace OHOS