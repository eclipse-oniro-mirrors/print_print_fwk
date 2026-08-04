/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include "print_preview_attribute.h"
#include "print_constant.h"
#include "printer_capability.h"
#include "print_margin.h"
#include "print_range.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {
class PrintPreviewAttributeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintPreviewAttributeTest::SetUpTestCase(void)
{}

void PrintPreviewAttributeTest::TearDownTestCase(void)
{}

void PrintPreviewAttributeTest::SetUp(void)
{}

void PrintPreviewAttributeTest::TearDown(void)
{}

/**
 * @tc.name: PrintPreviewAttributeTest_0001
 * @tc.desc: Verify the constructor function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0001, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.Dump();
    EXPECT_FALSE(attribute.HasResult());
    const uint32_t PRINT_INVALID_ID = 0xFFFFFFFF;
    EXPECT_EQ(attribute.GetResult(), PRINT_INVALID_ID);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0002
 * @tc.desc: Verify the hasResult function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0002, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.Reset();
    EXPECT_FALSE(attribute.HasResult());
}

/**
 * @tc.name: PrintPreviewAttributeTest_0003
 * @tc.desc: Verify the getResult function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0003, TestSize.Level1)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.SetResult(static_cast<uint32_t>(pipefd[1]));
    EXPECT_EQ(static_cast<uint32_t>(pipefd[1]), attribute.GetResult());
    close(pipefd[0]);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0004
 * @tc.desc: Verify the hasStartPage function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0004, TestSize.Level1)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintRange printRange;
    attribute.SetResult(static_cast<uint32_t>(pipefd[1]));
    attribute.SetPreviewRange(printRange);
    PrintRange previewRange;
    attribute.GetPreviewRange(previewRange);
    EXPECT_FALSE(previewRange.HasStartPage());
    close(pipefd[0]);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0005
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0005, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintRange printRange;
    attribute.SetPreviewRange(printRange);
    Parcel parcel;
    EXPECT_TRUE(attribute.Marshalling(parcel));
}

/**
 * @tc.name: PrintPreviewAttributeTest_0006
 * @tc.desc: Verify the marshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0006, TestSize.Level1)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintRange printRange;
    attribute.SetPreviewRange(printRange);
    attribute.SetResult(6);
    Parcel parcel;
    EXPECT_TRUE(attribute.Marshalling(parcel));

    // Unmarshalling and verify result fd is a valid dup
    auto result = OHOS::Print::PrintPreviewAttribute::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_TRUE(result->HasResult());
    EXPECT_NE(result->GetResult(), static_cast<uint32_t>(pipefd[1]));
    EXPECT_GT(result->GetResult(), OHOS::Print::STD_FD_MAX);

    close(pipefd[0]);
    close(pipefd[1]);
    close(result->GetResult());
}

/**
 * @tc.name: PrintPreviewAttributeTest_0007
 * @tc.desc: Verify the unmarshalling function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0007, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintRange printRange;
    attribute.SetPreviewRange(printRange);
    Parcel parcel;
    attribute.Marshalling(parcel);
    auto result = OHOS::Print::PrintPreviewAttribute::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0008
 * @tc.desc: Verify copy constructor dup fd success when hasResult is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0008, TestSize.Level1)
{
    // Create a temp fd via pipe
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.SetResult(static_cast<uint32_t>(pipefd[1]));
    EXPECT_TRUE(attribute.HasResult());

    // Copy constructor should dup the fd
    OHOS::Print::PrintPreviewAttribute copyAttr(attribute);
    EXPECT_TRUE(copyAttr.HasResult());
    EXPECT_NE(copyAttr.GetResult(), static_cast<uint32_t>(pipefd[1]));
    // The dup'd fd should be valid (> STD_FD_MAX)
    EXPECT_GT(copyAttr.GetResult(), OHOS::Print::STD_FD_MAX);

    // Clean up: close original pipe fds and dup'd fd
    close(pipefd[0]);
    close(pipefd[1]);
    close(copyAttr.GetResult());
}

/**
 * @tc.name: PrintPreviewAttributeTest_0009
 * @tc.desc: Verify copy constructor when hasResult is false (no dup).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0009, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    // hasResult_ is false by default, no dup should happen
    OHOS::Print::PrintPreviewAttribute copyAttr(attribute);
    EXPECT_FALSE(copyAttr.HasResult());
    EXPECT_EQ(copyAttr.GetResult(), OHOS::Print::PRINT_INVALID_ID);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0010
 * @tc.desc: Verify copy constructor dup fd failure (closed fd -> dup returns -1).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0010, TestSize.Level1)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    // Close the write end so dup will fail
    close(pipefd[1]);

    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.SetResult(static_cast<uint32_t>(pipefd[1]));
    // The fd is already closed, dup should fail
    OHOS::Print::PrintPreviewAttribute copyAttr(attribute);
    EXPECT_TRUE(copyAttr.HasResult());
    // When dup fails, result_ stays as the original (invalid) fd value
    EXPECT_EQ(copyAttr.GetResult(), static_cast<uint32_t>(pipefd[1]));

    close(pipefd[0]);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0011
 * @tc.desc: Verify assignment operator dup fd success when hasResult is true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0011, TestSize.Level1)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);

    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.SetResult(static_cast<uint32_t>(pipefd[1]));

    OHOS::Print::PrintPreviewAttribute assignTarget;
    assignTarget = attribute;
    EXPECT_TRUE(assignTarget.HasResult());
    EXPECT_NE(assignTarget.GetResult(), static_cast<uint32_t>(pipefd[1]));
    EXPECT_GT(assignTarget.GetResult(), OHOS::Print::STD_FD_MAX);

    close(pipefd[0]);
    close(pipefd[1]);
    close(assignTarget.GetResult());
}

/**
 * @tc.name: PrintPreviewAttributeTest_0012
 * @tc.desc: Verify assignment operator when hasResult is false (no dup).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0012, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    OHOS::Print::PrintPreviewAttribute assignTarget;
    assignTarget = attribute;
    EXPECT_FALSE(assignTarget.HasResult());
    EXPECT_EQ(assignTarget.GetResult(), OHOS::Print::PRINT_INVALID_ID);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0013
 * @tc.desc: Verify assignment operator dup fd failure (closed fd).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0013, TestSize.Level1)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    close(pipefd[1]);

    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.SetResult(static_cast<uint32_t>(pipefd[1]));

    OHOS::Print::PrintPreviewAttribute assignTarget;
    assignTarget = attribute;
    EXPECT_TRUE(assignTarget.HasResult());
    // dup failed, result_ stays as the original (now-invalid) fd value
    EXPECT_EQ(assignTarget.GetResult(), static_cast<uint32_t>(pipefd[1]));

    close(pipefd[0]);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0015
 * @tc.desc: Verify destructor closes valid fd (CLOSE_FD_IF_VALID).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0015, TestSize.Level1)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);

    {
        OHOS::Print::PrintPreviewAttribute attribute;
        attribute.SetResult(static_cast<uint32_t>(pipefd[1]));
        // attribute goes out of scope, destructor calls CLOSE_FD_IF_VALID(result_)
    }
    // pipefd[1] was closed by destructor; verify second close returns -1
    EXPECT_EQ(close(pipefd[1]), -1);
    close(pipefd[0]);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0016
 * @tc.desc: Verify Reset closes valid fd via CLOSE_FD_IF_VALID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0016, TestSize.Level1)
{
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);

    OHOS::Print::PrintPreviewAttribute attribute;
    attribute.SetResult(static_cast<uint32_t>(pipefd[1]));
    EXPECT_TRUE(attribute.HasResult());

    // Reset should close the fd and clear hasResult_
    attribute.Reset();
    EXPECT_FALSE(attribute.HasResult());

    // The fd should now be closed (CLOSE_FD_IF_VALID called close)
    // Verify by trying to close again — second close should return -1
    EXPECT_EQ(close(pipefd[1]), -1);

    close(pipefd[0]);
}

/**
 * @tc.name: PrintPreviewAttributeTest_0017
 * @tc.desc: Verify Reset on attribute with no result (PRINT_INVALID_ID) does not close invalid fd.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintPreviewAttributeTest, PrintPreviewAttributeTest_0017, TestSize.Level1)
{
    OHOS::Print::PrintPreviewAttribute attribute;
    // Default: hasResult_=false, result_=PRINT_INVALID_ID
    // Reset should not attempt to close PRINT_INVALID_ID (CLOSE_FD_IF_VALID guards it)
    attribute.Reset();
    EXPECT_FALSE(attribute.HasResult());
}

}  // namespace Print
}  // namespace OHOS