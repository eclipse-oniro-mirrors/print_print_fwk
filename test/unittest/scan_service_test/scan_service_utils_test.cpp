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

#include <fcntl.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "scan_constant.h"
#include "scan_service_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace Scan {

class ScanServiceUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanServiceUtilsTest::SetUpTestCase(void) {}
void ScanServiceUtilsTest::TearDownTestCase(void) {}

/**
 * @tc.name: ScanServiceUtilsTest_ReplaceDeviceIdUsbPort_Valid_0001
 * @tc.desc: Verify a valid usb port replaces the trailing device id segments.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_ReplaceDeviceIdUsbPort_Valid_0001, TestSize.Level2)
{
    std::string result = ScanServiceUtils::ReplaceDeviceIdUsbPort("usb:001:002:003:004", "1-2");
    EXPECT_EQ("usb:001:002:001:002", result);
}

/**
 * @tc.name: ScanServiceUtilsTest_ReplaceDeviceIdUsbPort_InvalidPort_0002
 * @tc.desc: Verify malformed usb ports return an empty string.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_ReplaceDeviceIdUsbPort_InvalidPort_0002, TestSize.Level2)
{
    EXPECT_EQ("", ScanServiceUtils::ReplaceDeviceIdUsbPort("usb:001:002:003:004", "abc"));
    EXPECT_EQ("", ScanServiceUtils::ReplaceDeviceIdUsbPort("usb:001:002:003:004", "1"));
    EXPECT_EQ("", ScanServiceUtils::ReplaceDeviceIdUsbPort("usb:001:002:003:004", "-1-2"));
}

/**
 * @tc.name: ScanServiceUtilsTest_ReplaceDeviceIdUsbPort_InvalidDeviceId_0003
 * @tc.desc: Verify malformed device ids return an empty string.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_ReplaceDeviceIdUsbPort_InvalidDeviceId_0003, TestSize.Level2)
{
    EXPECT_EQ("", ScanServiceUtils::ReplaceDeviceIdUsbPort("nocolon", "1-2"));
    EXPECT_EQ("", ScanServiceUtils::ReplaceDeviceIdUsbPort(":x", "1-2"));
    EXPECT_EQ("", ScanServiceUtils::ReplaceDeviceIdUsbPort("a:1", "1-2"));
}

/**
 * @tc.name: ScanServiceUtilsTest_EncodeTaskEventId_0004
 * @tc.desc: Verify encoding extracts the trailing type after the last delimiter.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_EncodeTaskEventId_0004, TestSize.Level2)
{
    std::string type;
    EXPECT_TRUE(ScanServiceUtils::EncodeTaskEventId("100-200-task1-scan", type));
    EXPECT_EQ("scan", type);

    std::string noDelimiterType = "unchanged";
    EXPECT_FALSE(ScanServiceUtils::EncodeTaskEventId("scanevent", noDelimiterType));
    EXPECT_EQ("unchanged", noDelimiterType);
}

/**
 * @tc.name: ScanServiceUtilsTest_GetTaskEventId_0005
 * @tc.desc: Verify event id composition with and without a task id.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_GetTaskEventId_0005, TestSize.Level2)
{
    EXPECT_EQ("100-200-task1-scan", ScanServiceUtils::GetTaskEventId("task1", "scan", 100, 200));
    EXPECT_EQ("100-200-scan", ScanServiceUtils::GetTaskEventId("", "scan", 100, 200));
}

/**
 * @tc.name: ScanServiceUtilsTest_DecodeTaskEventId_Valid_0006
 * @tc.desc: Verify decoding extracts user id and caller pid.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_DecodeTaskEventId_Valid_0006, TestSize.Level2)
{
    int32_t userId = 0;
    int32_t callerPid = 0;
    EXPECT_TRUE(ScanServiceUtils::DecodeTaskEventId("100-200-task1-scan", userId, callerPid));
    EXPECT_EQ(100, userId);
    EXPECT_EQ(200, callerPid);
}

/**
 * @tc.name: ScanServiceUtilsTest_DecodeTaskEventId_Invalid_0007
 * @tc.desc: Verify decoding fails for missing or non-numeric segments.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_DecodeTaskEventId_Invalid_0007, TestSize.Level2)
{
    int32_t userId = 0;
    int32_t callerPid = 0;
    EXPECT_FALSE(ScanServiceUtils::DecodeTaskEventId("100", userId, callerPid));
    EXPECT_FALSE(ScanServiceUtils::DecodeTaskEventId("100-abc", userId, callerPid));
    EXPECT_FALSE(ScanServiceUtils::DecodeTaskEventId("abc-def-x", userId, callerPid));
    EXPECT_FALSE(ScanServiceUtils::DecodeTaskEventId("100-abc-x", userId, callerPid));
}

/**
 * @tc.name: ScanServiceUtilsTest_ConvertErro_0008
 * @tc.desc: Verify known sane statuses map to scan error codes and unknown falls back.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_ConvertErro_0008, TestSize.Level2)
{
    EXPECT_EQ(E_SCAN_NONE, ScanServiceUtils::ConvertErro(SANE_STATUS_GOOD));
    EXPECT_EQ(E_SCAN_TLS_CERT_CHANGED, ScanServiceUtils::ConvertErro(SANE_STATUS_TLS_CERT_CHANGED));
    EXPECT_EQ(E_SCAN_DEVICE_BUSY, ScanServiceUtils::ConvertErro(SANE_STATUS_DEVICE_BUSY));
    EXPECT_EQ(E_SCAN_GENERIC_FAILURE, ScanServiceUtils::ConvertErro(static_cast<SaneStatus>(999999)));
}

/**
 * @tc.name: ScanServiceUtilsTest_ExtractIpOrPortFromUrl_0009
 * @tc.desc: Verify token splitting and minimum token length filtering.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_ExtractIpOrPortFromUrl_0009, TestSize.Level2)
{
    auto tokens = ScanServiceUtils::ExtractIpOrPortFromUrl("1.2.3.4:80", ':', 2);
    ASSERT_EQ(2u, tokens.size());
    EXPECT_EQ("1.2.3.4", tokens[0]);
    EXPECT_EQ("80", tokens[1]);

    auto tooFew = ScanServiceUtils::ExtractIpOrPortFromUrl("1.2.3.4:80", ':', 3);
    EXPECT_TRUE(tooFew.empty());

    auto single = ScanServiceUtils::ExtractIpOrPortFromUrl("abc", ':', 1);
    ASSERT_EQ(1u, single.size());
    EXPECT_EQ("abc", single[0]);
}

/**
 * @tc.name: ScanServiceUtilsTest_GetPathFromFd_0010
 * @tc.desc: Verify invalid fd returns empty and a valid fd resolves to its path.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_GetPathFromFd_0010, TestSize.Level2)
{
    EXPECT_EQ("", ScanServiceUtils::GetPathFromFd(-1));

    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    std::string path = ScanServiceUtils::GetPathFromFd(fd);
    close(fd);
    EXPECT_EQ("/dev/null", path);
}

/**
 * @tc.name: ScanServiceUtilsTest_ExtractBaseName_0011
 * @tc.desc: Verify the .jpg suffix is stripped and other suffixes are preserved.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_ExtractBaseName_0011, TestSize.Level2)
{
    EXPECT_EQ("test", ScanServiceUtils::ExtractBaseName("test.jpg"));
    EXPECT_EQ("/data/local/tmp/test", ScanServiceUtils::ExtractBaseName("/data/local/tmp/test.jpg"));
    EXPECT_EQ("test.jpeg", ScanServiceUtils::ExtractBaseName("test.jpeg"));
    EXPECT_EQ("noext", ScanServiceUtils::ExtractBaseName("noext"));
}

/**
 * @tc.name: ScanServiceUtilsTest_IsPathValid_0012
 * @tc.desc: Verify existing parent directory is valid and missing parent is invalid.
 */
HWTEST_F(ScanServiceUtilsTest, ScanServiceUtilsTest_IsPathValid_0012, TestSize.Level2)
{
    EXPECT_TRUE(ScanServiceUtils::IsPathValid("/system/scan_ut.jpg"));
    EXPECT_FALSE(ScanServiceUtils::IsPathValid("/nonexistent_scan_ut_dir/scan_ut.jpg"));
}

}  // namespace Scan
}  // namespace OHOS
