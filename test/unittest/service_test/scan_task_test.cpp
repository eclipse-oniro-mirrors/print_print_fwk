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
#include "scan_task.h"

constexpr int32_t DEFAULT_USER_ID = 100;
constexpr int32_t INVALID_USER_ID = 0x0FFEFEFE;
constexpr int32_t TEST_IMAGE_WIDTH = 1917;
constexpr int32_t TEST_IMAGE_HEIGHT = 1080;
constexpr int32_t TEST_IMAGE_STRIDE_RGB = 1920 * 3;
constexpr int32_t DEFAULT_SCANPARAM_DEPTH_RGB = 24;
constexpr int32_t DEFAULT_SCANPARAM_DEPTH_GREY = 8;
constexpr int32_t DEFAULT_SCANPARAM_DEPTH_MONO = 1;
constexpr uint16_t DEFAULT_SCAN_DPI = 300;

namespace OHOS {
namespace Scan {
using namespace testing::ext;
class ScanTaskTest : public ::testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

    void TestImageEncode(const ScanParameters& scanParam, ImageFormat imgFmt, std::string& imgPath);
};

void ScanTaskTest::SetUp()
{
}

void ScanTaskTest::TearDown()
{
}

void ScanTaskTest::TestImageEncode(const ScanParameters& scanParam, ImageFormat imgFmt, std::string& imgPath)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_TRUE(scanTask.CreateAndOpenScanFile(imgPath, imgFmt));
    ASSERT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_NONE);

    size_t dataLeft = scanParam.GetBytesPerLine() * scanParam.GetLines();
    size_t dataBlock = scanParam.GetBytesPerLine() * 2 - 1;
    std::vector<uint8_t> dataBuffer(dataBlock, 0x00);
    for (; dataLeft > 0; dataLeft -= dataBuffer.size()) {
        if (dataLeft < dataBlock) {
            dataBuffer.resize(dataLeft, 0x00);
        }
        
        ASSERT_EQ(scanTask.WriteImageData(dataBuffer), E_SCAN_NONE);
    }

    scanTask.ImageFinishCompress();
}

HWTEST_F(ScanTaskTest, CreateAndOpenScanFile_Normal, TestSize.Level1)
{
    std::string filePath;
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_TRUE(scanTask.CreateAndOpenScanFile(filePath));
    ASSERT_FALSE(filePath.empty());
}

HWTEST_F(ScanTaskTest, CreateAndOpenScanFile_InvalidUserId, TestSize.Level1)
{
    std::string filePath;
    ScanTask scanTask("", INVALID_USER_ID, false);
    ASSERT_FALSE(scanTask.CreateAndOpenScanFile(filePath));
}

HWTEST_F(ScanTaskTest, CreateAndOpenScanFile_OpenRepeatedly, TestSize.Level1)
{
    std::string filePath;
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_TRUE(scanTask.CreateAndOpenScanFile(filePath));
    ASSERT_FALSE(scanTask.CreateAndOpenScanFile(filePath));
}

HWTEST_F(ScanTaskTest, CreateAndOpenScanFile_ImageTypePng, TestSize.Level1)
{
    std::string filePath;
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_TRUE(scanTask.CreateAndOpenScanFile(filePath, ImageFormat::IMAGE_TYPE_PNG));
}

HWTEST_F(ScanTaskTest, CreateAndOpenScanFile_ImageTypeNone, TestSize.Level1)
{
    std::string filePath;
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_FALSE(scanTask.CreateAndOpenScanFile(filePath, ImageFormat::IMAGE_TYPE_NONE));
}

HWTEST_F(ScanTaskTest, WriteImageData_RGB, TestSize.Level1)
{
    std::string imgPath;
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_RGB);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_RGB);
    scanParam.SetBytesPerLine(TEST_IMAGE_STRIDE_RGB);
    TestImageEncode(scanParam, ImageFormat::IMAGE_TYPE_JPEG, imgPath);
    ASSERT_FALSE(imgPath.empty());
    ASSERT_EQ(access(imgPath.c_str(), 0), 0);
}

HWTEST_F(ScanTaskTest, WriteImageData_Grey, TestSize.Level1)
{
    std::string imgPath;
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_GRAY);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_GREY);
    scanParam.SetBytesPerLine(TEST_IMAGE_WIDTH);
    TestImageEncode(scanParam, ImageFormat::IMAGE_TYPE_PNG, imgPath);
    ASSERT_FALSE(imgPath.empty());
    ASSERT_EQ(access(imgPath.c_str(), 0), 0);
}

HWTEST_F(ScanTaskTest, WriteImageData_Mono, TestSize.Level1)
{
    std::string imgPath;
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_GRAY);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_MONO);
    scanParam.SetBytesPerLine((TEST_IMAGE_WIDTH + 7) / 8);
    TestImageEncode(scanParam, ImageFormat::IMAGE_TYPE_JPEG, imgPath);
    ASSERT_FALSE(imgPath.empty());
    ASSERT_EQ(access(imgPath.c_str(), 0), 0);
}

HWTEST_F(ScanTaskTest, WriteImageData_InvalidParam, TestSize.Level1)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);

    uint8_t dummyPicBuf[1] = { 0 };
    std::vector<uint8_t> dataBuffer;
    EXPECT_EQ(scanTask.WriteImageData(dataBuffer), E_SCAN_GENERIC_FAILURE);

    scanTask.picBuf_ = dummyPicBuf;
    EXPECT_EQ(scanTask.WriteImageData(dataBuffer), E_SCAN_GENERIC_FAILURE);

    scanTask.pixMap_ = std::make_unique<Media::PixelMap>();
    ASSERT_NE(scanTask.pixMap_, nullptr);
    EXPECT_EQ(scanTask.WriteImageData(dataBuffer), E_SCAN_INVALID_PARAMETER);
}


HWTEST_F(ScanTaskTest, WriteImageData_Redundantdata, TestSize.Level1)
{
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_RGB);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_RGB);
    scanParam.SetBytesPerLine(TEST_IMAGE_STRIDE_RGB);

    std::string filePath;
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_NONE);

    std::vector<uint8_t> dataBuffer(scanParam.GetBytesPerLine() * scanParam.GetLines());
    ASSERT_EQ(scanTask.WriteImageData(dataBuffer), E_SCAN_NONE);

    ASSERT_EQ(scanTask.WriteImageData(dataBuffer), E_SCAN_NONE);
}

HWTEST_F(ScanTaskTest, ImageFinishCompress_EmptyData, TestSize.Level1)
{
    std::string filePath;
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    scanTask.ImageFinishCompress();

    ASSERT_TRUE(scanTask.CreateAndOpenScanFile(filePath));
    scanTask.ImageFinishCompress();

    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_RGB);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_RGB);
    scanParam.SetBytesPerLine(TEST_IMAGE_STRIDE_RGB);

    ASSERT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_NONE);
    scanTask.ImageFinishCompress();

    EXPECT_EQ(scanTask.picBuf_, nullptr);
    EXPECT_EQ(scanTask.rowWriteIdx_, 0);
    EXPECT_EQ(scanTask.colWriteIdx_, 0);
    EXPECT_EQ(scanTask.pixMap_, nullptr);
    EXPECT_EQ(scanTask.imagePacker_, nullptr);
}

}  // namespace Scan
}  // namespace OHOS
