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
#include <unistd.h>
#include <cstdio>
#define private public
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

private:
    std::vector<std::string> createdFiles_;
};

void ScanTaskTest::SetUp()
{
}

void ScanTaskTest::TearDown()
{
    for (const auto& file : createdFiles_) {
        if (access(file.c_str(), F_OK) == 0) {
            remove(file.c_str());
        }
    }
    createdFiles_.clear();
}

void ScanTaskTest::TestImageEncode(const ScanParameters& scanParam, ImageFormat imgFmt, std::string& imgPath)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_TRUE(scanTask.CreateAndOpenScanFile(imgPath, imgFmt));
    createdFiles_.push_back(imgPath);
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
    createdFiles_.push_back(filePath);
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
    createdFiles_.push_back(filePath);
    ASSERT_FALSE(scanTask.CreateAndOpenScanFile(filePath));
}

HWTEST_F(ScanTaskTest, CreateAndOpenScanFile_ImageTypePng, TestSize.Level1)
{
    std::string filePath;
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_TRUE(scanTask.CreateAndOpenScanFile(filePath, ImageFormat::IMAGE_TYPE_PNG));
    createdFiles_.push_back(filePath);
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
    createdFiles_.push_back(filePath);
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

HWTEST_F(ScanTaskTest, WriteImageData_UnsupportedFormat, TestSize.Level1)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_RGB);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_RGB);
    scanParam.SetBytesPerLine(TEST_IMAGE_STRIDE_RGB);
    ASSERT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_NONE);
 
    // Change format to unsupported value after header is written
    scanTask.scanParams_.SetFormat(static_cast<ScanFrame>(99));
    std::vector<uint8_t> dataBuffer(100, 0x00);
    EXPECT_EQ(scanTask.WriteImageData(dataBuffer), E_SCAN_INVALID_PARAMETER);
}
 
HWTEST_F(ScanTaskTest, WriteImageHeader_AlreadyWritten, TestSize.Level1)
{
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_RGB);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_RGB);
    scanParam.SetBytesPerLine(TEST_IMAGE_STRIDE_RGB);
 
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_NONE);
    EXPECT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_GENERIC_FAILURE);
}
 
HWTEST_F(ScanTaskTest, GetBaseName_WithJpgExtension, TestSize.Level1)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    scanTask.filePath_ = "/data/test/scan_tmp1.jpg";
    EXPECT_EQ(scanTask.GetBaseName(), "/data/test/scan_tmp1");
}
 
HWTEST_F(ScanTaskTest, GetBaseName_WithoutJpgExtension, TestSize.Level1)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    scanTask.filePath_ = "/data/test/scan_tmp1.png";
    EXPECT_EQ(scanTask.GetBaseName(), "/data/test/scan_tmp1.png");
}
 
HWTEST_F(ScanTaskTest, ImageFinishCompress_PngFormat, TestSize.Level1)
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
    EXPECT_EQ(access(imgPath.c_str(), 0), 0);
}
 
HWTEST_F(ScanTaskTest, SaveRawData_EmptyFilePath, TestSize.Level1)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    // filePath_ is empty by default, SaveRawData should early return without crash
    scanTask.SaveRawData();
    // No crash = pass
}
 
HWTEST_F(ScanTaskTest, SaveImageMetadata_EmptyFilePath, TestSize.Level1)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    // filePath_ is empty by default, SaveImageMetadata should early return without crash
    scanTask.SaveImageMetadata();
    // No crash = pass
}
 
HWTEST_F(ScanTaskTest, WriteJfifDensityField_FileOpenFails, TestSize.Level1)
{
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    scanTask.filePath_ = "/nonexistent/path/test.jpg";
    scanTask.dpi_ = DEFAULT_SCAN_DPI;
    // Should return early without crash when file can't be opened
    scanTask.WriteJfifDensityField();
    // No crash = pass
}
 
HWTEST_F(ScanTaskTest, WriteGreyData_SrcStrideLessThanColWriteIdx, TestSize.Level1)
{
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_GRAY);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_GREY);
    // Set bytesPerLine smaller than width to trigger srcStride < colWriteIdx_
    scanParam.SetBytesPerLine(TEST_IMAGE_WIDTH - 1);
 
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_NONE);
 
    // Write enough data to fill one row and trigger srcStride < colWriteIdx_
    std::vector<uint8_t> dataBuffer(TEST_IMAGE_WIDTH * 2, 0x80);
    int32_t result = scanTask.WriteImageData(dataBuffer);
    // Should return E_SCAN_INVALID_PARAMETER when srcStride < colWriteIdx_
    EXPECT_EQ(result, E_SCAN_INVALID_PARAMETER);
}
 
HWTEST_F(ScanTaskTest, WriteImageData_RowWriteComplete, TestSize.Level1)
{
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_RGB);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_RGB);
    scanParam.SetBytesPerLine(TEST_IMAGE_STRIDE_RGB);
 
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_NONE);
 
    // Write all image data to fill the pixel map completely
    std::vector<uint8_t> fullData(scanParam.GetBytesPerLine() * scanParam.GetLines(), 0x00);
    ASSERT_EQ(scanTask.WriteImageData(fullData), E_SCAN_NONE);
 
    // Now rowWriteIdx_ >= GetLines(), further writes should return E_SCAN_NONE (no-op)
    std::vector<uint8_t> moreData(100, 0x00);
    EXPECT_EQ(scanTask.WriteImageData(moreData), E_SCAN_NONE);
}
 
HWTEST_F(ScanTaskTest, ImageFinishCompress_InsufficientData, TestSize.Level1)
{
    ScanParameters scanParam;
    scanParam.SetFormat(SCAN_FRAME_RGB);
    scanParam.SetPixelsPerLine(TEST_IMAGE_WIDTH);
    scanParam.SetLines(TEST_IMAGE_HEIGHT);
    scanParam.SetDepth(DEFAULT_SCANPARAM_DEPTH_RGB);
    scanParam.SetBytesPerLine(TEST_IMAGE_STRIDE_RGB);
 
    std::string filePath;
    ScanTask scanTask("", DEFAULT_USER_ID, false);
    ASSERT_TRUE(scanTask.CreateAndOpenScanFile(filePath));
    createdFiles_.push_back(filePath);
    ASSERT_EQ(scanTask.WriteImageHeader(scanParam, DEFAULT_SCAN_DPI), E_SCAN_NONE);
 
    // Only write a small amount of data (not enough for the full image)
    std::vector<uint8_t> smallData(scanParam.GetBytesPerLine(), 0x00);
    ASSERT_EQ(scanTask.WriteImageData(smallData), E_SCAN_NONE);
 
    // Finish with incomplete data - should still succeed and call WriteJfifDensityField for JPEG
    scanTask.ImageFinishCompress();
    EXPECT_EQ(scanTask.imagePacker_, nullptr);
    EXPECT_EQ(scanTask.pixMap_, nullptr);
    EXPECT_EQ(scanTask.picBuf_, nullptr);
}

}  // namespace Scan
}  // namespace OHOS
