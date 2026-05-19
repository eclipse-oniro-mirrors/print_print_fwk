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
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include "image_exporter.h"
#include "scan_picture_data.h"
#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS {
namespace Scan {
using namespace testing::ext;

constexpr int32_t TEST_WIDTH = 100;
constexpr int32_t TEST_HEIGHT = 100;
constexpr int32_t TEST_DPI = 300;
constexpr int32_t RGB_CHANNELS = 3;
constexpr uint8_t DEFAULT_PIXEL_VALUE = 128;
constexpr mode_t DIR_PERMISSION_MODE = 0755;
constexpr int32_t EXPECTED_ROW_BYTES_RGB = TEST_WIDTH * RGB_CHANNELS;

class ImageExporterTest : public ::testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    
    void CreateTestRawFile(const std::string& rawPath, int32_t width, int32_t height);
    void CreateTestMetadata(const std::string& metaPath, int32_t width, int32_t height, int32_t dpi);
    void CreateTestJpegFile(const std::string& jpegPath);
    
private:
    std::vector<std::string> createdFiles_;
    std::string testDir_;
};

void ImageExporterTest::SetUp()
{
    testDir_ = "/tmp/image_exporter_test_" + std::to_string(getpid());
    mkdir(testDir_.c_str(), DIR_PERMISSION_MODE);
}

void ImageExporterTest::TearDown()
{
    for (const auto& file : createdFiles_) {
        if (access(file.c_str(), F_OK) == 0) {
            remove(file.c_str());
        }
    }
    createdFiles_.clear();
    
    if (access(testDir_.c_str(), F_OK) == 0) {
        remove(testDir_.c_str());
    }
}

void ImageExporterTest::CreateTestRawFile(const std::string& rawPath, int32_t width, int32_t height)
{
    std::ofstream rawFile(rawPath, std::ios::binary);
    ASSERT_TRUE(rawFile.is_open());
    
    std::vector<uint8_t> rowData(width * RGB_CHANNELS, DEFAULT_PIXEL_VALUE);
    for (int32_t y = 0; y < height; y++) {
        rawFile.write(reinterpret_cast<const char*>(rowData.data()), rowData.size());
    }
    rawFile.close();
    createdFiles_.push_back(rawPath);
}

void ImageExporterTest::CreateTestMetadata(const std::string& metaPath, int32_t width, int32_t height, int32_t dpi)
{
    std::ofstream metaFile(metaPath);
    ASSERT_TRUE(metaFile.is_open());
    
    metaFile << "{\n";
    metaFile << "  \"width\": " << width << ",\n";
    metaFile << "  \"height\": " << height << ",\n";
    metaFile << "  \"depth\": 8,\n";
    metaFile << "  \"bytesPerLine\": " << (width * RGB_CHANNELS) << ",\n";
    metaFile << "  \"format\": \"RGB\",\n";
    metaFile << "  \"lastFrame\": true,\n";
    metaFile << "  \"dpi\": " << dpi << ",\n";
    metaFile << "  \"channels\": " << RGB_CHANNELS << ",\n";
    metaFile << "  \"bitsPerSample\": 8\n";
    metaFile << "}\n";
    
    metaFile.close();
    createdFiles_.push_back(metaPath);
}

void ImageExporterTest::CreateTestJpegFile(const std::string& jpegPath)
{
    std::ofstream jpegFile(jpegPath);
    jpegFile << "fake_jpeg_data";
    jpegFile.close();
    createdFiles_.push_back(jpegPath);
}

/**
 * @tc.name: ExportToFormat_PNG_Success
 * @tc.desc: 测试PNG导出正常流程
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, ExportToFormat_PNG_Success, TestSize.Level0)
{
    std::string baseName = testDir_ + "/test";
    std::string rawPath = baseName + RAW_SUFFIX;
    std::string metaPath = baseName + META_SUFFIX;
    
    CreateTestJpegFile(baseName + JPG_EXTENSION);
    CreateTestRawFile(rawPath, TEST_WIDTH, TEST_HEIGHT);
    CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
    
    ScanPictureData& cacheManager = ScanPictureData::GetInstance();
    int32_t exportedFd = -1;
    
    int32_t ret = ImageExporter::ExportToFormat(
        baseName, EXPORT_FORMAT_PNG, exportedFd, cacheManager);
    
    ASSERT_EQ(ret, E_SCAN_NONE);
    ASSERT_GE(exportedFd, 0);
    
    std::string pngPath = baseName + PNG_SUFFIX;
    ASSERT_EQ(access(pngPath.c_str(), F_OK), 0);
    
    close(exportedFd);
}

/**
 * @tc.name: ExportToFormat_TIFF_Success
 * @tc.desc: 测试TIFF导出正常流程
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, ExportToFormat_TIFF_Success, TestSize.Level0)
{
    std::string baseName = testDir_ + "/test";
    std::string rawPath = baseName + RAW_SUFFIX;
    std::string metaPath = baseName + META_SUFFIX;
    
    CreateTestJpegFile(baseName + JPG_EXTENSION);
    CreateTestRawFile(rawPath, TEST_WIDTH, TEST_HEIGHT);
    CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
    
    ScanPictureData& cacheManager = ScanPictureData::GetInstance();
    int32_t exportedFd = -1;
    
    int32_t ret = ImageExporter::ExportToFormat(
        baseName, EXPORT_FORMAT_TIFF, exportedFd, cacheManager);
    
    ASSERT_EQ(ret, E_SCAN_NONE);
    ASSERT_GE(exportedFd, 0);
    
    std::string tiffPath = baseName + TIFF_EXTENSION;
    ASSERT_EQ(access(tiffPath.c_str(), F_OK), 0);
    
    close(exportedFd);
}

/**
 * @tc.name: ExportToFormat_EmptyJpegPath
 * @tc.desc: 测试空路径参数
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, ExportToFormat_EmptyJpegPath, TestSize.Level1)
{
    ScanPictureData& cacheManager = ScanPictureData::GetInstance();
    int32_t exportedFd = -1;
    
    int32_t ret = ImageExporter::ExportToFormat(
        "", EXPORT_FORMAT_PNG, exportedFd, cacheManager);
    
    ASSERT_EQ(ret, E_SCAN_INVALID_PARAMETER);
    ASSERT_EQ(exportedFd, -1);
}

/**
 * @tc.name: ExportToFormat_InvalidFormat
 * @tc.desc: 测试无效的导出格式
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, ExportToFormat_InvalidFormat, TestSize.Level1)
{
    std::string baseName = testDir_ + "/test";
    CreateTestJpegFile(baseName + JPG_EXTENSION);
    
    ScanPictureData& cacheManager = ScanPictureData::GetInstance();
    int32_t exportedFd = -1;
    
    int32_t ret = ImageExporter::ExportToFormat(
        baseName, 999, exportedFd, cacheManager);
    
    ASSERT_EQ(ret, E_SCAN_UNSUPPORTED);
}

/**
 * @tc.name: LoadRawData_Success
 * @tc.desc: 测试Raw文件成功加载
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadRawData_Success, TestSize.Level0)
{
    std::string rawPath = testDir_ + "/test.raw";
    std::string metaPath = testDir_ + "/test.meta.json";
    
    CreateTestRawFile(rawPath, TEST_WIDTH, TEST_HEIGHT);
    CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
    
    auto pixMap = ImageExporter::LoadRawData(rawPath, metaPath);
    
    ASSERT_NE(pixMap, nullptr);
    ASSERT_EQ(pixMap->GetWidth(), TEST_WIDTH);
    ASSERT_EQ(pixMap->GetHeight(), TEST_HEIGHT);
}

/**
 * @tc.name: LoadRawData_RawFileNotExist
 * @tc.desc: 测试Raw文件不存在
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadRawData_RawFileNotExist, TestSize.Level1)
{
    std::string rawPath = testDir_ + "/nonexistent.raw";
    std::string metaPath = testDir_ + "/test.meta.json";
    
    CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
    
    auto pixMap = ImageExporter::LoadRawData(rawPath, metaPath);
    
    ASSERT_EQ(pixMap, nullptr);
}

/**
 * @tc.name: LoadRawData_MetaFileNotExist
 * @tc.desc: 测试元数据文件不存在
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadRawData_MetaFileNotExist, TestSize.Level1)
{
    std::string rawPath = testDir_ + "/test.raw";
    std::string metaPath = testDir_ + "/nonexistent.meta.json";
    
    CreateTestRawFile(rawPath, TEST_WIDTH, TEST_HEIGHT);
    
    auto pixMap = ImageExporter::LoadRawData(rawPath, metaPath);
    
    ASSERT_EQ(pixMap, nullptr);
}

/**
 * @tc.name: LoadDpiFromMetadata_Success
 * @tc.desc: 测试DPI解析成功
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadDpiFromMetadata_Success, TestSize.Level0)
{
    std::string metaPath = testDir_ + "/test.meta.json";
    CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
    
    int32_t dpi = ImageExporter::LoadDpiFromMetadata(metaPath);
    
    ASSERT_EQ(dpi, TEST_DPI);
}

/**
 * @tc.name: LoadDpiFromMetadata_FileNotExist
 * @tc.desc: 测试元数据文件不存在返回默认DPI
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadDpiFromMetadata_FileNotExist, TestSize.Level1)
{
    std::string metaPath = testDir_ + "/nonexistent.meta.json";
    
    int32_t dpi = ImageExporter::LoadDpiFromMetadata(metaPath);
    
    ASSERT_EQ(dpi, DEFAULT_DPI);
}

/**
 * @tc.name: LoadDpiFromMetadata_InvalidJsonFormat
 * @tc.desc: 测试JSON格式错误返回默认DPI
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadDpiFromMetadata_InvalidJsonFormat, TestSize.Level1)
{
    std::string metaPath = testDir_ + "/invalid.meta.json";
    
    std::ofstream metaFile(metaPath);
    metaFile << "{invalid json content}";
    metaFile.close();
    createdFiles_.push_back(metaPath);
    
    int32_t dpi = ImageExporter::LoadDpiFromMetadata(metaPath);
    
    ASSERT_EQ(dpi, DEFAULT_DPI);
}

/**
 * @tc.name: LoadDpiFromMetadata_FieldMissing
 * @tc.desc: 测试xResolution字段缺失
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadDpiFromMetadata_FieldMissing, TestSize.Level1)
{
    std::string metaPath = testDir_ + "/missing_dpi.meta.json";
    
    std::ofstream metaFile(metaPath);
    metaFile << "{\n";
    metaFile << "  \"width\": 100,\n";
    metaFile << "  \"height\": 100\n";
    metaFile << "}\n";
    metaFile.close();
    createdFiles_.push_back(metaPath);
    
    int32_t dpi = ImageExporter::LoadDpiFromMetadata(metaPath);
    
    ASSERT_EQ(dpi, DEFAULT_DPI);
}

/**
 * @tc.name: LoadDpiFromMetadata_DpiZero
 * @tc.desc: 测试DPI值为0返回默认值
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadDpiFromMetadata_DpiZero, TestSize.Level1)
{
    std::string metaPath = testDir_ + "/dpi_zero.meta.json";
    
    std::ofstream metaFile(metaPath);
    metaFile << "{\n";
    metaFile << "  \"xResolution\": 0\n";
    metaFile << "}\n";
    metaFile.close();
    createdFiles_.push_back(metaPath);
    
    int32_t dpi = ImageExporter::LoadDpiFromMetadata(metaPath);
    
    ASSERT_EQ(dpi, DEFAULT_DPI);
}

/**
 * @tc.name: LoadImageSizeFromMetadata_Success
 * @tc.desc: 测试宽高解析成功
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadImageSizeFromMetadata_Success, TestSize.Level0)
{
    std::string metaPath = testDir_ + "/test.meta.json";
    CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
    
    int32_t width = 0, height = 0;
    bool ret = ImageExporter::LoadImageSizeFromMetadata(metaPath, width, height);
    
    ASSERT_TRUE(ret);
    ASSERT_EQ(width, TEST_WIDTH);
    ASSERT_EQ(height, TEST_HEIGHT);
}

/**
 * @tc.name: LoadImageSizeFromMetadata_FieldMissing
 * @tc.desc: 测试width/height字段缺失
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadImageSizeFromMetadata_FieldMissing, TestSize.Level1)
{
    std::string metaPath = testDir_ + "/missing_size.meta.json";
    
    std::ofstream metaFile(metaPath);
    metaFile << "{\n";
    metaFile << "  \"xResolution\": 300\n";
    metaFile << "}\n";
    metaFile.close();
    createdFiles_.push_back(metaPath);
    
    int32_t width = 0, height = 0;
    bool ret = ImageExporter::LoadImageSizeFromMetadata(metaPath, width, height);
    
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: LoadImageSizeFromMetadata_WidthExceedsMaximum
 * @tc.desc: 测试宽度超过最大值
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadImageSizeFromMetadata_WidthExceedsMaximum, TestSize.Level1)
{
    std::string metaPath = testDir_ + "/exceed_width.meta.json";
    CreateTestMetadata(metaPath, MAX_IMAGE_DIMENSION + 1, TEST_HEIGHT, TEST_DPI);
    
    int32_t width = 0, height = 0;
    bool ret = ImageExporter::LoadImageSizeFromMetadata(metaPath, width, height);
    
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: LoadImageSizeFromMetadata_HeightExceedsMaximum
 * @tc.desc: 测试高度超过最大值
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadImageSizeFromMetadata_HeightExceedsMaximum, TestSize.Level1)
{
    std::string metaPath = testDir_ + "/exceed_height.meta.json";
    CreateTestMetadata(metaPath, TEST_WIDTH, MAX_IMAGE_DIMENSION + 1, TEST_DPI);
    
    int32_t width = 0, height = 0;
    bool ret = ImageExporter::LoadImageSizeFromMetadata(metaPath, width, height);
    
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: LoadImageSizeFromMetadata_SizeOverflow
 * @tc.desc: 测试图像尺寸整数溢出
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadImageSizeFromMetadata_SizeOverflow, TestSize.Level1)
{
    std::string metaPath = testDir_ + "/overflow_size.meta.json";
    int32_t overflowWidth = 30000;
    int32_t overflowHeight = 30000;
    CreateTestMetadata(metaPath, overflowWidth, overflowHeight, TEST_DPI);
    
    int32_t width = 0, height = 0;
    bool ret = ImageExporter::LoadImageSizeFromMetadata(metaPath, width, height);
    
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: LoadImageSizeFromMetadata_MaxValidDimension
 * @tc.desc: 测试最大有效尺寸边界
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadImageSizeFromMetadata_MaxValidDimension, TestSize.Level0)
{
    std::string metaPath = testDir_ + "/max_valid.meta.json";
    CreateTestMetadata(metaPath, MAX_IMAGE_DIMENSION, 100, TEST_DPI);
    
    int32_t width = 0, height = 0;
    bool ret = ImageExporter::LoadImageSizeFromMetadata(metaPath, width, height);
    
    ASSERT_TRUE(ret);
    ASSERT_EQ(width, MAX_IMAGE_DIMENSION);
    ASSERT_EQ(height, 100);
}

/**
 * @tc.name: LoadRawData_FileTooSmall
 * @tc.desc: 测试raw文件小于预期大小
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadRawData_FileTooSmall, TestSize.Level1)
{
    std::string rawPath = testDir_ + "/small.raw";
    std::string metaPath = testDir_ + "/small.meta.json";
    
    CreateTestMetadata(metaPath, 100, 100, TEST_DPI);
    CreateTestRawFile(rawPath, 100, 10);
    
    auto pixMap = ImageExporter::LoadRawData(rawPath, metaPath);
    ASSERT_EQ(pixMap, nullptr);
}

/**
 * @tc.name: LoadRawData_FileExactSize
 * @tc.desc: 测试raw文件大小正好匹配
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadRawData_FileExactSize, TestSize.Level0)
{
    std::string rawPath = testDir_ + "/exact.raw";
    std::string metaPath = testDir_ + "/exact.meta.json";
    
    CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
    CreateTestRawFile(rawPath, TEST_WIDTH, TEST_HEIGHT);
    
    auto pixMap = ImageExporter::LoadRawData(rawPath, metaPath);
    ASSERT_NE(pixMap, nullptr);
    ASSERT_EQ(pixMap->GetWidth(), TEST_WIDTH);
    ASSERT_EQ(pixMap->GetHeight(), TEST_HEIGHT);
}

/**
 * @tc.name: LoadRawData_FileLargerThanExpected
 * @tc.desc: 测试raw文件比预期大（应只读取所需部分）
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadRawData_FileLargerThanExpected, TestSize.Level1)
{
    std::string rawPath = testDir_ + "/large.raw";
    std::string metaPath = testDir_ + "/large.meta.json";
    
    CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
    CreateTestRawFile(rawPath, TEST_WIDTH * 2, TEST_HEIGHT);
    
    auto pixMap = ImageExporter::LoadRawData(rawPath, metaPath);
    ASSERT_NE(pixMap, nullptr);
    ASSERT_EQ(pixMap->GetWidth(), TEST_WIDTH);
    ASSERT_EQ(pixMap->GetHeight(), TEST_HEIGHT);
}

/**
 * @tc.name: LoadRawData_PartialReadFailure
 * @tc.desc: 测试读取中途失败（文件数据不完整）
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, LoadRawData_PartialReadFailure, TestSize.Level1)
{
    std::string rawPath = testDir_ + "/partial.raw";
    std::string metaPath = testDir_ + "/partial.meta.json";
    
    CreateTestMetadata(metaPath, 100, 100, TEST_DPI);
    
    std::ofstream rawFile(rawPath, std::ios::binary);
    std::vector<uint8_t> halfData(100 * 50 * RGB_CHANNELS, DEFAULT_PIXEL_VALUE);
    rawFile.write(reinterpret_cast<const char*>(halfData.data()), halfData.size());
    rawFile.close();
    createdFiles_.push_back(rawPath);
    
    auto pixMap = ImageExporter::LoadRawData(rawPath, metaPath);
    ASSERT_EQ(pixMap, nullptr);
}

/**
 * @tc.name: FileExists_True
 * @tc.desc: 测试文件存在检测返回true
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, FileExists_True, TestSize.Level1)
{
    std::string filePath = testDir_ + "/exist.txt";
    
    std::ofstream file(filePath);
    file << "test";
    file.close();
    createdFiles_.push_back(filePath);
    
    ASSERT_TRUE(ImageExporter::FileExists(filePath));
}

/**
 * @tc.name: FileExists_False
 * @tc.desc: 测试文件不存在检测返回false
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, FileExists_False, TestSize.Level1)
{
    std::string filePath = testDir_ + "/nonexistent.txt";
    
    ASSERT_FALSE(ImageExporter::FileExists(filePath));
}

/**
 * @tc.name: ExportToFormat_RawFileNotExist
 * @tc.desc: 测试Raw缓存不存在返回错误
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, ExportToFormat_RawFileNotExist, TestSize.Level1)
{
    std::string baseName = testDir_ + "/test";
    CreateTestJpegFile(baseName + JPG_EXTENSION);
    
    ScanPictureData& cacheManager = ScanPictureData::GetInstance();
    int32_t exportedFd = -1;
    
    int32_t ret = ImageExporter::ExportToFormat(
        baseName, EXPORT_FORMAT_PNG, exportedFd, cacheManager);
    
    ASSERT_EQ(ret, E_SCAN_SERVER_FAILURE);
}

/**
 * @tc.name: Integration_BatchExport
 * @tc.desc: 测试批量导出多张图片
 * @tc.type: FUNC
 */
HWTEST_F(ImageExporterTest, Integration_BatchExport, TestSize.Level2)
{
    constexpr int32_t batchCount = 3;
    ScanPictureData& cacheManager = ScanPictureData::GetInstance();
    
    std::vector<int32_t> exportedFds;
    
    for (int32_t i = 0; i < batchCount; i++) {
        std::string baseName = testDir_ + "/batch_" + std::to_string(i);
        std::string rawPath = baseName + RAW_SUFFIX;
        std::string metaPath = baseName + META_SUFFIX;
        
        CreateTestJpegFile(baseName + JPG_EXTENSION);
        CreateTestRawFile(rawPath, TEST_WIDTH, TEST_HEIGHT);
        CreateTestMetadata(metaPath, TEST_WIDTH, TEST_HEIGHT, TEST_DPI);
        
        int32_t exportedFd = -1;
        int32_t ret = ImageExporter::ExportToFormat(
            baseName, EXPORT_FORMAT_PNG, exportedFd, cacheManager);
        
        ASSERT_EQ(ret, E_SCAN_NONE);
        ASSERT_GE(exportedFd, 0);
        exportedFds.push_back(exportedFd);
    }
    
    ASSERT_EQ(exportedFds.size(), batchCount);
    
    for (int32_t fd : exportedFds) {
        close(fd);
    }
}

/**
 * @tc.name: Performance_PngEncodingTime
 * @tc.desc: 测试PNG编码性能
 * @tc.type: PERF
 */
HWTEST_F(ImageExporterTest, Performance_PngEncodingTime, TestSize.Level3)
{
    constexpr int32_t a4Width = 2550;
    constexpr int32_t a4Height = 3508;
    
    std::string baseName = testDir_ + "/perf_png";
    std::string rawPath = baseName + RAW_SUFFIX;
    std::string metaPath = baseName + META_SUFFIX;
    
    CreateTestJpegFile(baseName + JPG_EXTENSION);
    CreateTestRawFile(rawPath, a4Width, a4Height);
    CreateTestMetadata(metaPath, a4Width, a4Height, TEST_DPI);
    
    ScanPictureData& cacheManager = ScanPictureData::GetInstance();
    int32_t exportedFd = -1;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    int32_t ret = ImageExporter::ExportToFormat(
        baseName, EXPORT_FORMAT_PNG, exportedFd, cacheManager);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    ASSERT_EQ(ret, E_SCAN_NONE);
    
    SCAN_HILOGI("PNG encoding time: %{public}lld ms", static_cast<long long>(duration.count()));
    
    close(exportedFd);
}

/**
 * @tc.name: Performance_TiffEncodingTime
 * @tc.desc: 测试TIFF编码性能
 * @tc.type: PERF
 */
HWTEST_F(ImageExporterTest, Performance_TiffEncodingTime, TestSize.Level3)
{
    constexpr int32_t a4Width = 2550;
    constexpr int32_t a4Height = 3508;
    
    std::string baseName = testDir_ + "/perf_tiff";
    std::string rawPath = baseName + RAW_SUFFIX;
    std::string metaPath = baseName + META_SUFFIX;
    
    CreateTestJpegFile(baseName + JPG_EXTENSION);
    CreateTestRawFile(rawPath, a4Width, a4Height);
    CreateTestMetadata(metaPath, a4Width, a4Height, TEST_DPI);
    
    ScanPictureData& cacheManager = ScanPictureData::GetInstance();
    int32_t exportedFd = -1;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    int32_t ret = ImageExporter::ExportToFormat(
        baseName, EXPORT_FORMAT_TIFF, exportedFd, cacheManager);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    ASSERT_EQ(ret, E_SCAN_NONE);
    
    SCAN_HILOGI("TIFF encoding time: %{public}lld ms", static_cast<long long>(duration.count()));
    
    close(exportedFd);
}

}  // namespace Scan
}  // namespace OHOS