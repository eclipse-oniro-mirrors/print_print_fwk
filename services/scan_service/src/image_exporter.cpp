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

#include <cerrno>
#include <climits>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <cinttypes>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>
#include "image_exporter.h"
#include "image_packer.h"
#include "image_source.h"
#include "media_errors.h"
#include "print_json_util.h"
#include "scan_log.h"

namespace OHOS::Scan {

bool ImageExporter::FileExists(const std::string& path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

int32_t ImageExporter::LoadDpiFromMetadata(const std::string& metaPath)
{
    if (!FileExists(metaPath)) {
        SCAN_HILOGW("Metadata not found: %{private}s, using default DPI", metaPath.c_str());
        return DEFAULT_DPI;
    }

    std::ifstream metaFile(metaPath);
    if (!metaFile.is_open()) {
        SCAN_HILOGE("Open metadata file failed: %{private}s", metaPath.c_str());
        return DEFAULT_DPI;
    }

    Json::Value metadataJson;
    if (!Print::PrintJsonUtil::ParseFromStream(metaFile, metadataJson)) {
        SCAN_HILOGE("Parse metadata JSON failed: %{private}s", metaPath.c_str());
        metaFile.close();
        return DEFAULT_DPI;
    }
    metaFile.close();

    if (!Print::PrintJsonUtil::IsMember(metadataJson, "dpi") ||
        !metadataJson["dpi"].isInt()) {
        SCAN_HILOGW("dpi not found or invalid, using default DPI");
        return DEFAULT_DPI;
    }

    int32_t dpi = metadataJson["dpi"].asInt();
    if (dpi <= 0) {
        SCAN_HILOGW("Invalid DPI: %{public}d, using default", dpi);
        return DEFAULT_DPI;
    }

    SCAN_HILOGI("Loaded DPI from metadata: %{public}d", dpi);
    return dpi;
}

bool ImageExporter::LoadImageSizeFromMetadata(const std::string& metaPath, int32_t& width, int32_t& height)
{
    std::ifstream metaFile(metaPath);
    if (!metaFile.is_open()) {
        SCAN_HILOGE("Open metadata file failed: %{private}s", metaPath.c_str());
        return false;
    }

    Json::Value metadataJson;
    if (!Print::PrintJsonUtil::ParseFromStream(metaFile, metadataJson)) {
        SCAN_HILOGE("Parse metadata JSON failed: %{private}s", metaPath.c_str());
        metaFile.close();
        return false;
    }
    metaFile.close();
    SCAN_HILOGD("metadataJson: %{private}s", Print::PrintJsonUtil::WriteString(metadataJson).c_str());

    if (!Print::PrintJsonUtil::IsMember(metadataJson, "width") || !metadataJson["width"].isInt()) {
        SCAN_HILOGE("width not found or invalid in metadata");
        return false;
    }
    width = metadataJson["width"].asInt();

    if (!Print::PrintJsonUtil::IsMember(metadataJson, "height") || !metadataJson["height"].isInt()) {
        SCAN_HILOGE("height not found or invalid in metadata");
        return false;
    }
    height = metadataJson["height"].asInt();
    if (width <= 0 || height <= 0 || width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION) {
        SCAN_HILOGE("Invalid image dimension: %{public}dx%{public}d", width, height);
        return false;
    }

    int64_t totalSize = static_cast<int64_t>(width) * height * CHANNEL_THREE;
    if (totalSize > INT32_MAX) {
        SCAN_HILOGE("Image size would overflow: %{public}dx%{public}d", width, height);
        return false;
    }

    SCAN_HILOGI("Loaded image size: %{public}dx%{public}d", width, height);
    return true;
}

std::unique_ptr<Media::PixelMap> ImageExporter::LoadRawData(
    const std::string& rawPath, const std::string& metaPath)
{
    int32_t width = 0;
    int32_t height = 0;
    if (!LoadImageSizeFromMetadata(metaPath, width, height)) {
        SCAN_HILOGE("Load image size from metadata failed");
        return nullptr;
    }

    Media::InitializationOptions initOpts;
    initOpts.size.width = width;
    initOpts.size.height = height;
    initOpts.pixelFormat = Media::PixelFormat::RGB_888;
    initOpts.allocatorType = Media::AllocatorType::HEAP_ALLOC;

    auto pixMap = Media::PixelMap::Create(initOpts);
    if (pixMap == nullptr) {
        SCAN_HILOGE("Create RGB_888 PixelMap failed");
        return nullptr;
    }

    std::ifstream rawFile(rawPath, std::ios::binary);
    if (!rawFile.is_open()) {
        SCAN_HILOGE("Open raw file failed: %{private}s", rawPath.c_str());
        return nullptr;
    }

    uint8_t* dstData = static_cast<uint8_t*>(pixMap->GetWritablePixels());
    int32_t rowStride = pixMap->GetRowStride();
    int32_t rowBytes = pixMap->GetRowBytes();

    int64_t totalBytesRead = 0;

    for (int32_t y = 0; y < height; y++) {
        rawFile.read(reinterpret_cast<char*>(dstData + y * rowStride), rowBytes);
        
        if (rawFile.gcount() != rowBytes || rawFile.fail() || rawFile.bad()) {
            SCAN_HILOGE("Read failed at row %{public}d: expected %{public}d bytes", y, rowBytes);
            rawFile.close();
            return nullptr;
        }
        
        totalBytesRead += rawFile.gcount();
    }

    rawFile.close();
    return pixMap;
}

int32_t ImageExporter::PackTiffImage(const std::string& tiffPath,
    const std::unique_ptr<Media::PixelMap>& pixMap, int32_t dpi, int64_t& packedSize)
{
    auto tiffPacker = std::make_unique<Media::ImagePacker>();
    if (tiffPacker == nullptr) {
        SCAN_HILOGE("Alloc TIFF packer failed");
        return E_SCAN_SERVER_FAILURE;
    }

    Media::PackOption tiffOpt;
    tiffOpt.format = MIME_TYPE_TIFF;
    tiffOpt.quality = IMAGE_COMPRESS_QUALITY_MAX;
    tiffOpt.tiffPackingOption.xResolution = static_cast<float>(dpi);
    tiffOpt.tiffPackingOption.yResolution = static_cast<float>(dpi);
    tiffOpt.tiffPackingOption.resolutionUnit = TIFF_RESOLUTION_UNIT_INCH;

    uint32_t ret = tiffPacker->StartPacking(tiffPath, tiffOpt);
    if (ret != Media::SUCCESS) {
        SCAN_HILOGE("TIFF StartPacking failed: err=%{public}u", ret);
        return E_SCAN_SERVER_FAILURE;
    }

    tiffPacker->AddImage(*pixMap);

    ret = tiffPacker->FinalizePacking(packedSize);
    if (ret != Media::SUCCESS) {
        SCAN_HILOGE("TIFF FinalizePacking failed: err=%{public}u", ret);
        return E_SCAN_SERVER_FAILURE;
    }

    return E_SCAN_NONE;
}

int32_t ImageExporter::ExportToPng(const std::string& baseName, int32_t& pngFd, ScanPictureData& cacheManager)
{
    std::string rawPath = baseName + RAW_SUFFIX;
    std::string metaPath = baseName + META_SUFFIX;
    
    auto pixMap = LoadRawData(rawPath, metaPath);
    if (pixMap == nullptr) {
        SCAN_HILOGE("Load raw data failed");
        return E_SCAN_SERVER_FAILURE;
    }
    
    std::string pngPath = baseName + PNG_SUFFIX;

    auto pngPacker = std::make_unique<Media::ImagePacker>();
    if (pngPacker == nullptr) {
        SCAN_HILOGE("Alloc PNG packer failed");
        return E_SCAN_SERVER_FAILURE;
    }

    Media::PackOption pngOpt;
    pngOpt.quality = IMAGE_COMPRESS_QUALITY_MAX;
    pngOpt.format = MIME_TYPE_PNG;

    uint32_t ret = pngPacker->StartPacking(pngPath, pngOpt);
    if (ret != Media::SUCCESS) {
        SCAN_HILOGE("PNG StartPacking failed: err=%{public}u", ret);
        return E_SCAN_SERVER_FAILURE;
    }

    pngPacker->AddImage(*pixMap);

    int64_t packedSize = 0;
    ret = pngPacker->FinalizePacking(packedSize);
    if (ret != Media::SUCCESS) {
        SCAN_HILOGE("PNG FinalizePacking failed: err=%{public}u", ret);
        return E_SCAN_SERVER_FAILURE;
    }

    pngFd = open(pngPath.c_str(), O_RDONLY);
    if (pngFd < 0) {
        SCAN_HILOGE("Open PNG file failed: %{private}s, errno=%{public}d", pngPath.c_str(), errno);
        return E_SCAN_SERVER_FAILURE;
    }

    fdsan_exchange_owner_tag(pngFd, 0, SCAN_LOG_DOMAIN);
    cacheManager.RegisterExportedResult(baseName, pngFd, EXPORT_FORMAT_PNG);
    
    SCAN_HILOGI("PNG export success: fd=%{public}d, Size=%{public}" PRId64, pngFd, packedSize);
    return E_SCAN_NONE;
}

int32_t ImageExporter::ExportToTiff(const std::string& baseName, int32_t& tiffFd, ScanPictureData& cacheManager)
{
    std::string rawPath = baseName + RAW_SUFFIX;
    std::string metaPath = baseName + META_SUFFIX;
    
    auto pixMap = LoadRawData(rawPath, metaPath);
    if (pixMap == nullptr) {
        SCAN_HILOGE("Load raw data failed");
        return E_SCAN_SERVER_FAILURE;
    }
    
    int32_t dpi = LoadDpiFromMetadata(metaPath);
    SCAN_HILOGI("TIFF DPI=%{public}d", dpi);
    
    std::string tiffPath = baseName + TIFF_EXTENSION;
    int64_t packedSize = 0;
    int32_t ret = PackTiffImage(tiffPath, pixMap, dpi, packedSize);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("PackTiffImage failed: tiffPath=%{private}s, dpi=%{public}d, ret=%{public}d",
                    tiffPath.c_str(), dpi, ret);
        return ret;
    }

    tiffFd = open(tiffPath.c_str(), O_RDONLY);
    if (tiffFd < 0) {
        SCAN_HILOGE("Open TIFF file failed: %{private}s, errno=%{public}d", tiffPath.c_str(), errno);
        return E_SCAN_SERVER_FAILURE;
    }

    fdsan_exchange_owner_tag(tiffFd, 0, SCAN_LOG_DOMAIN);
    cacheManager.RegisterExportedResult(baseName, tiffFd, EXPORT_FORMAT_TIFF);
    
    SCAN_HILOGI("TIFF export success: %{private}s, Size=%{public}" PRId64, tiffPath.c_str(), packedSize);
    return E_SCAN_NONE;
}

int32_t ImageExporter::ExportToFormat(
    const std::string& baseName, int32_t format, int32_t& exportedFd, ScanPictureData& cacheManager)
{
    if (baseName.empty()) {
        SCAN_HILOGE("Empty baseName");
        return E_SCAN_INVALID_PARAMETER;
    }

    if (format != EXPORT_FORMAT_PNG && format != EXPORT_FORMAT_TIFF) {
        SCAN_HILOGE("Unsupported format: %{public}d", format);
        return E_SCAN_UNSUPPORTED;
    }

    std::string rawPath = baseName + RAW_SUFFIX;
    if (!FileExists(rawPath)) {
        SCAN_HILOGE("Raw cache not found: %{private}s", rawPath.c_str());
        return E_SCAN_SERVER_FAILURE;
    }

    int32_t ret = E_SCAN_NONE;
    if (format == EXPORT_FORMAT_PNG) {
        ret = ExportToPng(baseName, exportedFd, cacheManager);
    } else if (format == EXPORT_FORMAT_TIFF) {
        ret = ExportToTiff(baseName, exportedFd, cacheManager);
    }

    return ret;
}

}  // namespace OHOS::Scan