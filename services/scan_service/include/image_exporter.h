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

#ifndef IMAGE_EXPORTER_H
#define IMAGE_EXPORTER_H

#include <memory>
#include <string>
#include "pixel_map.h"
#include "scan_constant.h"
#include "scan_picture_data.h"

namespace OHOS::Scan {

class ImageExporter {
public:
    /**
     * @brief Export scanned image to specified format (PNG or TIFF)
     *
     * Converts JPEG scan result to PNG or TIFF format using cached raw RGB data.
     * The raw data and metadata are automatically loaded from scan cache files.
     *
     * @param baseName Base name of the scan result files (without extension, e.g., "scan_tmp1")
     * @param format Target format: EXPORT_FORMAT_PNG (0) or EXPORT_FORMAT_TIFF (1)
     * @param exportedFd [out] File descriptor of the exported image file
     * @param cacheManager ScanPictureData instance for cache management
     * @return E_SCAN_NONE on success, error code on failure:
     *         - E_SCAN_INVALID_PARAMETER: Invalid parameters (empty baseName)
     *         - E_SCAN_UNSUPPORTED: Unsupported format
     *         - E_SCAN_SERVER_FAILURE: Export operation failed (cache not found, encoding failed, file open failed)
     */
    static int32_t ExportToFormat(
        const std::string& baseName,
        int32_t format,
        int32_t& exportedFd,
        ScanPictureData& cacheManager);

private:
    // Export scan image to PNG format from raw RGB data
    static int32_t ExportToPng(
        const std::string& baseName,
        int32_t& pngFd,
        ScanPictureData& cacheManager);
    
    // Export scan image to TIFF format with DPI metadata
    static int32_t ExportToTiff(
        const std::string& baseName,
        int32_t& tiffFd,
        ScanPictureData& cacheManager);
    
    // Load raw RGB888 data and metadata into PixelMap
    static std::unique_ptr<Media::PixelMap> LoadRawData(
        const std::string& rawPath,
        const std::string& metaPath);
    
    // Load DPI value from JSON metadata file
    static int32_t LoadDpiFromMetadata(const std::string& metaPath);
    // Load width and height from JSON metadata
    static bool LoadImageSizeFromMetadata(
        const std::string& metaPath,
        int32_t& width,
        int32_t& height);
    
    // Pack PixelMap to TIFF file with resolution info
    static int32_t PackTiffImage(
        const std::string& tiffPath,
        const std::unique_ptr<Media::PixelMap>& pixMap,
        int32_t dpi,
        int64_t& packedSize);
    
    // Check if file exists using stat
    static bool FileExists(const std::string& path);
};

} // namespace OHOS::Scan
#endif // IMAGE_EXPORTER_H