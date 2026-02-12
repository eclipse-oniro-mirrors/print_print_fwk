/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SCAN_TASK
#define SCAN_TASK

#include <string>
#include <map>
#include <mutex>
#include <vector>
#include <queue>
#include "scanner_info.h"
#include "scan_parameters.h"
#include "pixel_map.h"
#include "image_packer.h"

namespace OHOS::Scan {

enum class ImageFormat : int32_t {
    IMAGE_TYPE_NONE,
    IMAGE_TYPE_JPEG,
    IMAGE_TYPE_PNG
};

class ScanTask {
public:
    ScanTask(const std::string& scannerId, int32_t userId, bool batchMode);
    ~ScanTask();
    std::string GetScannerId() const;
    bool GetBatchMode() const;
    bool CreateAndOpenScanFile(std::string& filePath, ImageFormat imgFmt = ImageFormat::IMAGE_TYPE_JPEG,
        uint32_t quality = JPEG_QUALITY_SEVENTY_FIVE);
    int32_t WriteImageHeader(const ScanParameters &parm, uint16_t dpi);
    int32_t WriteImageData(const std::vector<uint8_t>& dataBuffer);
    void ImageDestroyCompress();
    void ImageFinishCompress();
    ImageFormat GetImageFormat() const;

private:
    ScanTask(const ScanTask&) = delete;
    ScanTask& operator=(const ScanTask&) = delete;

    bool GetImageOutputDir(ImageFormat imgFmt, std::string& path, std::string& mimeType);
    int32_t WriteRgbData(const std::vector<uint8_t>& dataBuffer);
    int32_t WriteGreyData(const std::vector<uint8_t>& dataBuffer);
    int32_t WriteMonoData(const std::vector<uint8_t>& dataBuffer);
    void WriteJfifDensityField();

    std::string scannerId_;
    std::string filePath_;
    bool batchMode_;
    int32_t userId_;

    uint16_t dpi_ = 0;
    ImageFormat imageFormat_ = ImageFormat::IMAGE_TYPE_NONE;
    uint8_t *picBuf_ = nullptr;
    size_t rowWriteIdx_ = 0;
    size_t colWriteIdx_ = 0;
    ScanParameters scanParams_;
    std::unique_ptr<Media::PixelMap> pixMap_;
    std::unique_ptr<Media::ImagePacker> imagePacker_;
};

} // namespace OHOS::Scan
#endif // SCAN_TASK
