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
#include <sstream>
#include "scan_task.h"
#include "scan_constant.h"
#include "scan_log.h"
#include "securec.h"
#include "sane_info.h"
#include "media_errors.h"
#include "image_common.h"

namespace OHOS::Scan {
static const std::string EXIF_RESOLUTION_UNIT_INCH = "2";

constexpr uint32_t JFIF_BUFF_SIZE = 16;
const uint8_t JFIF_HEAD_APP0[] = {0xFF, 0xD8, 0xFF, 0xE0};
const uint8_t JFIF_DENSITY_UNITS_INCH = 0x01;
const size_t JFIF_DENSITY_UNITS_FILE_POS = 13;
const size_t JFIF_DENSITY_VALUE_LEN = 2;

ScanTask::ScanTask(const std::string& scannerId, int32_t userId, bool batchMode)
    :   scannerId_(scannerId),
        batchMode_(batchMode),
        userId_(userId)
{
}

ScanTask::~ScanTask()
{
}

std::string ScanTask::GetScannerId() const
{
    return scannerId_;
}

bool ScanTask::GetBatchMode() const
{
    return batchMode_;
}

ImageFormat ScanTask::GetImageFormat() const
{
    return imageFormat_;
}

bool ScanTask::CreateAndOpenScanFile(std::string& filePath, ImageFormat imgFmt, uint32_t quality)
{
    if (imagePacker_ != nullptr) {
        SCAN_HILOGE("File already opened!");
        return false;
    }

    std::string outputPath;
    Media::PackOption imgPackOpt;
    imgPackOpt.quality = quality < IMAGE_COMPRESS_QUALITY_MAX ? quality : IMAGE_COMPRESS_QUALITY_MAX;
    imgPackOpt.needsPackProperties = false;
    if (!GetImageOutputDir(imgFmt, outputPath, imgPackOpt.format)) {
        return false;
    }

    auto imgPacker = std::make_unique<Media::ImagePacker>();
    if (imgPacker == nullptr) {
        SCAN_HILOGE("Alloc image packer object failed");
        return false;
    }

    uint32_t ret = imgPacker->StartPacking(outputPath, imgPackOpt);
    if (ret != Media::SUCCESS) {
        SCAN_HILOGE("Imagepacker start packing failed! err=%{public}u path=%{private}s", ret, outputPath.c_str());
        return false;
    }

    SCAN_HILOGI("OpenScanFile Format=%{public}d Quality=%{public}u", imgFmt, quality);
    imageFormat_ = imgFmt;
    imagePacker_.swap(imgPacker);
    filePath.swap(outputPath);
    filePath_ = filePath;
    return true;
}

bool ScanTask::GetImageOutputDir(ImageFormat imgFmt, std::string& path, std::string& mimeType)
{
    std::string outputPath = "/data/service/el2/" + std::to_string(userId_) + "/print_service";
    char canonicalPath[PATH_MAX] = {0};
    if (realpath(outputPath.c_str(), canonicalPath) == nullptr) {
        SCAN_HILOGE("The real output dir is null, errno:%{public}d path=%{private}s",
            errno, outputPath.c_str());
        return false;
    }

    static uint32_t pictureId = 1;
    outputPath = canonicalPath;
    outputPath += "/scan_tmp";
    outputPath += std::to_string(pictureId++);

    switch (imgFmt) {
        case ImageFormat::IMAGE_TYPE_JPEG:
            mimeType = MIME_TYPE_JPEG;
            outputPath += ".jpg";
            break;

        case ImageFormat::IMAGE_TYPE_PNG:
            mimeType = MIME_TYPE_PNG;
            outputPath += ".png";
            break;

        default:
            SCAN_HILOGE("Unsupport image format(%{public}d)", imgFmt);
            return false;
    }

    path.swap(outputPath);
    return true;
}

int32_t ScanTask::WriteImageHeader(const ScanParameters &parm, uint16_t dpi)
{
    if (pixMap_ != nullptr) {
        SCAN_HILOGE("Header already writed!");
        return E_SCAN_GENERIC_FAILURE;
    }

    SCAN_HILOGI("WriteImageHeader size=%{public}dx%{public}d BytesPerLine=%{public}d Depth=%{public}d dpi=%{public}u",
        parm.GetPixelsPerLine(), parm.GetLines(), parm.GetBytesPerLine(), parm.GetDepth(),
        static_cast<uint32_t>(dpi));

    Media::InitializationOptions pixMapInitOpt;
    pixMapInitOpt.size.width = parm.GetPixelsPerLine();
    pixMapInitOpt.size.height = parm.GetLines();
    pixMapInitOpt.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    pixMapInitOpt.pixelFormat = Media::PixelFormat::RGB_888;
    pixMapInitOpt.allocatorType = Media::AllocatorType::HEAP_ALLOC;
    pixMapInitOpt.editable = true;

    std::unique_ptr<Media::PixelMap> pixMap = Media::PixelMap::Create(pixMapInitOpt);
    if (pixMap == nullptr) {
        SCAN_HILOGE("Create pixelmap failed");
        return E_SCAN_INVALID_PARAMETER;
    }

    picBuf_ = static_cast<uint8_t*>(pixMap->GetWritablePixels());
    if (picBuf_ == nullptr) {
        SCAN_HILOGE("Get pixelmap buffer point failed");
        return E_SCAN_INVALID_PARAMETER;
    }

    dpi_ = dpi;
    rowWriteIdx_ = 0;
    colWriteIdx_ = 0;
    pixMap_ = std::move(pixMap);
    scanParams_ = parm;
    return E_SCAN_NONE;
}

int32_t ScanTask::WriteImageData(const std::vector<uint8_t>& dataBuffer)
{
    if (picBuf_ == nullptr || pixMap_ == nullptr) {
        SCAN_HILOGE("PixelMap is nullptr! No init?");
        return E_SCAN_GENERIC_FAILURE;
    }

    if (dataBuffer.empty()) {
        SCAN_HILOGE("Empty data");
        return E_SCAN_INVALID_PARAMETER;
    }

    if (rowWriteIdx_ >= static_cast<size_t>(scanParams_.GetLines())) {
        SCAN_HILOGW("PixelMap data already write complete, no need more");
        return E_SCAN_NONE;
    }

    ScanFrame pixelFormat = scanParams_.GetFormat();
    if (pixelFormat == SCAN_FRAME_RGB) {
        return WriteRgbData(dataBuffer);
    }

    if (pixelFormat == SCAN_FRAME_GRAY) {
        if (scanParams_.GetDepth() != 1) {
            return WriteGreyData(dataBuffer);
        } else {
            return WriteMonoData(dataBuffer);
        }
    }

    SCAN_HILOGE("Unsupport format(%{public}d)!", pixelFormat);
    return E_SCAN_INVALID_PARAMETER;
}

int32_t ScanTask::WriteRgbData(const std::vector<uint8_t>& dataBuffer)
{
    const size_t srcStride = static_cast<size_t>(scanParams_.GetBytesPerLine());
    const size_t dstStride = static_cast<size_t>(pixMap_->GetRowStride());
    const size_t dstRowByteLength = static_cast<size_t>(pixMap_->GetRowBytes());
    const size_t height = static_cast<size_t>(pixMap_->GetHeight());
    const uint8_t *srcData = dataBuffer.data();
    size_t dataLeft = dataBuffer.size();
    uint8_t *dstRowData = picBuf_ + rowWriteIdx_ * dstStride;

    while (dataLeft > 0) {
        if (colWriteIdx_ < dstRowByteLength) {
            size_t rowBufRemain = dstRowByteLength - colWriteIdx_;
            size_t copySize = std::min(dataLeft, rowBufRemain);
            if (memcpy_s(dstRowData + colWriteIdx_, rowBufRemain, srcData, copySize) != 0) {
                SCAN_HILOGE("Copy pic data failed");
                return E_SCAN_GENERIC_FAILURE;
            }

            dataLeft -= copySize;
            colWriteIdx_ += copySize;
            srcData += copySize;
        }

        size_t srcRowDataLeft = srcStride - colWriteIdx_;
        if (srcRowDataLeft <= dataLeft) {
            if (++rowWriteIdx_ >= height) {
                break;
            }

            srcData += srcRowDataLeft;
            dataLeft -= srcRowDataLeft;
            dstRowData += dstStride;
            colWriteIdx_ = 0;
        } else {
            colWriteIdx_ += dataLeft;
            break;
        }
    }

    return E_SCAN_NONE;
}

int32_t ScanTask::WriteGreyData(const std::vector<uint8_t>& dataBuffer)
{
    const size_t srcStride = static_cast<size_t>(scanParams_.GetBytesPerLine());
    const size_t dstStride = static_cast<size_t>(pixMap_->GetRowStride());
    const size_t dstPixelBytes = static_cast<size_t>(pixMap_->GetPixelBytes());
    const size_t dstRowPaddingBytes = dstStride - static_cast<size_t>(pixMap_->GetRowBytes());
    const size_t width = static_cast<size_t>(pixMap_->GetWidth());
    const size_t height = static_cast<size_t>(pixMap_->GetHeight());
    const uint8_t *srcData = dataBuffer.data();
    size_t dataLeft = dataBuffer.size();
    uint8_t *dstData = picBuf_ + rowWriteIdx_ * dstStride + std::min(colWriteIdx_, width) * dstPixelBytes;
    while (dataLeft > 0) {
        // Pixmap unsupport YUV400 Grey image, Convert grey value to RGB888
        for (; colWriteIdx_ < width && dataLeft > 0; ++colWriteIdx_, ++srcData, --dataLeft) {
            *dstData++ = *srcData;
            *dstData++ = *srcData;
            *dstData++ = *srcData;
        }

        size_t srcRowDataLeft = srcStride - colWriteIdx_;
        if (srcRowDataLeft <= dataLeft) {
            if (++rowWriteIdx_ >= height) {
                break;
            }

            srcData += srcRowDataLeft;
            dataLeft -= srcRowDataLeft;
            dstData += dstRowPaddingBytes;
            colWriteIdx_ = 0;
        } else {
            colWriteIdx_ += dataLeft;
            break;
        }
    }

    return E_SCAN_NONE;
}

int32_t ScanTask::WriteMonoData(const std::vector<uint8_t>& dataBuffer)
{
    const size_t srcPixelStride = static_cast<size_t>(scanParams_.GetBytesPerLine() * BYTE_BITS);
    const size_t dstStride = static_cast<size_t>(pixMap_->GetRowStride());
    const size_t dstPixelBytes = static_cast<size_t>(pixMap_->GetPixelBytes());
    const size_t dstRowPaddingBytes = dstStride - static_cast<size_t>(pixMap_->GetRowBytes());
    const size_t width = static_cast<size_t>(pixMap_->GetWidth());
    const size_t height = static_cast<size_t>(pixMap_->GetHeight());
    const uint8_t *srcData =  dataBuffer.data();
    uint8_t *dstData = picBuf_ + rowWriteIdx_ * dstStride + std::min(colWriteIdx_, width) * dstPixelBytes;
    int32_t bitIdx = 0;
    for (size_t pixelLeft = dataBuffer.size() * BYTE_BITS; pixelLeft > 0; --pixelLeft) {
        if (colWriteIdx_ < width) {
            // Pixmap unsupport mono image, Convert to RGB888
            uint8_t dstPixelVal = (*srcData & (0x80 >> bitIdx)) != 0 ? 0x00 : 0xff;
            *dstData++ = dstPixelVal;
            *dstData++ = dstPixelVal;
            *dstData++ = dstPixelVal;
        }

        if (++bitIdx >= BYTE_BITS) {
            bitIdx = 0;
            ++srcData;
        }

        if (++colWriteIdx_ >= srcPixelStride) {
            if (++rowWriteIdx_ >= height) {
                break;
            }

            colWriteIdx_ = 0;
            dstData += dstRowPaddingBytes;
        }
    }

    return E_SCAN_NONE;
}

void ScanTask::ImageDestroyCompress()
{
    imagePacker_.reset();
    pixMap_.reset();
    picBuf_ = nullptr;
    rowWriteIdx_ = 0;
    colWriteIdx_ = 0;
    imageFormat_ = ImageFormat::IMAGE_TYPE_NONE;
}

void ScanTask::ImageFinishCompress()
{
    if (imagePacker_ == nullptr || pixMap_ == nullptr) {
        SCAN_HILOGE("Can not finish without init");
        return;
    }

    if (rowWriteIdx_ < static_cast<size_t>(pixMap_->GetHeight())) {
        SCAN_HILOGW("Insufficient image data, only write %{public}zu lines", rowWriteIdx_);
    }

    int64_t packedSize = 0;
    imagePacker_->AddImage(*pixMap_);
    uint32_t ret = imagePacker_->FinalizePacking(packedSize);
    if (ret == Media::SUCCESS) {
        SCAN_HILOGI("Imagepacker FinalizePacking successed! FileSize=%{public}" PRId64, packedSize);
    } else {
        SCAN_HILOGE("Imagepacker FinalizePacking failed! err=%{public}u", ret);
    }

    if (imageFormat_ == ImageFormat::IMAGE_TYPE_JPEG) {
        WriteJfifDensityField();
    }

    ImageDestroyCompress();
}

void ScanTask::WriteJfifDensityField()
{
    FILE* file = fopen(filePath_.c_str(), "r+b");
    if (file == nullptr) {
        SCAN_HILOGE("Open file failed");
        return;
    }

    do {
        // Read and check jfif app0 head
        uint8_t buf[JFIF_BUFF_SIZE] = {0};
        if (fread(buf, sizeof(JFIF_HEAD_APP0), 1, file) != 1) {
            SCAN_HILOGE("Read jfif app0 head failed");
            break;
        }

        if (std::memcmp(buf, JFIF_HEAD_APP0, sizeof(JFIF_HEAD_APP0)) != 0) {
            SCAN_HILOGE("Check jfif app0 head failed");
            break;
        }

        if (fseek(file, JFIF_DENSITY_UNITS_FILE_POS, SEEK_SET) != 0) {
            SCAN_HILOGE("fseek to density uints pos failed");
            break;
        }

        buf[0] = static_cast<uint8_t>((dpi_ >> BYTE_BITS) & 0xFF);
        buf[1] = static_cast<uint8_t>(dpi_ & 0xFF);
        if (fwrite(&JFIF_DENSITY_UNITS_INCH, sizeof(JFIF_DENSITY_UNITS_INCH), 1, file) != 1 ||
            fwrite(buf, JFIF_DENSITY_VALUE_LEN, 1, file) != 1 ||
            fwrite(buf, JFIF_DENSITY_VALUE_LEN, 1, file) != 1) {
            SCAN_HILOGE("Write JFIF density value failed");
            break;
        }
    } while (false);

    int ret = fclose(file);
    if (ret != 0) {
        SCAN_HILOGE("Close file failed, err=%{public}d", ret);
    }
}

} // namespace OHOS::Scan
