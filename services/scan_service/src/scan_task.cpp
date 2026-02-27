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

namespace OHOS::Scan {
constexpr int32_t BIT = 1;

ScanTask::ScanTask(const std::string& scannerId, int32_t userId, bool batchMode)
    :   scannerId_(scannerId),
        batchMode_(batchMode),
        userId_(userId),
        ofp_(nullptr),
        jpegbuf_(nullptr)
{
    if (memset_s(&cinfo_, sizeof(cinfo_), 0, sizeof(cinfo_)) != 0) {
        SCAN_HILOGW("cinfo memset fail");
    }
    if (memset_s(&jerr_, sizeof(jerr_), 0, sizeof(jerr_)) != 0) {
        SCAN_HILOGW("jerr memset fail");
    }
    if (memset_s(&jpegJumpBuffer_, sizeof(jpegJumpBuffer_), 0, sizeof(jpegJumpBuffer_)) != 0) {
        SCAN_HILOGW("jpegJumpBuffer memset fail");
    }
}

ScanTask::~ScanTask()
{
    DELETE_ARRAY_AND_NULLIFY(jpegbuf_)
    if (ofp_ != nullptr) {
        fclose(ofp_);
        ofp_ = nullptr;
    }
}

std::string ScanTask::GetScannerId() const
{
    return scannerId_;
}

bool ScanTask::GetBatchMode()
{
    return batchMode_;
}

bool ScanTask::CreateAndOpenScanFile(std::string& filePath)
{
    std::string outputDir = "/data/service/el2/" + std::to_string(userId_) + "/print_service";
    char canonicalPath[PATH_MAX] = {0};
    if (realpath(outputDir.c_str(), canonicalPath) == nullptr) {
        SCAN_HILOGE("The real output dir is null, errno:%{public}s", std::to_string(errno).c_str());
        return false;
    }
    outputDir = canonicalPath;
    static int32_t pictureId = 1;
    filePath = outputDir + "/scan_tmp" + std::to_string(pictureId++) + ".jpg";
    ofp_ = fopen(filePath.c_str(), "w");
    if (ofp_ == nullptr) {
        SCAN_HILOGE("file [%{private}s] open fail", filePath.c_str());
        return false;
    }
    return true;
}

int32_t ScanTask::WriteJpegHeader(ScanParameters &parm, const UINT16& dpi)
{
    if (setjmp(jpegJumpBuffer_) != 0) {
        SCAN_HILOGE("WriteJpegHeader failed, longjmp from JpegErrorExit");
        return E_SCAN_INVAL;
    }
    ScanFrame format = parm.GetFormat();
    int32_t width = parm.GetPixelsPerLine();
    int32_t height = parm.GetLines();
    if (width <= 0 || height <= 0 || dpi <= 0) {
        SCAN_HILOGE("Invalid param: width:%{public}d, height:%{public}d, dpi:%{public}d", width, height, dpi);
        return E_SCAN_INVAL;
    }
    cinfo_.err = jpeg_std_error(&jerr_);
    cinfo_.err->error_exit = &ScanTask::JpegErrorExit;
    cinfo_.client_data = this;
    jpeg_create_compress(&cinfo_);
    jpeg_stdio_dest(&cinfo_, ofp_);
    cinfo_.image_width = static_cast<JDIMENSION>(width);
    cinfo_.image_height = static_cast<JDIMENSION>(height);
    if (format == SCAN_FRAME_RGB) {
        cinfo_.in_color_space = JCS_RGB;
        cinfo_.input_components = CHANNEL_THREE;
        SCAN_HILOGI("generate RGB picture");
    } else if (format == SCAN_FRAME_GRAY) {
        cinfo_.in_color_space = JCS_GRAYSCALE;
        cinfo_.input_components = CHANNEL_ONE;
        SCAN_HILOGI("generate gray picture");
    } else {
        SCAN_HILOGE("not support this color");
        return E_SCAN_INVALID_PARAMETER;
    }
    jpeg_set_defaults(&cinfo_);
    cinfo_.density_unit = 1;
    cinfo_.X_density = dpi;
    cinfo_.Y_density = dpi;
    cinfo_.write_JFIF_header = TRUE;
    SCAN_HILOGI("width:[%{public}d],height:[%{public}d],dpi:[%{public}d]", width, height, dpi);
    jpeg_set_quality(&cinfo_, JPEG_QUALITY_SEVENTY_FIVE, TRUE);
    jpeg_start_compress(&cinfo_, TRUE);
    jpegbuf_ = new (std::nothrow) JSAMPLE[parm.GetBytesPerLine() / sizeof(JSAMPLE)]{};
    if (jpegbuf_ == nullptr) {
        SCAN_HILOGE("jpegbuf new fail");
        return E_SCAN_SERVER_FAILURE;
    }
    return E_SCAN_NONE;
}

int32_t ScanTask::WritePicData(int32_t& jpegrow, std::vector<uint8_t>& dataBuffer, ScanParameters &parm)
{
    int32_t i = 0;
    int32_t left = static_cast<int32_t>(dataBuffer.size());
    if (setjmp(jpegJumpBuffer_) != 0) {
        SCAN_HILOGE("WritePicData failed, longjmp from JpegErrorExit");
        return E_SCAN_NO_MEM;
    }
    while (jpegrow + left >= parm.GetBytesPerLine()) {
        if (memcpy_s(jpegbuf_ + jpegrow, parm.GetBytesPerLine() - jpegrow, dataBuffer.data() + i,
            parm.GetBytesPerLine() - jpegrow) != E_SCAN_NONE) {
            SCAN_HILOGE("memcpy_s failed");
            return E_SCAN_SERVER_FAILURE;
        }
        if (parm.GetDepth() != 1) {
            jpeg_write_scanlines(&cinfo_, &jpegbuf_, BIT);
            i += parm.GetBytesPerLine() - jpegrow;
            left -= parm.GetBytesPerLine() - jpegrow;
            jpegrow = 0;
            continue;
        }
        int64_t jpegImageBytes = static_cast<int64_t>(parm.GetBytesPerLine()) * BYTE_BITS;
        if (jpegImageBytes < 0 || jpegImageBytes > MAX_BUFLEN) {
            SCAN_HILOGE("nultiplication would overflow");
            return E_SCAN_SERVER_FAILURE;
        }
        std::vector<JSAMPLE> buf8(static_cast<int32_t>(jpegImageBytes));
        for (int32_t col1 = 0; col1 < parm.GetBytesPerLine(); col1++) {
            for (int32_t col8 = 0; col8 < BYTE_BITS; col8++) {
                buf8[col1 * BYTE_BITS + col8] = jpegbuf_[col1] & (1 << (BYTE_BITS - col8 - BIT)) ? 0 : 0xff;
            }
        }
        JSAMPLE* buf8Ptr = buf8.data();
        jpeg_write_scanlines(&cinfo_, &buf8Ptr, BIT);
        i += parm.GetBytesPerLine() - jpegrow;
        left -= parm.GetBytesPerLine() - jpegrow;
        jpegrow = 0;
        continue;
    }
    if (memcpy_s(jpegbuf_ + jpegrow, parm.GetBytesPerLine(), dataBuffer.data() + i, left) != E_SCAN_NONE) {
        SCAN_HILOGE("memcpy_s failed");
        return E_SCAN_SERVER_FAILURE;
    }
    jpegrow += left;
    return E_SCAN_NONE;
}

void ScanTask::JpegDestroyCompress()
{
    jpeg_destroy_compress(&cinfo_);
    DELETE_ARRAY_AND_NULLIFY(jpegbuf_)
    if (ofp_ != nullptr) {
        fclose(ofp_);
        ofp_ = nullptr;
    }
}

void ScanTask::JpegFinishCompress()
{
    jpeg_finish_compress(&cinfo_);
    if (ofp_ != nullptr) {
        fflush(ofp_);
        fclose(ofp_);
        ofp_ = nullptr;
    }
}

void ScanTask::JpegErrorExit(j_common_ptr cinfo)
{
    ScanTask* self = static_cast<ScanTask*>(cinfo->client_data);
    if (self != nullptr) {
        SCAN_HILOGE("ScanTask JpegErrorExit");
        longjmp(self->jpegJumpBuffer_, 1);
    }
}
} // namespace OHOS::Scan
