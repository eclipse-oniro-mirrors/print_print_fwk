/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "print_converter.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_util.h"

namespace {
const uint32_t ORIENTATION_OFFSET = 3;
}  // namespace
namespace OHOS::Print {
Print_ErrorCode ConvertToNativeErrorCode(int32_t errorCode)
{
    if (errorCode >= E_PRINT_GENERIC_FAILURE && errorCode <= E_PRINT_UNKNOWN) {
        return static_cast<Print_ErrorCode>(errorCode + PRINT_ERROR_GENERIC_FAILURE - E_PRINT_GENERIC_FAILURE);
    }
    return static_cast<Print_ErrorCode>(errorCode);
}

Print_PrinterState ConvertPrinterState(uint32_t state)
{
    switch (state) {
        case PRINTER_ADDED:
            return PRINTER_UNAVAILABLE;
        case PRINTER_REMOVED:
            return PRINTER_UNAVAILABLE;
        case PRINTER_UPDATE_CAP:
            return PRINTER_UNAVAILABLE;
        case PRINTER_CONNECTED:
            return PRINTER_IDLE;
        case PRINTER_DISCONNECTED:
            return PRINTER_UNAVAILABLE;
        case PRINTER_RUNNING:
            return PRINTER_BUSY;
        default:
            return PRINTER_UNAVAILABLE;
    }
}

bool ConvertStringToInt(const char *src, int &dst)
{
    if (src == nullptr) {
        return false;
    }
    dst = atoi(src);
    if (errno == ERANGE) {
        PRINT_HILOGW("ConvertStringToInt fail: %{public}s", src);
        return false;
    }
    return true;
}

bool ConvertOrientationMode(const uint32_t &src, Print_OrientationMode &dst)
{
    if (src >= ORIENTATION_OFFSET && src - ORIENTATION_OFFSET <= static_cast<uint32_t>(ORIENTATION_MODE_NONE)) {
        dst = static_cast<Print_OrientationMode>(src - ORIENTATION_OFFSET);
        return true;
    } else {
        return false;
    }
}

bool ConvertColorMode(const uint32_t &src, Print_ColorMode &dst)
{
    if (src >= 0 && src <= static_cast<uint32_t>(COLOR_MODE_AUTO)) {
        dst = static_cast<Print_ColorMode>(src);
        return true;
    } else {
        return false;
    }
}

bool ConvertDuplexMode(const uint32_t &src, Print_DuplexMode &dst)
{
    if (src >= 0 && src <= static_cast<uint32_t>(DUPLEX_MODE_SHORT_EDGE)) {
        dst = static_cast<Print_DuplexMode>(src);
        return true;
    } else {
        return false;
    }
}

bool ConvertQuality(const uint32_t &src, Print_Quality &dst)
{
    if (src >= static_cast<uint32_t>(PRINT_QUALITY_DRAFT) && src <= static_cast<uint32_t>(PRINT_QUALITY_HIGH)) {
        dst = static_cast<Print_Quality>(src);
        return true;
    } else {
        return false;
    }
}

std::string GetDocumentFormatString(Print_DocumentFormat format)
{
    switch (format) {
        case DOCUMENT_FORMAT_JPEG:
            return "image/jpeg";
        case DOCUMENT_FORMAT_PDF:
            return "application/pdf";
        case DOCUMENT_FORMAT_POSTSCRIPT:
            return "application/postscript";
        case DOCUMENT_FORMAT_TEXT:
            return "text/plain";
        case DOCUMENT_FORMAT_AUTO:
            return "application/octet-stream";
        default:
            return "application/octet-stream";
    }
}

std::string GetResolutionString(Print_Resolution resolution)
{
    return std::to_string(resolution.horizontalDpi) + "x" + std::to_string(resolution.verticalDpi) + "dpi";
}
}  // namespace OHOS::Print
