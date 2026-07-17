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

#define private public
#include "fuzzer/FuzzedDataProvider.h"
#include "scantask_fuzzer.h"
#include "scan_task.h"
#include "scan_parameters.h"
#include "scan_constant.h"
#include "print_log.h"
#include <functional>

namespace OHOS::Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t MIN_IMAGE_DIM = 1;
constexpr int32_t MAX_IMAGE_DIM = 16;
constexpr int32_t FUZZ_DEFAULT_USER_ID = 100;
constexpr int32_t FUZZ_SMALL_IMAGE_WIDTH = 4;
constexpr int32_t FUZZ_SMALL_IMAGE_HEIGHT = 4;
constexpr int32_t FUZZ_SMALL_IMAGE_BYTES_PER_LINE = 12;
constexpr int32_t FUZZ_RGB_DEPTH = 8;
constexpr int32_t FUZZ_MONO_DEPTH = 1;
constexpr int32_t FUZZ_MAX_IMAGE_FORMAT_INDEX = 5;
constexpr uint32_t FUZZ_MAX_QUALITY = 200;
constexpr size_t FUZZ_MAX_CHUNK_SIZE = 64;
constexpr int32_t FUZZ_GRAY_BYTES_MULTIPLIER = 2;

void TestConstructorAndGetter(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    bool batchMode = dataProvider->ConsumeBool();
    ScanTask task(scannerId, userId, batchMode);
    task.GetScannerId();
    task.GetBatchMode();
    task.GetImageFormat();
}

void TestWriteImageHeaderRgb(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, dataProvider->ConsumeBool());

    int32_t width = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t height = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t bytesPerLine = width * CHANNEL_THREE;

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_RGB);
    parm.SetPixelsPerLine(width);
    parm.SetLines(height);
    parm.SetBytesPerLine(bytesPerLine);
    parm.SetDepth(FUZZ_RGB_DEPTH);

    uint16_t dpi = dataProvider->ConsumeIntegralInRange<uint16_t>(1, DEFAULT_DPI);
    int32_t ret = task.WriteImageHeader(parm, dpi);
    if (ret == E_SCAN_NONE) {
        std::vector<uint8_t> imageData = dataProvider->ConsumeRemainingBytes<uint8_t>();
        if (!imageData.empty()) {
            task.WriteImageData(imageData);
        }
        task.ImageDestroyCompress();
    }
}

void TestWriteImageHeaderGray(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, dataProvider->ConsumeBool());

    int32_t width = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t height = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t bytesPerLine = width;

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_GRAY);
    parm.SetPixelsPerLine(width);
    parm.SetLines(height);
    parm.SetBytesPerLine(bytesPerLine);
    parm.SetDepth(FUZZ_RGB_DEPTH);

    uint16_t dpi = dataProvider->ConsumeIntegralInRange<uint16_t>(1, DEFAULT_DPI);
    int32_t ret = task.WriteImageHeader(parm, dpi);
    if (ret == E_SCAN_NONE) {
        std::vector<uint8_t> imageData = dataProvider->ConsumeRemainingBytes<uint8_t>();
        if (!imageData.empty()) {
            task.WriteImageData(imageData);
        }
        task.ImageDestroyCompress();
    }
}

void TestWriteImageHeaderMono(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, dataProvider->ConsumeBool());

    int32_t width = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t height = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t bytesPerLine = (width + 7) / BYTE_BITS;

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_GRAY);
    parm.SetPixelsPerLine(width);
    parm.SetLines(height);
    parm.SetBytesPerLine(bytesPerLine);
    parm.SetDepth(FUZZ_MONO_DEPTH);

    uint16_t dpi = dataProvider->ConsumeIntegralInRange<uint16_t>(1, DEFAULT_DPI);
    int32_t ret = task.WriteImageHeader(parm, dpi);
    if (ret == E_SCAN_NONE) {
        std::vector<uint8_t> imageData = dataProvider->ConsumeRemainingBytes<uint8_t>();
        if (!imageData.empty()) {
            task.WriteImageData(imageData);
        }
        task.ImageDestroyCompress();
    }
}

void TestWriteImageDataNoInit(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, false);

    std::vector<uint8_t> imageData = dataProvider->ConsumeRemainingBytes<uint8_t>();
    task.WriteImageData(imageData);
}

void TestWriteImageDataEmpty(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanTask task("fuzz_scanner", FUZZ_DEFAULT_USER_ID, false);

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_RGB);
    parm.SetPixelsPerLine(FUZZ_SMALL_IMAGE_WIDTH);
    parm.SetLines(FUZZ_SMALL_IMAGE_HEIGHT);
    parm.SetBytesPerLine(FUZZ_SMALL_IMAGE_BYTES_PER_LINE);
    parm.SetDepth(FUZZ_RGB_DEPTH);

    int32_t ret = task.WriteImageHeader(parm, DEFAULT_DPI);
    if (ret == E_SCAN_NONE) {
        std::vector<uint8_t> emptyData;
        task.WriteImageData(emptyData);
        task.ImageDestroyCompress();
    }
}

void TestCreateAndOpenScanFile(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, dataProvider->ConsumeBool());

    std::string filePath;
    int32_t imgFmtInt = dataProvider->ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_IMAGE_FORMAT_INDEX);
    ImageFormat imgFmt = static_cast<ImageFormat>(imgFmtInt);
    uint32_t quality = dataProvider->ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_QUALITY);
    task.CreateAndOpenScanFile(filePath, imgFmt, quality);
}

void TestFinishCompressNoInit(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, false);
    task.ImageFinishCompress();
}

void TestDestroyCompress(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, dataProvider->ConsumeBool());
    task.ImageDestroyCompress();
}

void TestWriteHeaderAlreadyWrited(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanTask task("fuzz_scanner", FUZZ_DEFAULT_USER_ID, false);

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_RGB);
    parm.SetPixelsPerLine(FUZZ_SMALL_IMAGE_WIDTH);
    parm.SetLines(FUZZ_SMALL_IMAGE_HEIGHT);
    parm.SetBytesPerLine(FUZZ_SMALL_IMAGE_BYTES_PER_LINE);
    parm.SetDepth(FUZZ_RGB_DEPTH);

    task.WriteImageHeader(parm, DEFAULT_DPI);
    task.WriteImageHeader(parm, DEFAULT_DPI);
    task.ImageDestroyCompress();
}

void TestUnsupportedFormat(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, false);

    int32_t width = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t height = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_RED);
    parm.SetPixelsPerLine(width);
    parm.SetLines(height);
    parm.SetBytesPerLine(width * CHANNEL_THREE);
    parm.SetDepth(FUZZ_RGB_DEPTH);

    int32_t ret = task.WriteImageHeader(parm, DEFAULT_DPI);
    if (ret == E_SCAN_NONE) {
        std::vector<uint8_t> imageData = dataProvider->ConsumeRemainingBytes<uint8_t>();
        if (!imageData.empty()) {
            task.WriteImageData(imageData);
        }
        task.ImageDestroyCompress();
    }
}

void TestCreateAndOpenScanFileAlreadyOpened(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, false);

    task.imagePacker_ = std::make_unique<Media::ImagePacker>();
    std::string filePath;
    task.CreateAndOpenScanFile(filePath, ImageFormat::IMAGE_TYPE_JPEG, JPEG_QUALITY_SEVENTY_FIVE);
    task.ImageDestroyCompress();
}

void TestWriteImageDataMultipleCalls(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanTask task("fuzz_scanner", FUZZ_DEFAULT_USER_ID, false);

    int32_t width = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t height = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_RGB);
    parm.SetPixelsPerLine(width);
    parm.SetLines(height);
    parm.SetBytesPerLine(width * CHANNEL_THREE);
    parm.SetDepth(FUZZ_RGB_DEPTH);

    int32_t ret = task.WriteImageHeader(parm, DEFAULT_DPI);
    if (ret == E_SCAN_NONE) {
        size_t firstSize = dataProvider->ConsumeIntegralInRange<size_t>(1, FUZZ_MAX_CHUNK_SIZE);
        std::vector<uint8_t> firstChunk = dataProvider->ConsumeBytes<uint8_t>(firstSize);
        task.WriteImageData(firstChunk);

        std::vector<uint8_t> secondChunk = dataProvider->ConsumeRemainingBytes<uint8_t>();
        if (!secondChunk.empty()) {
            task.WriteImageData(secondChunk);
        }
        task.ImageDestroyCompress();
    }
}

void TestGetImageFormatAfterInit(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, false);
    task.GetImageFormat();

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_RGB);
    parm.SetPixelsPerLine(FUZZ_SMALL_IMAGE_WIDTH);
    parm.SetLines(FUZZ_SMALL_IMAGE_HEIGHT);
    parm.SetBytesPerLine(FUZZ_SMALL_IMAGE_BYTES_PER_LINE);
    parm.SetDepth(FUZZ_RGB_DEPTH);
    task.WriteImageHeader(parm, DEFAULT_DPI);
    task.GetImageFormat();
    task.ImageDestroyCompress();
    task.GetImageFormat();
}

void TestGreyDataInsufficientSrc(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanTask task(scannerId, userId, false);

    int32_t width = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t height = dataProvider->ConsumeIntegralInRange<int32_t>(MIN_IMAGE_DIM, MAX_IMAGE_DIM);
    int32_t bytesPerLine = dataProvider->ConsumeIntegralInRange<int32_t>(1, width * FUZZ_GRAY_BYTES_MULTIPLIER);

    ScanParameters parm;
    parm.SetFormat(SCAN_FRAME_GRAY);
    parm.SetPixelsPerLine(width);
    parm.SetLines(height);
    parm.SetBytesPerLine(bytesPerLine);
    parm.SetDepth(FUZZ_RGB_DEPTH);

    uint16_t dpi = dataProvider->ConsumeIntegralInRange<uint16_t>(1, DEFAULT_DPI);
    int32_t ret = task.WriteImageHeader(parm, dpi);
    if (ret == E_SCAN_NONE) {
        std::vector<uint8_t> imageData = dataProvider->ConsumeRemainingBytes<uint8_t>();
        if (!imageData.empty()) {
            task.WriteImageData(imageData);
        }
        task.ImageDestroyCompress();
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Scan::U32_AT_SIZE || size > OHOS::Scan::FOO_MAX_LEN) {
    }
    FuzzedDataProvider dataProvider(data, size);
    PRINT_HILOGI("scantask_fuzzer is running at function LLVMFuzzerTestOneInput.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Scan::TestConstructorAndGetter,
        &OHOS::Scan::TestWriteImageHeaderRgb,
        &OHOS::Scan::TestWriteImageHeaderGray,
        &OHOS::Scan::TestWriteImageHeaderMono,
        &OHOS::Scan::TestWriteImageDataNoInit,
        &OHOS::Scan::TestWriteImageDataEmpty,
        &OHOS::Scan::TestCreateAndOpenScanFile,
        &OHOS::Scan::TestFinishCompressNoInit,
        &OHOS::Scan::TestDestroyCompress,
        &OHOS::Scan::TestWriteHeaderAlreadyWrited,
        &OHOS::Scan::TestUnsupportedFormat,
        &OHOS::Scan::TestCreateAndOpenScanFileAlreadyOpened,
        &OHOS::Scan::TestWriteImageDataMultipleCalls,
        &OHOS::Scan::TestGetImageFormatAfterInit,
        &OHOS::Scan::TestGreyDataInsufficientSrc,
    };

    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}
