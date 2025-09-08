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
#include "jpeglib.h"
#include "scan_parameters.h"

namespace OHOS::Scan {

class ScanTask {
public:
    ScanTask(const std::string& scannerId, int32_t userId, bool batchMode);
    std::string GetScannerId() const;
    ~ScanTask();
    bool GetBatchMode();
    bool CreateAndOpenScanFile(std::string& filePath);
    int32_t WriteJpegHeader(ScanParameters &parm, const UINT16& dpi);
    int32_t WritePicData(int32_t& jpegrow, std::vector<uint8_t>& dataBuffer, ScanParameters &parm);
    void JpegDestroyCompress();
    void JpegFinishCompress();

private:
    ScanTask(const ScanTask&) = delete;
    ScanTask& operator=(const ScanTask&) = delete;
    static void JpegErrorExit(j_common_ptr cinfo);
    std::string scannerId_;
    bool batchMode_;
    bool isJpegWriteSuccess_;
    int32_t userId_;
    FILE *ofp_;
    JSAMPLE *jpegbuf_;
    struct jpeg_compress_struct cinfo_;
    struct jpeg_error_mgr jerr_;
};

} // namespace OHOS::Scan
#endif // SCAN_TASK