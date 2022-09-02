/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_PRINT_JOB_H
#define PRINT_PRINT_JOB_H
#include <map>
#include <string>
#include <vector>
#include "print_range.h"
#include "print_page_size.h"
#include "print_margin.h"
#include "preview_attribute.h"

namespace OHOS::Print{
class PrintJob {
public:
    explicit PrintJob();
    PrintJob(const PrintJob& right);
    PrintJob& operator=(PrintJob& right);
    ~PrintJob();
    
    void SetFiles(const std::vector<std::string>& files);

    void SetJobId(uint32_t jobId);

    void SetPrintId(uint32_t printerid);

    void SetJobState(uint32_t jobState);

    void SetCopyNumber(uint32_t copyNumber);

    void SetPageRange(PrintRange pageRange_);

    void SetIsSequential(bool isSequential_);

    void SetPageSize(PrintPageSize pageSize_);

    void SetIsLandscape(bool isLandscape_);

    void SetColorMode(uint32_t colorMode_);

    void SetDuplexMode(uint32_t duplexmode);

    void SetMargin(PrintMargin margin_);

    void SetPreview(PreviewAttribute preview_);

    void GetFiles(std::vector<std::string>& fileList) const;

    [[nodiscard]] uint32_t GetJobId() const;

    [[nodiscard]] uint32_t GetPrinterId() const;

    [[nodiscard]] uint32_t GetJobState() const;

    [[nodiscard]] uint32_t GetCopyNumber() const;

    void GetPageRange(PrintRange& range) const;

    [[nodiscard]] bool GetIsSequential() const;

    void GetPageSize(PrintPageSize& printPageSize) const;

    [[nodiscard]] bool GetIsLandscape() const;

    [[nodiscard]] uint32_t GetColorMode() const;

    [[nodiscard]] uint32_t GetDuplexMode() const;

    void GetMargin(PrintMargin& printMargin) const;

    void GetPreview(PreviewAttribute& previewAttr) const;

    void Dump();
private:
    std::vector<std::string> files_;
    uint32_t jobId_;
    uint32_t printerId_;
    uint32_t jobState_;
    uint32_t copyNumber_;
    PrintRange pageRange_;
    bool isSequential_;
    PrintPageSize pageSize_;
    bool isLandscape_;
    int32_t colorMode_;
    int32_t duplexMode_;
    PrintMargin margin_;
    PreviewAttribute preview_;
/*
    enum PrintJobState {
        PRINT_JOB_CREATED = 1,
        PRINT_JOB_QUEUED = 2,
        PRINT_JOB_PRINTING = 3,
        PRINT_JOB_BLOCKED = 4,
        PRINT_JOB_SUCCESS = 5,
        PRINT_JOB_FAILED = 6,
        PRINT_JOB_cancelled = 7,
    };

    enum PrintState{
        PRINT_CREATED = 1,
        PRINT_QUEUED = 2,
        PRINT_PRINTING = 3,
        PRINT_BLOCKED = 4,
        PRINT_SUCCESS = 5,
        PRINT_FAILED = 6,
        PRINT_cancelled = 7,
    };
*/    
};
}// namespace OHOS::Request::Print
#endif /* PRINT_PRINT_JOB_H */
