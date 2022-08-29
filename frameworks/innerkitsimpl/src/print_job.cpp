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

#include "print_job.h"
#include "log.h"

namespace OHOS::Print{
PrintJob::PrintJob()
: jobId_(0), jobState_(1), copyNumber_(1), isSequential_(true),
isLandscape_(1), colorMode_(1), duplexMode_(1) {   

}

PrintJob::~PrintJob()
{

}

void PrintJob::SetFiles(std::string files)
{
    files_.push_back(files);
}

void PrintJob::SetJobId(uint32_t jobId)
{
    jobId_ = jobId;
}

void PrintJob::SetPrintId(uint32_t printerid)
{
    printerId_ = printerid;
}

void PrintJob::SetJobState(uint32_t jobState)
{
    jobState_ = jobState;
}
void PrintJob::SetCopyNumber(uint32_t copyNumber)
{
    copyNumber_ = copyNumber;
}
void PrintJob::SetPageRange(PrinterRange pageRange)
{
    pageRange_ = pageRange;
}
void PrintJob::SetIsSequential(bool isSequential)
{
    isSequential_ = isSequential;
}
void PrintJob::SetPageSize(PrinterPageSize pageSize)
{
    pageSize_ = pageSize;
}
void PrintJob::SetIsLandscape(bool isLandscape)
{
    isLandscape_ = isLandscape;
}
void PrintJob::SetColorMode(uint32_t colorMode)
{
    colorMode_ = colorMode;
}
void PrintJob::SetDuplexMode(uint32_t duplexmode)
{
    duplexMode_ = duplexmode;
}
void PrintJob::SetMargin(PrintMargin margin)
{
    margin_ = margin;
}
void PrintJob::SetPreview(PreviewAttribute preview)
{
    preview_ = preview;
}

std::vector<std::string> &PrintJob::GetFiles()
{
    return files_;
}
uint32_t PrintJob::GetJobId()
{
    return jobId_;
}

uint32_t PrintJob::GetPrinterId()
{
    return printerId_;
}

uint32_t PrintJob::GetJobState()
{
    return jobState_;
}

uint32_t PrintJob::GetCopyNumber()
{
    return copyNumber_;
}
PrinterRange &PrintJob::GetPageRange()
{
    return pageRange_;
}
bool PrintJob::GetIsSequential()
{
    return isSequential_;
}
PrinterPageSize &PrintJob::GetPageSize()
{
    return pageSize_;
}
bool PrintJob::GetIsLandscape()
{
    return isLandscape_;
}
uint32_t PrintJob::GetColorMode()
{
    return colorMode_;
}
uint32_t PrintJob::GetDuplexMode()
{
    return duplexMode_;
}
PrintMargin &PrintJob::GetMargin()
{
    return margin_;
}
PreviewAttribute &PrintJob::GetPreview()
{
    return preview_;
}

void PrintJob::Dump()
{
    uint32_t fileLength = files_.size();
    for(uint32_t i = 0; i < fileLength; i++)
    {
        PRINT_HILOGD("files_ = %{public}s", files_[i].c_str());
    }

    PRINT_HILOGD("jobId_ = %{public}d", jobId_);
    PRINT_HILOGD("printerId_ = %{public}d", printerId_);
    PRINT_HILOGD("jobState_ = %{public}d", jobState_);
    PRINT_HILOGD("copyNumber_ = %{public}d", copyNumber_);
    PRINT_HILOGD("isSequential_ = %{public}d", isSequential_);
    PRINT_HILOGD("isLandscape_ = %{public}d", isLandscape_);
    PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);
}
}
