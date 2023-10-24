/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
PrintJob::PrintJob()
    : jobId_(""), printerId_(""), jobState_(PRINT_JOB_PREPARED),
      subState_(PRINT_JOB_BLOCKED_UNKNOWN), copyNumber_(0),
      isSequential_(false), isLandscape_(false), colorMode_(0), duplexMode_(0),
      hasMargin_(false), hasPreview_(false), hasOption_(false), option_("") {
    margin_.Reset();
    preview_.Reset();
}

PrintJob::PrintJob(const PrintJob &right)
{
    fdList_.clear();
    fdList_.assign(right.fdList_.begin(), right.fdList_.end());

    printerId_ = right.printerId_;
    jobId_ = right.jobId_;
    jobState_ = right.jobState_;
    subState_ = right.subState_;
    copyNumber_ = right.copyNumber_;
    pageRange_ = right.pageRange_;
    isSequential_ = right.isSequential_;
    pageSize_ = right.pageSize_;
    isLandscape_ = right.isLandscape_;
    colorMode_ = right.colorMode_;
    duplexMode_ = right.duplexMode_;
    hasMargin_ = right.hasMargin_;
    margin_ = right.margin_;
    hasPreview_ = right.hasPreview_;
    preview_ = right.preview_;
    hasOption_ = right.hasOption_;
    option_ = right.option_;
}

PrintJob &PrintJob::operator=(const PrintJob &right)
{
    if (this != &right) {
        fdList_.clear();
        fdList_.assign(right.fdList_.begin(), right.fdList_.end());

        printerId_ = right.printerId_;
        jobId_ = right.jobId_;
        jobState_ = right.jobState_;
        subState_ = right.subState_;
        copyNumber_ = right.copyNumber_;
        pageRange_ = right.pageRange_;
        isSequential_ = right.isSequential_;
        pageSize_ = right.pageSize_;
        isLandscape_ = right.isLandscape_;
        colorMode_ = right.colorMode_;
        duplexMode_ = right.duplexMode_;
        hasMargin_ = right.hasMargin_;
        margin_ = right.margin_;
        hasPreview_ = right.hasPreview_;
        preview_ = right.preview_;
        hasOption_ = right.hasOption_;
        option_ = right.option_;
    }
    return *this;
}

PrintJob::~PrintJob()
{
}

void PrintJob::SetFdList(const std::vector<uint32_t> &fdList)
{
    fdList_.clear();
    fdList_.assign(fdList.begin(), fdList.end());
}

void PrintJob::SetJobId(const std::string &jobId)
{
    jobId_ = jobId;
}

void PrintJob::SetPrinterId(const std::string &printerid)
{
    printerId_ = printerid;
}

void PrintJob::SetJobState(uint32_t jobState)
{
    if (jobState < PRINT_JOB_UNKNOWN) {
        jobState_ = jobState;
    }
}

void PrintJob::SetSubState(uint32_t subState)
{
    if (jobState_ == PRINT_JOB_COMPLETED && subState <= PRINT_JOB_COMPLETED_FILE_CORRUPT) {
        subState_ = subState;
    }
    if (jobState_ == PRINT_JOB_BLOCKED &&
    (subState < PRINT_JOB_BLOCKED_UNKNOWN && subState > PRINT_JOB_COMPLETED_FILE_CORRUPT)) {
        subState_ = subState;
    }
    if (jobState_ == PRINT_JOB_RUNNING &&
    (subState < PRINT_JOB_BLOCKED_UNKNOWN && subState > PRINT_JOB_COMPLETED_FILE_CORRUPT)) {
        subState_ = subState;
    }

    if (jobState_ == PRINT_JOB_CREATE_FILE_COMPLETED &&
    (subState == PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS || subState == PRINT_JOB_CREATE_FILE_COMPLETED_FAILED)) {
        subState_ = subState;
    }
}

void PrintJob::SetCopyNumber(uint32_t copyNumber)
{
    copyNumber_ = copyNumber;
}

void PrintJob::SetPageRange(const PrintRange &pageRange)
{
    pageRange_ = pageRange;
}

void PrintJob::SetIsSequential(bool isSequential)
{
    isSequential_ = isSequential;
}

void PrintJob::SetPageSize(const PrintPageSize &pageSize)
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

void PrintJob::SetMargin(const PrintMargin &margin)
{
    hasMargin_ = true;
    margin_ = margin;
}

void PrintJob::SetOption(const std::string &option)
{
    hasOption_ = true;
    option_ = option;
}

void PrintJob::SetPreview(const PrintPreviewAttribute &preview)
{
    hasPreview_ = true;
    preview_ = preview;
}

void PrintJob::UpdateParams(const PrintJob &jobInfo)
{
    fdList_.clear();
    fdList_.assign(jobInfo.fdList_.begin(), jobInfo.fdList_.end());

    jobId_ = jobInfo.jobId_;
    printerId_ = jobInfo.printerId_;
    copyNumber_ = jobInfo.copyNumber_;
    pageRange_ = jobInfo.pageRange_;
    isSequential_ = jobInfo.isSequential_;
    pageSize_ = jobInfo.pageSize_;
    isLandscape_ = jobInfo.isLandscape_;
    colorMode_ = jobInfo.colorMode_;
    duplexMode_ = jobInfo.duplexMode_;
    hasMargin_ = jobInfo.hasMargin_;
    margin_ = jobInfo.margin_;
    hasPreview_ = jobInfo.hasPreview_;
    preview_ = jobInfo.preview_;
    hasOption_ = jobInfo.hasOption_;
    option_ = jobInfo.option_;
}

void PrintJob::GetFdList(std::vector<uint32_t> &fdList) const
{
    fdList.clear();
    fdList.assign(fdList_.begin(), fdList_.end());
}

const std::string &PrintJob::GetJobId() const
{
    return jobId_;
}

const std::string &PrintJob::GetPrinterId() const
{
    return printerId_;
}

uint32_t PrintJob::GetJobState() const
{
    return jobState_;
}

uint32_t PrintJob::GetSubState() const
{
    return subState_;
}

uint32_t PrintJob::GetCopyNumber() const
{
    return copyNumber_;
}

void PrintJob::GetPageRange(PrintRange &range) const
{
    range = pageRange_;
}

bool PrintJob::GetIsSequential() const
{
    return isSequential_;
}
void PrintJob::GetPageSize(PrintPageSize &pageSize) const
{
    pageSize = pageSize_;
}

bool PrintJob::GetIsLandscape() const
{
    return isLandscape_;
}

uint32_t PrintJob::GetColorMode() const
{
    return colorMode_;
}

uint32_t PrintJob::GetDuplexMode() const
{
    return duplexMode_;
}

bool PrintJob::HasMargin() const
{
    return hasMargin_;
}

void PrintJob::GetMargin(PrintMargin &margin) const
{
    margin = margin_;
}

bool PrintJob::HasPreview() const
{
    return hasPreview_;
}

void PrintJob::GetPreview(PrintPreviewAttribute &previewAttr) const
{
    previewAttr = preview_;
}

bool PrintJob::HasOption() const
{
    return hasOption_;
}

const std::string &PrintJob::GetOption() const
{
    return option_;
}

void PrintJob::ReadParcelFD(Parcel &parcel)
{
    uint32_t fdSize = parcel.ReadUint32();
    fdList_.clear();

    CHECK_IS_EXCEED_PRINT_RANGE_VOID(fdSize);
    auto msgParcel = static_cast<MessageParcel*>(&parcel);
    for (uint32_t index = 0; index < fdSize; index++) {
        auto fd = msgParcel->ReadFileDescriptor();
        PRINT_HILOGD("fd[%{public}d] = %{public}d", index, fd);
        fdList_.emplace_back(fd);
    }
}

void PrintJob::ReadFromParcel(Parcel &parcel)
{
    ReadParcelFD(parcel);
    SetJobId(parcel.ReadString());
    SetPrinterId(parcel.ReadString());
    SetJobState(parcel.ReadUint32());
    SetSubState(parcel.ReadUint32());
    SetCopyNumber(parcel.ReadUint32());
    auto rangePtr = PrintRange::Unmarshalling(parcel);
    if (rangePtr != nullptr) {
        SetPageRange(*rangePtr);
    }
    SetIsSequential(parcel.ReadBool());
    auto pageSizePtr = PrintPageSize::Unmarshalling(parcel);
    if (pageSizePtr != nullptr) {
        SetPageSize(*pageSizePtr);
    }
    SetIsLandscape(parcel.ReadBool());
    SetColorMode(parcel.ReadUint32());
    SetDuplexMode(parcel.ReadUint32());
    hasMargin_ = parcel.ReadBool();
    if (hasMargin_) {
        auto marginPtr = PrintMargin::Unmarshalling(parcel);
        if (marginPtr != nullptr) {
            margin_ = *marginPtr;
        }
    }
    hasPreview_ = parcel.ReadBool();
    if (hasPreview_) {
        auto previewPtr = PrintPreviewAttribute::Unmarshalling(parcel);
        if (previewPtr != nullptr) {
            preview_ = *previewPtr;
        }
    }
    hasOption_ = parcel.ReadBool();
    if (hasOption_) {
        SetOption(parcel.ReadString());
    }
}

bool PrintJob::Marshalling(Parcel &parcel) const
{
    parcel.WriteUint32(fdList_.size());
    auto msgParcel = static_cast<MessageParcel*>(&parcel);
    if (msgParcel != nullptr) {
        for (auto fd : fdList_) {
            msgParcel->WriteFileDescriptor(fd);
        }
    }

    parcel.WriteString(GetJobId());
    parcel.WriteString(GetPrinterId());
    parcel.WriteUint32(GetJobState());
    parcel.WriteUint32(GetSubState());
    parcel.WriteUint32(GetCopyNumber());
    pageRange_.Marshalling(parcel);
    parcel.WriteBool(GetIsSequential());
    return MarshallingParam(parcel);
}

bool PrintJob::MarshallingParam(Parcel &parcel) const
{
    pageSize_.Marshalling(parcel);
    parcel.WriteBool(GetIsLandscape());
    parcel.WriteUint32(GetColorMode());
    parcel.WriteUint32(GetDuplexMode());

    parcel.WriteBool(hasMargin_);
    if (hasMargin_) {
        margin_.Marshalling(parcel);
    }

    parcel.WriteBool(hasPreview_);
    if (hasPreview_) {
        preview_.Marshalling(parcel);
    }

    parcel.WriteBool(hasOption_);
    if (hasOption_) {
        parcel.WriteString(GetOption());
    }

    return true;
}

std::shared_ptr<PrintJob> PrintJob::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintJob>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrintJob::Dump()
{
    uint32_t fileLength = fdList_.size();
    for (uint32_t i = 0; i < fileLength; i++) {
        PRINT_HILOGD("fd = %{public}d", fdList_[i]);
    }

    PRINT_HILOGD("jobId_ = %{public}s", jobId_.c_str());
    PRINT_HILOGD("printerId_ = %{private}s", printerId_.c_str());
    PRINT_HILOGD("jobState_ = %{public}d", jobState_);
    PRINT_HILOGD("subState_ = %{public}d", subState_);
    PRINT_HILOGD("copyNumber_ = %{public}d", copyNumber_);
    PRINT_HILOGD("isSequential_ = %{public}d", isSequential_);
    PRINT_HILOGD("isLandscape_ = %{public}d", isLandscape_);
    PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);

    pageRange_.Dump();
    pageSize_.Dump();
    if (hasMargin_) {
        margin_.Dump();
    }
    if (hasPreview_) {
        preview_.Dump();
    }
    if (hasOption_) {
        PRINT_HILOGD("option: %{private}s", option_.c_str());
    }
}
} // namespace OHOS::Print
