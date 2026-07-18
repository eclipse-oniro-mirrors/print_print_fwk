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
    : jobId_(""), printerId_(""), jobState_(PRINT_JOB_PREPARED), subState_(PRINT_JOB_BLOCKED_UNKNOWN), copyNumber_(0),
      isSequential_(false), isLandscape_(false), colorMode_(0), duplexMode_(0),
      hasMargin_(false), hasPreview_(false), hasOption_(false), option_(""), hasVendorOptions_(false)
{
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
    hasVendorOptions_ = right.hasVendorOptions_;
    vendorOptions_ = right.vendorOptions_;
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
        hasVendorOptions_ = right.hasVendorOptions_;
        vendorOptions_ = right.vendorOptions_;
    }
    return *this;
}

PrintJob::~PrintJob()
{}

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
    subState_ = subState;
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
    hasVendorOptions_ = jobInfo.hasVendorOptions_;
    vendorOptions_ = jobInfo.vendorOptions_;
}

void PrintJob::GetFdList(std::vector<uint32_t> &fdList) const
{
    fdList.clear();
    fdList.assign(fdList_.begin(), fdList_.end());
}

void PrintJob::DupFdList(std::vector<uint32_t> &fdList) const
{
    fdList.clear();
    for (uint32_t fd : fdList_) {
        int32_t dupFd = dup(fd);
        if (dupFd < 0) {
            PRINT_HILOGW("dup fd failed");
            fdList.push_back(fd);
            continue;
        }
        fdList.push_back(static_cast<uint32_t>(dupFd));
    }
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

void PrintJob::SetVendorOptions(const std::string &vendorOptions)
{
    hasVendorOptions_ = true;
    vendorOptions_ = vendorOptions;
}

bool PrintJob::HasVendorOptions() const
{
    return hasVendorOptions_;
}

const std::string &PrintJob::GetVendorOptions() const
{
    return vendorOptions_;
}

bool PrintJob::ReadParcelFD(Parcel &parcel)
{
    uint32_t fdSize = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(fdSize), false);
    fdList_.clear();

    CHECK_IS_EXCEED_PRINT_RANGE_BOOL(fdSize);
    auto msgParcel = static_cast<MessageParcel *>(&parcel);
    for (uint32_t index = 0; index < fdSize; index++) {
        auto fd = msgParcel->ReadFileDescriptor();
        PRINT_HILOGD("fd[%{public}d] = %{public}d", index, fd);
        fdList_.emplace_back(fd);
    }
    return true;
}

bool PrintJob::ReadFromParcel(Parcel &parcel)
{
    if (parcel.GetReadableBytes() == 0) {
        PRINT_HILOGE("no data in parcel");
        return false;
    }
    if (!ReadParcelFD(parcel)) {
        return false;
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(jobId_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(printerId_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(jobState_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(subState_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(copyNumber_), false);
    auto rangePtr = PrintRange::Unmarshalling(parcel);
    if (rangePtr != nullptr) {
        SetPageRange(*rangePtr);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(isSequential_), false);
    auto pageSizePtr = PrintPageSize::Unmarshalling(parcel);
    if (pageSizePtr != nullptr) {
        SetPageSize(*pageSizePtr);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(isLandscape_), false);
    return ReadLayoutFromParcel(parcel);
}

bool PrintJob::ReadLayoutFromParcel(Parcel &parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(colorMode_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadUint32(duplexMode_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasMargin_), false);
    if (hasMargin_) {
        auto marginPtr = PrintMargin::Unmarshalling(parcel);
        if (marginPtr != nullptr) {
            margin_ = *marginPtr;
        }
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasPreview_), false);
    if (hasPreview_) {
        auto previewPtr = PrintPreviewAttribute::Unmarshalling(parcel);
        if (previewPtr != nullptr) {
            preview_ = *previewPtr;
        }
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasOption_), false);
    if (hasOption_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(option_), false);
    }
    if (!ReadVendorOptionsFromParcel(parcel)) {
        return false;
    }
    return true;
}
 	 
bool PrintJob::ReadVendorOptionsFromParcel(Parcel &parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasVendorOptions_), false);
    if (hasVendorOptions_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(vendorOptions_), false);
    }
    return true;
}

bool PrintJob::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(static_cast<uint32_t>(fdList_.size())), false);
    auto msgParcel = static_cast<MessageParcel *>(&parcel);
    if (msgParcel != nullptr) {
        for (auto fd : fdList_) {
            msgParcel->WriteFileDescriptor(fd);
        }
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetJobId()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetPrinterId()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetJobState()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetSubState()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetCopyNumber()), false);
    if (!pageRange_.Marshalling(parcel)) {
        PRINT_HILOGE("Marshalling for pageRange_ failed");
        return false;
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(GetIsSequential()), false);
    return MarshallingParam(parcel);
}

bool PrintJob::MarshallingParam(Parcel &parcel) const
{
    if (!pageSize_.Marshalling(parcel)) {
        PRINT_HILOGE("Marshalling for pageSize_ failed");
        return false;
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(GetIsLandscape()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetColorMode()), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteUint32(GetDuplexMode()), false);

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasMargin_), false);
    if (hasMargin_) {
        if (!margin_.Marshalling(parcel)) {
            PRINT_HILOGE("Marshalling for margin_ failed");
            return false;
        }
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasPreview_), false);
    if (hasPreview_) {
        if (!preview_.Marshalling(parcel)) {
            PRINT_HILOGE("Marshalling for preview_ failed");
            return false;
        }
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasOption_), false);
    if (hasOption_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetOption()), false);
    }

    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasVendorOptions_), false);
    if (hasVendorOptions_) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(GetVendorOptions()), false);
    }

   return true;
}

std::shared_ptr<PrintJob> PrintJob::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintJob>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("nativeObj is nullptr");
        return nullptr;
    }
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
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
    if (hasVendorOptions_) {
        PRINT_HILOGD("vendorOptions: %{private}s", vendorOptions_.c_str());
    }
}

std::string PrintJob::ConvertToJsonString() const
{
    Json::Value json;
    json["printerId"] = printerId_;
    json["jobId"] = jobId_;
    json["copyNumber"] = copyNumber_;
    json["colorMode"] = colorMode_;
    json["duplexMode"] = duplexMode_;
    json["pageSize"] = pageSize_.GetName();
    if (hasOption_) {
        json["option"] = option_;
    }
    if (hasVendorOptions_) {
        json["vendorOptions"] = vendorOptions_;
    }
    Json::StreamWriterBuilder wBuilder;
    std::string jsonString = Json::writeString(wBuilder, json);
    return jsonString;
}

Json::Value PrintJob::ConvertToJsonObject() const
{
    Json::Value jsonObject;
    jsonObject["jobId"] = jobId_;
    jsonObject["printerId"] = printerId_;
    jsonObject["jobState"] = jobState_;
    jsonObject["subState"] = subState_;
    jsonObject["copyNumber"] = copyNumber_;
    jsonObject["pageRange"] = pageRange_.ConvertToJsonObject();
    jsonObject["isSequential"] = isSequential_;
    jsonObject["pageSize"] = pageSize_.ConvertToJsonObject();
    jsonObject["isLandscape"] = isLandscape_;
    jsonObject["colorMode"] = colorMode_;
    jsonObject["duplexMode"] = duplexMode_;
    jsonObject["hasMargin"] = hasMargin_;
    if (hasMargin_) {
        jsonObject["margin"] = margin_.ConvertToJsonObject();
    }
    jsonObject["hasPreview"] = hasPreview_;
    if (hasPreview_) {
        jsonObject["preview"] = preview_.ConvertToJsonObject();
    }
    jsonObject["hasOption"] = hasOption_;
    if (hasOption_) {
        jsonObject["option"] = option_;
    }
    jsonObject["hasVendorOptions"] = hasVendorOptions_;
    if (hasVendorOptions_) {
        jsonObject["vendorOptions"] = vendorOptions_;
    }
    return jsonObject;
}
}  // namespace OHOS::Print
