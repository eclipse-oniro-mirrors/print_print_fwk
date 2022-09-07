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

#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
PrintJob::PrintJob()
    : jobId_(0), jobState_(1), copyNumber_(1), isSequential_(true), isLandscape_(1), colorMode_(1), duplexMode_(1)
{}

PrintJob::PrintJob(const PrintJob &right)
{
    files_.clear();
    files_.assign(right.files_.begin(), right.files_.end());

    printerId_ = right.printerId_;
    jobId_ = right.jobId_;
    jobState_ = right.jobState_;
    copyNumber_ = right.copyNumber_;
    pageRange_ = right.pageRange_;
    isSequential_ = right.isSequential_;
    pageSize_ = right.pageSize_;
    isLandscape_ = right.isLandscape_;
    colorMode_ = right.colorMode_;
    duplexMode_ = right.duplexMode_;
    margin_ = right.margin_;
    preview_ = right.preview_;
}

PrintJob &PrintJob::operator=(PrintJob &right)
{
    if (this != &right) {
        files_.clear();
        files_.assign(right.files_.begin(), right.files_.end());

        printerId_ = right.printerId_;
        jobId_ = right.jobId_;
        jobState_ = right.jobState_;
        copyNumber_ = right.copyNumber_;
        pageRange_ = right.pageRange_;
        isSequential_ = right.isSequential_;
        pageSize_ = right.pageSize_;
        isLandscape_ = right.isLandscape_;
        colorMode_ = right.colorMode_;
        duplexMode_ = right.duplexMode_;
        margin_ = right.margin_;
        preview_ = right.preview_;
    }
    return *this;
}

PrintJob::~PrintJob() {}

void PrintJob::SetFiles(const std::vector<std::string> &files)
{
    files_.clear();
    files_.assign(files.begin(), files.end());
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
    margin_ = margin;
}

void PrintJob::SetPreview(const PreviewAttribute &preview)
{
    preview_ = preview;
}

void PrintJob::GetFiles(std::vector<std::string> &files) const
{
    files.clear();
    files.assign(files_.begin(), files_.end());
}

uint32_t PrintJob::GetJobId() const
{
    return jobId_;
}

uint32_t PrintJob::GetPrinterId() const
{
    return printerId_;
}

uint32_t PrintJob::GetJobState() const
{
    return jobState_;
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

void PrintJob::GetMargin(PrintMargin &margin) const
{
    margin = margin_;
}

void PrintJob::GetPreview(PreviewAttribute &previewAttr) const
{
    previewAttr = preview_;
}

void PrintJob::ConvertToParcel(MessageParcel &reply) const
{
    std::vector<std::string> files;
    GetFiles(files);
    reply.WriteUint32((uint32_t)files.size());
    for (uint32_t i = 0; i < (uint32_t)files.size(); i++) {
        reply.WriteString(files[i]);
    }
    reply.WriteUint32(GetJobId());
    reply.WriteUint32(GetPrinterId());
    reply.WriteUint32(GetJobState());
    reply.WriteUint32(GetCopyNumber());

    PrintRange range;
    GetPageRange(range);
    reply.WriteUint32(range.GetStartPage());
    reply.WriteUint32(range.GetEndPage());

    std::vector<uint32_t> pages;
    range.GetPages(pages);
    reply.WriteUint32((uint32_t)pages.size());
    for (uint32_t i = 0; i < (uint32_t)pages.size(); i++) {
        reply.WriteUint32(pages[i]);
    }

    reply.WriteUint32(GetIsSequential());

    PrintPageSize pageSize;
    GetPageSize(pageSize);
    reply.WriteString(pageSize.GetId());
    reply.WriteString(pageSize.GetName());
    reply.WriteUint32(pageSize.GetWidth());
    reply.WriteUint32(pageSize.GetHeight());

    reply.WriteUint32(GetIsLandscape());
    reply.WriteUint32(GetColorMode());
    reply.WriteUint32(GetDuplexMode());

    PrintMargin margin;
    GetMargin(margin);
    reply.WriteUint32(margin.GetTop());
    reply.WriteUint32(margin.GetBottom());
    reply.WriteUint32(margin.GetLeft());
    reply.WriteUint32(margin.GetRight());

    PreviewAttribute preview;
    GetPreview(preview);
    reply.WriteString(preview.GetResult());

    range.Reset();
    preview.GetPreviewRange(range);
    reply.WriteUint32(range.GetStartPage());
    reply.WriteUint32(range.GetEndPage());

    range.GetPages(pages);
    reply.WriteUint32((uint32_t)pages.size());
    for (uint32_t i = 0; i < (uint32_t)pages.size(); i++) {
        reply.WriteUint32(pages[i]);
    }
}

void PrintJob::SetBuild(MessageParcel &data)
{
    PrintPageSize pageSize;
    pageSize.SetId(data.ReadString());
    pageSize.SetName(data.ReadString());
    pageSize.SetWidth(data.ReadUint32());
    pageSize.SetHeight(data.ReadUint32());
    SetPageSize(pageSize);

    SetIsLandscape(data.ReadUint32());
    SetColorMode(data.ReadUint32());
    SetDuplexMode(data.ReadUint32());

    PrintMargin minMargin;
    minMargin.SetTop(data.ReadUint32());
    minMargin.SetBottom(data.ReadUint32());
    minMargin.SetLeft(data.ReadUint32());
    minMargin.SetRight(data.ReadUint32());
    SetMargin(minMargin);
}

void PrintJob::BuildFromParcel(MessageParcel &data)
{
    uint32_t fileLength = data.ReadUint32();
    std::vector<std::string> files;
    uint32_t index = 0;
    for (index = 0; index < fileLength; index++) {
        files.push_back(data.ReadString());
    }
    SetFiles(files);
    SetJobId(data.ReadUint32());
    SetPrintId(data.ReadUint32());
    SetJobState(data.ReadUint32());
    SetCopyNumber(data.ReadUint32());

    PrintRange range;
    range.SetStartPage(data.ReadUint32());
    range.SetEndPage(data.ReadUint32());
    uint32_t pageLength = data.ReadUint32();
    std::vector<uint32_t> rangePages;
    for (index = 0; index < pageLength; index++) {
        rangePages.push_back(data.ReadUint32());
    }
    range.SetPages(rangePages);
    SetPageRange(range);

    SetIsSequential(data.ReadUint32());

    SetBuild(data);
    PreviewAttribute previewAttr;

    previewAttr.SetResult(data.ReadString());
    range.Reset();
    range.SetStartPage(data.ReadUint32());
    range.SetEndPage(data.ReadUint32());
    uint32_t previewPageLength = data.ReadUint32();
    std::vector<uint32_t> previewRangePages;
    for (index = 0; index < previewPageLength; index++) {
        previewRangePages.push_back(data.ReadUint32());
    }
    range.SetPages(previewRangePages);
    previewAttr.SetPreviewRange(range);
    SetPreview(previewAttr);
    Dump();
}

void PrintJob::SetSubPageRange(napi_env env, napi_value &subPageRange)
{
    napi_create_object(env, &subPageRange);
    NapiPrintUtils::SetUint32Property(env, subPageRange, "startPage", pageRange_.GetStartPage());
    NapiPrintUtils::SetUint32Property(env, subPageRange, "endPage", pageRange_.GetEndPage());
    napi_value arrPreviewPages;
    status = napi_create_array(env, &arrPreviewPages);
    PrintRange previewPrintRange;
    std::vector<uint32_t> previewRangePages;
    preview_.GetPreviewRange(previewPrintRange);
    previewPrintRange.GetPages(previewRangePages);
    uint32_t arrPreviewPagesLength = previewRangePages.size();

    for (uint32_t i = 0; i < arrPreviewPagesLength; i++) {
        napi_value value;
        napi_create_uint32(env, previewRangePages[i], &value);
        status = napi_set_element(env, arrPreviewPages, i, value);
    }
    napi_set_named_property(env, subPageRange, "files", arrPreviewPages);
}

void PrintJob::SetPageSize(napi_env env, napi_value &pageSize)
{
    NapiPrintUtils::SetStringPropertyUtf8(env, pageSize, "id", pageSize_.GetId());
    NapiPrintUtils::SetStringPropertyUtf8(env, pageSize, "name", pageSize_.GetName().c_str());
    NapiPrintUtils::SetUint32Property(env, pageSize, "width", pageSize_.GetWidth());
    NapiPrintUtils::SetUint32Property(env, pageSize, "height", pageSize_.GetHeight());
}

void PrintJob::SetMargin(napi_env env, napi_value &margin)
{
    NapiPrintUtils::SetUint32Property(env, margin, "top", margin_.GetTop());
    NapiPrintUtils::SetUint32Property(env, margin, "bottom", margin_.GetBottom());
    NapiPrintUtils::SetUint32Property(env, margin, "left", margin_.GetLeft());
    NapiPrintUtils::SetUint32Property(env, margin, "right", margin_.GetRight());
}

void PrintJob::ConvertToJs(napi_env env, napi_value *result) const
{
    napi_create_object(env, result);
    napi_value arrFiles;
    napi_status status = napi_create_array(env, &arrFiles);
    uint32_t arrFilesLength = files_.size();

    for (uint32_t i = 0; i < arrFilesLength; i++) {
        napi_value value;
        status = napi_create_string_utf8(env, files_[i].c_str(), NAPI_AUTO_LENGTH, &value);
        status = napi_set_element(env, arrFiles, i, value);
    }
    napi_set_named_property(env, *result, "files", arrFiles);

    NapiPrintUtils::SetUint32Property(env, *result, "jobId", GetJobId());
    NapiPrintUtils::SetUint32Property(env, *result, "printerId", GetPrinterId());
    NapiPrintUtils::SetUint32Property(env, *result, "jobState", GetJobState());
    NapiPrintUtils::SetUint32Property(env, *result, "copyNumber", GetCopyNumber());
    napi_value pageRange;
    napi_create_object(env, &pageRange);
    NapiPrintUtils::SetUint32Property(env, pageRange, "startPage", pageRange_.GetStartPage());
    NapiPrintUtils::SetUint32Property(env, pageRange, "endPage", pageRange_.GetEndPage());
    napi_value arrPages;
    status = napi_create_array(env, &arrPages);
    std::vector<uint32_t> pages;
    pageRange_.GetPages(pages);
    uint32_t arrPagesLength = pages.size();
    for (uint32_t i = 0; i < arrPagesLength; i++) {
        napi_value value;
        napi_create_uint32(env, pages[i], &value);
        status = napi_set_element(env, arrPages, i, value);
    }
    napi_set_named_property(env, pageRange, "files", arrPages);

    NapiPrintUtils::SetUint32Property(env, *result, "isSequential", GetIsSequential());
    napi_value pageSize;
    napi_create_object(env, &pageSize);
    SetPageSize(env, pageSize);

    NapiPrintUtils::SetUint32Property(env, *result, "isLandscape", GetIsLandscape());
    NapiPrintUtils::SetUint32Property(env, *result, "colorMode", GetColorMode());
    NapiPrintUtils::SetUint32Property(env, *result, "duplexMode", GetDuplexMode());

    napi_value margin;
    napi_create_object(env, &margin);
    SetMargin(env, margin);

    napi_value preview;
    napi_create_object(env, &preview);
    NapiPrintUtils::SetStringPropertyUtf8(env, preview, "result", preview_.GetResult().c_str());
    
    napi_value subPageRange;
    napi_create_object(env, &subPageRange);
    SetSubPageRange(env, subPageRange);
    napi_set_named_property(env, preview, "pageRange", subPageRange);
    napi_set_named_property(env, *result, "pageRange", pageRange);
    napi_set_named_property(env, *result, "pageSize", pageSize);
    napi_set_named_property(env, *result, "margin", margin);
    napi_set_named_property(env, *result, "preview", preview);
}

void PrintJob::BuildFromJs(napi_env env, napi_value capValue) {}

void PrintJob::Dump()
{
    uint32_t fileLength = files_.size();
    for (uint32_t i = 0; i < fileLength; i++) {
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

    pageRange_.Dump();
    pageSize_.Dump();
    margin_.Dump();
    preview_.Dump();
}
} // namespace OHOS::Print
