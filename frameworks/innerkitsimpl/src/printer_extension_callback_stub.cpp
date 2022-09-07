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

#include "printer_extension_callback_stub.h"

#include "print_common.h"
#include "print_log.h"
#include "print_resolution.h"

namespace OHOS::Print {
PrintExtensionCallbackStub::PrintExtensionCallbackStub() : extCb_(nullptr), jobCb_(nullptr), cb_(nullptr)
{
    cmdMap_[PRINT_EXTCB] = &PrintExtensionCallbackStub::HandleExtCallback;
    cmdMap_[PRINT_EXTCB_PRINTER] = &PrintExtensionCallbackStub::HandlePrinterCallback;
    cmdMap_[PRINT_EXTCB_PRINTJOB] = &PrintExtensionCallbackStub::HandlePrintJobCallback;
    cmdMap_[PRINT_EXTCB_PRINTCAPABILITY] = &PrintExtensionCallbackStub::HandleCapabilityCallback;
}

int32_t PrintExtensionCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_IPC_ERROR;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }
    PRINT_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool PrintExtensionCallbackStub::OnCallback()
{
    if (extCb_ != nullptr) {
        return extCb_();
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(uint32_t printerId)
{
    if (cb_ != nullptr) {
        return cb_(printerId);
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(const PrintJob &job)
{
    if (jobCb_ != nullptr) {
        return jobCb_(job);
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(uint32_t printerId, MessageParcel &reply) // PrinterCapability& reply
{
    PrinterCapability capability;
    capability.ConvertToParcel(reply);
    
    return true;
}

void PrintExtensionCallbackStub::SetExtCallback(PrintExtCallback cb)
{
    extCb_ = cb;
}

void PrintExtensionCallbackStub::SetPrintJobCallback(PrintJobCallback cb)
{
    jobCb_ = cb;
}

void PrintExtensionCallbackStub::SetPrinterCallback(PrinterCallback cb)
{
    cb_ = cb;
}

void PrintExtensionCallbackStub::SetCapabilityCallback(PrinterCapabilityCallback cb)
{
    capability_ = cb;
}

bool PrintExtensionCallbackStub::HandleExtCallback(MessageParcel &data, MessageParcel &reply)
{
    return OnCallback();
}

bool PrintExtensionCallbackStub::HandlePrinterCallback(MessageParcel &data, MessageParcel &reply)
{
    uint32_t printerId = data.ReadUint32();
    return OnCallback(printerId);
}

void PrintExtensionCallbackStub::dataReadJob(MessageParcel &data, PrintJob &job)
{
    uint32_t fileLength = data.ReadUint32();
    std::vector<std::string> files;
    for (uint32_t i = 0; i < fileLength; i++) {
        files.push_back(data.ReadString());
    }
    job.SetFiles(files);
    job.SetJobId(data.ReadUint32());
    job.SetPrintId(data.ReadUint32());
    job.SetJobState(data.ReadUint32());
    job.SetCopyNumber(data.ReadUint32());
    PrintRange range;
    std::vector<uint32_t> pages;
    range.SetStartPage(data.ReadUint32());
    range.SetEndPage(data.ReadUint32());
    uint32_t pageLength = data.ReadUint32();
    for (uint32_t i = 0; i < pageLength; i++) {
        pages.push_back(data.ReadUint32());
    }
    range.SetPages(pages);
    job.SetPageRange(range);

    job.SetIsSequential(data.ReadUint32());
    PrintPageSize pageSize;
    pageSize.SetId(data.ReadString());
    pageSize.SetName(data.ReadString());
    pageSize.SetWidth(data.ReadUint32());
    pageSize.SetHeight(data.ReadUint32());
    job.SetPageSize(pageSize);

    job.SetIsLandscape(data.ReadUint32());
    job.SetColorMode(data.ReadUint32());
    job.SetDuplexMode(data.ReadUint32());

    PrintMargin margin;
    margin.SetTop(data.ReadUint32());
    margin.SetBottom(data.ReadUint32());
    margin.SetLeft(data.ReadUint32());
    margin.SetRight(data.ReadUint32());
    job.SetMargin(margin);

    PreviewAttribute previewAttr;
    PrintRange previewRange;
    previewAttr.SetResult(data.ReadString());
    previewRange.SetStartPage(data.ReadUint32());
    previewRange.SetEndPage(data.ReadUint32());
    uint32_t previewPageLength = data.ReadUint32();
    std::vector<uint32_t> arrayPages;
    for (uint32_t i = 0; i < previewPageLength; i++) {
        arrayPages.push_back(data.ReadUint32());
    }
    previewRange.SetPages(arrayPages);
    previewAttr.SetPreviewRange(previewRange);
    job.SetPreview(previewAttr);
}

bool PrintExtensionCallbackStub::HandlePrintJobCallback(MessageParcel &data, MessageParcel &reply)
{
    PrintJob job;
    job.BuildFromParcel(data);
    // dataReadJob(data, job);
    return OnCallback(job);
}

bool PrintExtensionCallbackStub::HandleCapabilityCallback(MessageParcel &data, MessageParcel &reply)
{
    uint32_t printerId = data.ReadUint32();
    // PrinterCapability cap;
    // OnCallabck(printerId, cap);
    // cap.BuildParcel(reply);
    return OnCallback(printerId, reply);
}
} // namespace OHOS::Print
