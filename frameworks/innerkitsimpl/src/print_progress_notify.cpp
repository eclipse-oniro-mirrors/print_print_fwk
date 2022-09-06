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

#include "print_progress_notify.h"

#include <uv.h>

#include "napi_print_utils.h"
#include "print_job.h"
#include "print_log.h"
#include "print_page_size.h"
#include "print_resolution.h"
#include "printer_capability.h"
#include "printer_info.h"

namespace OHOS::Print {
PrintProgressNotify::PrintProgressNotify(napi_env env, const std::string &type, napi_ref ref)
    : PrintBaseNotify(env, type, ref)
{}

PrintProgressNotify::~PrintProgressNotify()
{
    PRINT_HILOGD("");
}

void PrintProgressNotify::DataReadInfo(PrinterInfo &info, MessageParcel &data)
{
    /*
        info.SetPrinterId(data.ReadUint32());
        info.SetPrinterName(data.ReadString());
        info.SetPrinterIcon(data.ReadUint32());
        info.SetPrinterState(data.ReadUint32());
        info.SetDescription(data.ReadString());
        uint32_t pageSizeLength = data.ReadUint32();
        uint32_t resolutionLength = data.ReadUint32();
        PRINT_HILOGI("OnStartDiscoverPrinter pageSizeLength = %{public}d", pageSizeLength);
        PRINT_HILOGI("OnStartDiscoverPrinter resolutionLength = %{public}d", resolutionLength);
        info.GetCapability().GetMinMargin().SetTop(data.ReadUint32());
        info.GetCapability().GetMinMargin().SetBottom(data.ReadUint32());
        info.GetCapability().GetMinMargin().SetLeft(data.ReadUint32());
        info.GetCapability().GetMinMargin().SetRight(data.ReadUint32());

        for(uint32_t i = 0; i < pageSizeLength; i++)
        {
            PrintPageSize PrintPageSize;
            PrintPageSize.SetId(data.ReadUint32());
            PrintPageSize.SetName(data.ReadString());
            PrintPageSize.SetWidth(data.ReadUint32());
            PrintPageSize.SetHeight(data.ReadUint32());
            info.GetCapability().GetPageSize().push_back(PrintPageSize);
            PrintPageSize.Dump();
        }

        for(uint32_t i = 0; i < resolutionLength; i++)
        {
            PrintResolution PrintResolution;
            PrintResolution.SetId(data.ReadUint32());
            PrintResolution.SetHorizontalDpi(data.ReadUint32());
            PrintResolution.SetVerticalDpi(data.ReadUint32());
            info.GetCapability().GetResolution().push_back(PrintResolution);
            PrintResolution.Dump();
        }

        info.GetCapability().SetColorMode(data.ReadUint32());
        info.GetCapability().SetDuplexMode(data.ReadUint32());
    */
}

void PrintProgressNotify::DataReadJob(PrintJob &job, MessageParcel &data)
{
    /*
        uint32_t fileLength = data.ReadUint32();
        for(uint32_t i = 0; i < fileLength; i++)
        {
            job.GetFiles().push_back(data.ReadString());

        }
        job.SetJobId(data.ReadUint32());
        job.SetPrintId(data.ReadUint32());
        job.SetJobState(data.ReadUint32());
        job.SetCopyNumber(data.ReadUint32());

        job.GetPageRange().SetStartPage(data.ReadUint32());
        job.GetPageRange().SetEndPage(data.ReadUint32());
        uint32_t pageLength = data.ReadUint32();
        for(uint32_t i = 0; i < pageLength; i++)
        {
            job.GetPageRange().SetPages(data.ReadUint32());
        }

        job.SetIsSequential(data.ReadUint32());

        job.GetPageSize().SetId(data.ReadUint32());
        job.GetPageSize().SetName(data.ReadString());
        job.GetPageSize().SetWidth(data.ReadUint32());
        job.GetPageSize().SetHeight(data.ReadUint32());

        job.SetIsLandscape(data.ReadUint32());
        job.SetColorMode(data.ReadUint32());
        job.SetDuplexMode(data.ReadUint32());

        job.GetMargin().SetTop(data.ReadUint32());
        job.GetMargin().SetBottom(data.ReadUint32());
        job.GetMargin().SetLeft(data.ReadUint32());
        job.GetMargin().SetRight(data.ReadUint32());

        job.GetPreview().SetResult(data.ReadString());
        job.GetPreview().GetPreviewRange().SetStartPage(data.ReadUint32());
        job.GetPreview().GetPreviewRange().SetEndPage(data.ReadUint32());
        uint32_t previewPageLength = data.ReadUint32();

        for(uint32_t i = 0; i < previewPageLength; i++)
        {
             job.GetPreview().GetPreviewRange().SetPages(data.ReadUint32());
        }
    */
}

void PrintProgressNotify::WriteInfoJsObject(napi_env env, PrinterInfo info, napi_value *result)
{
    /*
        napi_value resultPrintMargin;
        napi_create_object(env, result);

        PrintNapiUtils::SetUint32Property(env, *result, "printerId", info.GetPrintId());
        PrintNapiUtils::SetStringPropertyUtf8(env, *result, "printerName", info.GetPrinterName().c_str());
        PrintNapiUtils::SetUint32Property(env, *result, "printerIcon", info.GetPrinterIcon());
        PrintNapiUtils::SetUint32Property(env, *result, "printerState", info.GetPrinterState());
        PrintNapiUtils::SetStringPropertyUtf8(env, *result, "description", info.GetDescription().c_str());

        napi_value capability;
        napi_create_object(env, &capability);
        napi_create_object(env, &resultPrintMargin);
        napi_value arrPageSize,arrResolution;
        napi_status status = napi_create_array(env, &arrPageSize);
        status = napi_create_array(env, &arrResolution);

        PrintNapiUtils::SetUint32Property(env, capability, "colorMode", info.GetCapability().GetColorMode());
        PrintNapiUtils::SetUint32Property(env, capability, "duplexMode", info.GetCapability().GetDuplexMode());

        PrintNapiUtils::SetUint32Property(env, resultPrintMargin, "top", info.GetCapability().GetMinMargin().GetTop());
        PrintNapiUtils::SetUint32Property(env, resultPrintMargin, "bottom",
       info.GetCapability().GetMinMargin().GetBottom()); PrintNapiUtils::SetUint32Property(env, resultPrintMargin,
       "left", info.GetCapability().GetMinMargin().GetLeft()); PrintNapiUtils::SetUint32Property(env, resultPrintMargin,
       "right", info.GetCapability().GetMinMargin().GetRight()); uint32_t printerCapabilityLength =
       info.GetCapability().GetPageSize().size();

        for(uint32_t i = 0; i < printerCapabilityLength; i++)
        {
            napi_value resultPrinterPageSize;
            napi_create_object(env, &resultPrinterPageSize);
            PrintNapiUtils::SetUint32Property(env, resultPrinterPageSize, "id",
       info.GetCapability().GetPageSize()[i].GetId()); PrintNapiUtils::SetStringPropertyUtf8(env, resultPrinterPageSize,
       "name", info.GetCapability().GetPageSize()[i].GetName().c_str()); PrintNapiUtils::SetUint32Property(env,
       resultPrinterPageSize, "width", info.GetCapability().GetPageSize()[i].GetWidth());
            PrintNapiUtils::SetUint32Property(env, resultPrinterPageSize, "height",
       info.GetCapability().GetPageSize()[i].GetHeight()); status = napi_set_element(env, arrPageSize, i,
       resultPrinterPageSize);
        }

        uint32_t printerCapabilityresolutionLength = info.GetCapability().GetResolution().size();

        for(uint32_t i = 0; i < printerCapabilityresolutionLength; i++)
        {
            napi_value resultPrinterResolution;
            napi_create_object(env, &resultPrinterResolution);
            PrintNapiUtils::SetUint32Property(env, resultPrinterResolution, "id",
       info.GetCapability().GetResolution()[i].GetId()); PrintNapiUtils::SetUint32Property(env, resultPrinterResolution,
       "horizontalDpi", info.GetCapability().GetResolution()[i].GetHorizontalDpi());
            PrintNapiUtils::SetUint32Property(env, resultPrinterResolution, "verticalDpi",
       info.GetCapability().GetResolution()[i].GetVerticalDpi()); status = napi_set_element(env, arrResolution, i,
       resultPrinterResolution);
        }

        status = napi_set_named_property(env, capability, "minMargin", resultPrintMargin);
        PRINT_HILOGD("output ---- status[%{public}d]", status);
        napi_set_named_property(env, capability, "pageSize", arrPageSize);
        napi_set_named_property(env, capability, "resolution", arrResolution);
        napi_set_named_property(env, *result, "capability", capability);
    */
}

void PrintProgressNotify::WriteJobJsObject(napi_env env, PrintJob job, napi_value *result)
{
    /*
        napi_create_object(env, result);
        napi_value arrFiles;
        napi_status status = napi_create_array(env, &arrFiles);
        uint32_t arrFilesLength = job.GetFiles().size();

        for(uint32_t i = 0; i < arrFilesLength; i++)
        {
            napi_value value;
            status = napi_create_string_utf8(env, job.GetFiles()[i].c_str(), NAPI_AUTO_LENGTH, &value);
            status = napi_set_element(env, arrFiles, i, value);
        }
        napi_set_named_property(env, *result, "files", arrFiles);

        PrintNapiUtils::SetUint32Property(env, *result, "jobId", job.GetJobId());
        PrintNapiUtils::SetUint32Property(env, *result, "printerId", job.GetPrinterId());
        PrintNapiUtils::SetUint32Property(env, *result, "jobState", job.GetJobState());
        PrintNapiUtils::SetUint32Property(env, *result, "copyNumber", job.GetCopyNumber());
        napi_value pageRange;
        napi_create_object(env, &pageRange);
        PrintNapiUtils::SetUint32Property(env, pageRange, "startPage", job.GetPageRange().GetStartPage());
        PrintNapiUtils::SetUint32Property(env, pageRange, "endPage", job.GetPageRange().GetEndPage());
        napi_value arrPages;
        status = napi_create_array(env, &arrPages);

        uint32_t arrPagesLength = job.GetPageRange().GetPages().size();

        for(uint32_t i = 0; i < arrPagesLength; i++)
        {
            napi_value value;
            napi_create_uint32(env, job.GetPageRange().GetPages()[i], &value);
            status = napi_set_element(env, arrPages, i, value);
        }
        napi_set_named_property(env, pageRange, "files", arrPages);

        PrintNapiUtils::SetUint32Property(env, *result, "isSequential", job.GetIsSequential());
        napi_value pageSize;
        napi_create_object(env, &pageSize);
        PrintNapiUtils::SetUint32Property(env, pageSize, "id", job.GetPageSize().GetId());
        PrintNapiUtils::SetStringPropertyUtf8(env, pageSize, "name", job.GetPageSize().GetName().c_str());
        PrintNapiUtils::SetUint32Property(env, pageSize, "width", job.GetPageSize().GetWidth());
        PrintNapiUtils::SetUint32Property(env, pageSize, "height", job.GetPageSize().GetHeight());

        PrintNapiUtils::SetUint32Property(env, *result, "isLandscape", job.GetIsLandscape());
        PrintNapiUtils::SetUint32Property(env, *result, "colorMode", job.GetColorMode());
        PrintNapiUtils::SetUint32Property(env, *result, "duplexMode", job.GetDuplexMode());

        napi_value margin;
        napi_create_object(env, &margin);
        PrintNapiUtils::SetUint32Property(env, margin, "top", job.GetMargin().GetTop());
        PrintNapiUtils::SetUint32Property(env, margin, "bottom", job.GetMargin().GetBottom());
        PrintNapiUtils::SetUint32Property(env, margin, "left", job.GetMargin().GetLeft());
        PrintNapiUtils::SetUint32Property(env, margin, "right", job.GetMargin().GetRight());

        napi_value preview;
        napi_create_object(env, &preview);
        PrintNapiUtils::SetStringPropertyUtf8(env, preview, "result", job.GetPreview().GetResult().c_str());
        napi_value subPageRange;
        napi_create_object(env, &subPageRange);
        PrintNapiUtils::SetUint32Property(env, subPageRange, "startPage", job.GetPageRange().GetStartPage());
        PrintNapiUtils::SetUint32Property(env, subPageRange, "endPage", job.GetPageRange().GetEndPage());
        napi_value arrPreviewPages;
        status = napi_create_array(env, &arrPreviewPages);
        uint32_t arrPreviewPagesLength = job.GetPageRange().GetPages().size();

        for(uint32_t i = 0; i < arrPreviewPagesLength; i++)
        {
            napi_value value;
            napi_create_uint32(env, job.GetPageRange().GetPages()[i], &value);
            status = napi_set_element(env, arrPreviewPages, i, value);
        }
        napi_set_named_property(env, subPageRange, "files", arrPreviewPages);
        napi_set_named_property(env, preview, "pageRange", subPageRange);

        napi_set_named_property(env, *result, "pageRange", pageRange);
        napi_set_named_property(env, *result, "pageSize", pageSize);
        napi_set_named_property(env, *result, "margin", margin);
        napi_set_named_property(env, *result, "preview", preview);
    */
}

void PrintProgressNotify::OnCallBack(MessageParcel &data)
{
    PRINT_HILOGD("Progress callback in");
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        PRINT_HILOGE("Failed to get uv event loop");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        PRINT_HILOGE("Failed to create uv work");
        return;
    }

    NotifyData *notifyData = GetNotifyData();
    notifyData->env = env_;
    notifyData->ref = ref_;
    notifyData->type = type_;
    notifyData->objectType = data.ReadString();
    notifyData->firstArgv = data.ReadUint32();
    if ("PrinterInfo" == notifyData->objectType) {
        PrinterInfo info;
        DataReadInfo(info, data);
        notifyData->secondArgv = info;
    } else if ("PrintJob" == notifyData->objectType) {
        PrintJob job;
        DataReadJob(job, data);
        notifyData->thirdArgv = job;
    }

    work->data = notifyData;

    uv_queue_work(
        loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int statusInt) {
            NotifyData *notifyData = static_cast<NotifyData *>(work->data);
            if (notifyData != nullptr) {
                napi_value undefined = 0;
                napi_get_undefined(notifyData->env, &undefined);
                napi_value callbackFunc = nullptr;
                napi_get_reference_value(notifyData->env, notifyData->ref, &callbackFunc);
                napi_value result = nullptr;
                napi_value callbackVal[PrintNapiUtils::TWO_ARG] = { 0 };
                napi_create_uint32(notifyData->env, notifyData->firstArgv, &callbackVal[PrintNapiUtils::FIRST_ARGV]);
                if ("PrinterInfo" == notifyData->objectType) {
                    WriteInfoJsObject(
                        notifyData->env, notifyData->secondArgv, &callbackVal[PrintNapiUtils::SECOND_ARGV]);
                } else if ("PrintJob" == notifyData->objectType) {
                    WriteJobJsObject(notifyData->env, notifyData->thirdArgv, &callbackVal[PrintNapiUtils::SECOND_ARGV]);
                }
                napi_call_function(
                    notifyData->env, nullptr, callbackFunc, PrintNapiUtils::TWO_ARG, callbackVal, &result);
                if (work != nullptr) {
                    delete work;
                    work = nullptr;
                }
                delete notifyData;
                notifyData = nullptr;
            }
        });
}

} // namespace OHOS::Print