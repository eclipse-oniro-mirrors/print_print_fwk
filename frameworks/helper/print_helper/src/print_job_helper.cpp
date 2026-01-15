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
#include "print_job_helper.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_margin_helper.h"
#include "print_preview_attribute_helper.h"
#include "print_page_size_helper.h"
#include "print_range_helper.h"

namespace OHOS::Print {
static constexpr const char *PARAM_JOB_FDLIST = "fdList";
static constexpr const char *PARAM_JOB_JOBID = "jobId";
static constexpr const char *PARAM_JOB_PRINTERID = "printerId";
static constexpr const char *PARAM_JOB_JOBSTATE = "jobState";
static constexpr const char *PARAM_JOB_SUBSTATE = "jobSubstate";
static constexpr const char *PARAM_JOB_COPYNUMBER = "copyNumber";
static constexpr const char *PARAM_JOB_PAGERANGE = "pageRange";
static constexpr const char *PARAM_JOB_ISSEQUENTIAL = "isSequential";
static constexpr const char *PARAM_JOB_PAGESIZE = "pageSize";
static constexpr const char *PARAM_JOB_ISLANDSCAPE = "isLandscape";
static constexpr const char *PARAM_JOB_COLORMODE = "colorMode";
static constexpr const char *PARAM_JOB_DUPLEXMODE = "duplexMode";
static constexpr const char *PARAM_JOB_MARGIN = "margin";
static constexpr const char *PARAM_JOB_PREVIEW = "preview";
static constexpr const char *PARAM_JOB_OPTION = "options";
static constexpr const char *PARAM_JOB_NAME = "jobName";
static constexpr const char *PARAM_JOB_MEDIATYPE = "mediaType";
static constexpr const char *PARAM_JOB_ISBORDERLESS = "isBorderless";
static constexpr const char *PARAM_JOB_DOCUMENTFORMAT = "documentFormat";
static constexpr const char *PARAM_JOB_PRINTQUALITY = "printQuality";
static constexpr const char *PARAM_JOB_BINARYDATA = "binaryData";
static constexpr const char *PARAM_JOB_DOCFLAVOR = "docFlavor";
static constexpr const char *PARAM_JOB_ISAUTORATATE = "isAutoRotate";
static constexpr const char *PARAM_JOB_ISREVERSE = "isReverse";
static constexpr const char *PARAM_JOB_ISCOLLATE = "isCollate";

napi_value PrintJobHelper::MakeJsSimpleObject(napi_env env, const PrintJob &job)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_JOBID, job.GetJobId());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_JOBSTATE, job.GetJobState());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_SUBSTATE, job.GetSubState());
    return jsObj;
}

napi_value PrintJobHelper::MakeJsObject(napi_env env, const PrintJob &job)
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    if (!CreateFdList(env, jsObj, job)) {
        PRINT_HILOGE("Failed to create files property of print job");
        return nullptr;
    }
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_JOBID, job.GetJobId());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_PRINTERID, job.GetPrinterId());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_JOBSTATE, job.GetJobState());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_SUBSTATE, job.GetSubState());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_COPYNUMBER, job.GetCopyNumber());

    if (!CreatePageRange(env, jsObj, job)) {
        PRINT_HILOGE("Failed to create page range property of print job");
        return nullptr;
    }

    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_ISSEQUENTIAL, job.GetIsSequential());

    if (!CreatePageSize(env, jsObj, job)) {
        PRINT_HILOGE("Failed to create page size property of print job");
        return nullptr;
    }

    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_ISLANDSCAPE, job.GetIsLandscape());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_COLORMODE, job.GetColorMode());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_DUPLEXMODE, job.GetDuplexMode());

    if (job.HasMargin() && !CreateMargin(env, jsObj, job)) {
        PRINT_HILOGE("Failed to create margin property of print job");
        return nullptr;
    }

    if (job.HasPreview() && !CreatePreview(env, jsObj, job)) {
        PRINT_HILOGE("Failed to create preview property of print job");
        return nullptr;
    }

    if (job.HasOption()) {
        NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_OPTION, job.GetOption());
    }
    return jsObj;
}

std::shared_ptr<PrintJob> PrintJobHelper::BuildFromJs(napi_env env, napi_value jsValue, bool cvtToPwgSize)
{
    auto nativeObj = std::make_shared<PrintJob>();

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print job");
        return nullptr;
    }

    napi_value jsFdList = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_FDLIST);
    bool isFileArray = false;
    napi_is_array(env, jsFdList, &isFileArray);
    if (!isFileArray) {
        PRINT_HILOGE("Invalid file list of print job");
        return nullptr;
    }
    std::vector<uint32_t> printFdList;
    uint32_t arrayReLength = 0;
    napi_get_array_length(env, jsFdList, &arrayReLength);
    for (uint32_t index = 0; index < arrayReLength; index++) {
        napi_value filesValue;
        napi_get_element(env, jsFdList, index, &filesValue);
        uint32_t fd = NapiPrintUtils::GetUint32FromValue(env, filesValue);
        PRINT_HILOGD("printJob_value fd %{public}d", fd);
        printFdList.emplace_back(fd);
    }
    nativeObj->SetFdList(printFdList);

    std::string jobId = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_JOBID);
    std::string printerId = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_PRINTERID);
    uint32_t jobState = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_JOBSTATE);
    uint32_t subState = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_SUBSTATE);
    uint32_t copyNumber = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_COPYNUMBER);
    bool isSequential = NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISSEQUENTIAL);
    bool isLandscape = NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISLANDSCAPE);
    uint32_t colorMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_COLORMODE);
    uint32_t duplexMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_DUPLEXMODE);
    nativeObj->SetJobId(jobId);
    nativeObj->SetPrinterId(printerId);
    nativeObj->SetJobState(jobState);
    nativeObj->SetSubState(subState);
    nativeObj->SetCopyNumber(copyNumber);
    nativeObj->SetIsSequential(isSequential);
    nativeObj->SetIsLandscape(isLandscape);
    nativeObj->SetColorMode(colorMode);
    nativeObj->SetDuplexMode(duplexMode);

    BuildJsWorkerIsLegal(env, jsValue, jobId, jobState, subState, nativeObj, cvtToPwgSize);
    nativeObj->Dump();
    return nativeObj;
}

std::shared_ptr<PrintJob> PrintJobHelper::BuildPrintJobFromJs(napi_env env, napi_value jsValue)
{
    if (!ValidatePrintJobProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print job");
        return nullptr;
    }
    PrintJobParams params;
    if (!FillPrintJobParamsFromJs(env, jsValue, params)) {
        return nullptr;
    }
    auto nativeObj = PrintUtils::ConvertParamsToPrintJob(params);
    if (nativeObj == nullptr) {
        return nullptr;
    }
    nativeObj->Dump();
    return nativeObj;
}

std::shared_ptr<PrintJob> PrintJobHelper::BuildJsWorkerIsLegal(napi_env env, napi_value jsValue, std::string jobId,
    uint32_t jobState, uint32_t subState, std::shared_ptr<PrintJob> &nativeObj, bool cvtToPwgSize)
{
    if (jobState >= PRINT_JOB_UNKNOWN || subState > PRINT_JOB_BLOCKED_UNKNOWN) {
        PRINT_HILOGE("Invalid job state[%{public}d] or sub state [%{public}d]", jobState, subState);
        return nullptr;
    }

    napi_value jsPageRange = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PAGERANGE);
    auto pageRangePtr = PrintRangeHelper::BuildFromJs(env, jsPageRange);
    if (pageRangePtr == nullptr) {
        PRINT_HILOGE("Failed to build print job object from js");
        return nullptr;
    }
    nativeObj->SetPageRange(*pageRangePtr);

    napi_value jsPageSize = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PAGESIZE);
    auto pageSizePtr = PrintPageSizeHelper::BuildFromJsEx(env, jsPageSize, cvtToPwgSize);
    if (pageSizePtr == nullptr) {
        PRINT_HILOGE("Failed to build print job object from js");
        return nullptr;
    }
    nativeObj->SetPageSize(*pageSizePtr);

    napi_value jsMargin = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_MARGIN);
    if (jsMargin != nullptr) {
        auto marginPtr = PrintMarginHelper::BuildFromJs(env, jsMargin);
        if (marginPtr == nullptr) {
            PRINT_HILOGE("Failed to build print job object from js");
            return nullptr;
        }
        nativeObj->SetMargin(*marginPtr);
    }

    napi_value jsPreview = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PREVIEW);
    if (jsPreview != nullptr) {
        auto previewPtr = PrintPreviewAttributeHelper::BuildFromJs(env, jsPreview);
        if (previewPtr == nullptr) {
            PRINT_HILOGE("Failed to build print job object from js");
            return nullptr;
        }
        nativeObj->SetPreview(*previewPtr);
    }

    napi_value jsOption = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_OPTION);
    if (jsOption != nullptr) {
        nativeObj->SetOption(NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_OPTION));
    }
    return nativeObj;
}

bool PrintJobHelper::CreateFdList(napi_env env, napi_value &jsPrintJob, const PrintJob &job)
{
    napi_value arrFiles = nullptr;
    PRINT_CALL_BASE(env, napi_create_array(env, &arrFiles), false);
    std::vector<uint32_t> fdList;
    job.GetFdList(fdList);
    uint32_t arrFilesLength = fdList.size();

    for (uint32_t i = 0; i < arrFilesLength; i++) {
        napi_value value;
        PRINT_CALL_BASE(env, napi_create_uint32(env, fdList[i], &value), false);
        PRINT_CALL_BASE(env, napi_set_element(env, arrFiles, i, value), false);
    }
    PRINT_CALL_BASE(env, napi_set_named_property(env, jsPrintJob, PARAM_JOB_FDLIST, arrFiles), false);
    return true;
}

bool PrintJobHelper::CreatePageRange(napi_env env, napi_value &jsPrintJob, const PrintJob &job)
{
    PrintRange range;
    job.GetPageRange(range);
    napi_value jsPageRange = PrintRangeHelper::MakeJsObject(env, range);
    PRINT_CALL_BASE(env, napi_set_named_property(env, jsPrintJob, PARAM_JOB_PAGERANGE, jsPageRange), false);
    return true;
}

bool PrintJobHelper::CreatePageSize(napi_env env, napi_value &jsPrintJob, const PrintJob &job)
{
    PrintPageSize pageSize;
    job.GetPageSize(pageSize);
    napi_value jsPageSize = PrintPageSizeHelper::MakeJsObject(env, pageSize);
    PRINT_CALL_BASE(env, napi_set_named_property(env, jsPrintJob, PARAM_JOB_PAGESIZE, jsPageSize), false);
    return true;
}

bool PrintJobHelper::CreateMargin(napi_env env, napi_value &jsPrintJob, const PrintJob &job)
{
    PrintMargin margin;
    job.GetMargin(margin);
    napi_value jsMargin = PrintMarginHelper::MakeJsObject(env, margin);
    PRINT_CALL_BASE(env, napi_set_named_property(env, jsPrintJob, PARAM_JOB_MARGIN, jsMargin), false);
    return true;
}

bool PrintJobHelper::CreatePreview(napi_env env, napi_value &jsPrintJob, const PrintJob &job)
{
    PrintPreviewAttribute preview;
    job.GetPreview(preview);
    napi_value jsPreview = PrintPreviewAttributeHelper::MakeJsObject(env, preview);
    PRINT_CALL_BASE(env, napi_set_named_property(env, jsPrintJob, PARAM_JOB_PREVIEW, jsPreview), false);
    return true;
}

bool PrintJobHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_JOB_FDLIST, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_JOBID, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_PRINTERID, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_JOBSTATE, PRINT_PARAM_OPT},
        {PARAM_JOB_SUBSTATE, PRINT_PARAM_OPT},
        {PARAM_JOB_COPYNUMBER, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_PAGERANGE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_ISSEQUENTIAL, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_PAGESIZE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_ISLANDSCAPE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_COLORMODE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_DUPLEXMODE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_MARGIN, PRINT_PARAM_OPT},
        {PARAM_JOB_PREVIEW, PRINT_PARAM_OPT},
        {PARAM_JOB_OPTION, PRINT_PARAM_OPT},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    return NapiPrintUtils::VerifyProperty(names, propertyList);
}

bool PrintJobHelper::ValidatePrintJobProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_JOB_PRINTERID, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_DOCUMENTFORMAT, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_NAME, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_DOCFLAVOR, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_COPYNUMBER, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_ISLANDSCAPE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_COLORMODE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_DUPLEXMODE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_PAGESIZE, PRINT_PARAM_NOT_SET},
        {PARAM_JOB_JOBID, PRINT_PARAM_OPT},
        {PARAM_JOB_FDLIST, PRINT_PARAM_OPT},
        {PARAM_JOB_BINARYDATA, PRINT_PARAM_OPT},
        {PARAM_JOB_PRINTQUALITY, PRINT_PARAM_OPT},
        {PARAM_JOB_MEDIATYPE, PRINT_PARAM_OPT},
        {PARAM_JOB_ISBORDERLESS, PRINT_PARAM_OPT},
        {PARAM_JOB_ISAUTORATATE, PRINT_PARAM_OPT},
        {PARAM_JOB_ISREVERSE, PRINT_PARAM_OPT},
        {PARAM_JOB_ISCOLLATE, PRINT_PARAM_OPT},
        {PARAM_JOB_PAGERANGE, PRINT_PARAM_OPT},
        {PARAM_JOB_MARGIN, PRINT_PARAM_OPT},
        {PARAM_JOB_PREVIEW, PRINT_PARAM_OPT},
        {PARAM_JOB_ISSEQUENTIAL, PRINT_PARAM_OPT},
        {PARAM_JOB_OPTION, PRINT_PARAM_OPT},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    return NapiPrintUtils::VerifyProperty(names, propertyList);
}

bool PrintJobHelper::FillPrintJobParamsFromJs(napi_env env, napi_value jsValue, PrintJobParams &params)
{
    params.printerId = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_PRINTERID);
    params.jobName = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_NAME);
    params.documentFormat = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_DOCUMENTFORMAT);
    params.docFlavor = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_DOCFLAVOR);
    params.copyNumber = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_COPYNUMBER);
    params.isLandscape = NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISLANDSCAPE);
    params.colorMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_COLORMODE);
    params.duplexMode = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_DUPLEXMODE);
    napi_value jsPageSize = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PAGESIZE);
    auto pageSizePtr = PrintPageSizeHelper::BuildFromJs(env, jsPageSize);
    if (pageSizePtr == nullptr) {
        PRINT_HILOGE("Failed to build print job object from js");
        return false;
    }
    params.pageSize = *pageSizePtr;

    if (!FillOptionalParamsFromJs(env, jsValue, params)) {
        return false;
    }
    return true;
}

bool PrintJobHelper::FillOptionalParamsFromJs(napi_env env, napi_value jsValue, PrintJobParams &params)
{
    params.jobId = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_JOBID);
    if (!GetFileDescriptorList(env, jsValue, params.printFdList)) {
        return false;
    }
    if (!ExtractBinaryData(env, jsValue, params.binaryData, params.dataLength)) {
        return false;
    }
    napi_value jsPrintQuality = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PRINTQUALITY);
    if (jsPrintQuality != nullptr) {
        params.printQuality = static_cast<int32_t>(
            NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_PRINTQUALITY));
    }
    params.mediaType = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_MEDIATYPE);
    napi_value jsIsBorderless = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_ISBORDERLESS);
    if (jsIsBorderless != nullptr) {
        params.isBorderless = static_cast<int32_t>(
            NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISBORDERLESS));
    }
    napi_value jsIsAutoRotate = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_ISAUTORATATE);
    if (jsIsAutoRotate != nullptr) {
        params.isAutoRotate = static_cast<int32_t>(
            NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISAUTORATATE));
    }
    napi_value jsIsReverse = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_ISREVERSE);
    if (jsIsReverse != nullptr) {
        params.isReverse = static_cast<int32_t>(
            NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISREVERSE));
    }
    napi_value jsIsCollate = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_ISCOLLATE);
    if (jsIsCollate != nullptr) {
        params.isCollate = static_cast<int32_t>(
            NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISCOLLATE));
    }

    if (!GetPrintPageRange(env, jsValue, params) || !GetPrintMargin(env, jsValue, params) ||
        !GetPrintPreview(env, jsValue, params)) {
        return false;
    }
    napi_value jsIsSequential = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_ISSEQUENTIAL);
    if (jsIsSequential != nullptr) {
        params.isSequential = static_cast<int32_t>(
            NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISSEQUENTIAL));
    }
    params.cupsOptions = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_OPTION);
    return true;
}

bool PrintJobHelper::GetFileDescriptorList(napi_env env, napi_value jsValue, std::vector<uint32_t> &printFdList)
{
    printFdList.clear();
    napi_value jsFdList = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_FDLIST);
    if (jsFdList != nullptr) {
        bool isFileArray = false;
        napi_is_array(env, jsFdList, &isFileArray);
        if (!isFileArray) {
            PRINT_HILOGE("Invalid file list of print job");
            return false;
        }
        uint32_t arrayReLength = 0;
        napi_get_array_length(env, jsFdList, &arrayReLength);
        for (uint32_t index = 0; index < arrayReLength; index++) {
            napi_value filesValue;
            napi_get_element(env, jsFdList, index, &filesValue);
            uint32_t fd = NapiPrintUtils::GetUint32FromValue(env, filesValue);
            printFdList.emplace_back(fd);
        }
    }
    return true;
}

bool PrintJobHelper::ExtractBinaryData(napi_env env, napi_value jsValue, void* &binaryData, size_t &dataLength)
{
    napi_value jsBinaryData = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_BINARYDATA);
    if (jsBinaryData != nullptr) {
        bool isTypedArray = false;
        napi_is_typedarray(env, jsBinaryData, &isTypedArray);
        if (!isTypedArray) {
            PRINT_HILOGE("Invalid binary data for print job.");
            return false;
        }
        napi_typedarray_type arrayType;
        napi_value arrayBuffer;
        size_t byteOffset = 0;
        napi_get_typedarray_info(env, jsBinaryData, &arrayType, &dataLength, &binaryData, &arrayBuffer, &byteOffset);
    }
    return true;
}

bool PrintJobHelper::GetPrintPageRange(napi_env env, napi_value jsValue, PrintJobParams &params)
{
    napi_value jsPageRange = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PAGERANGE);
    if (jsPageRange != nullptr) {
        auto pageRangePtr = PrintRangeHelper::BuildFromJs(env, jsPageRange);
        if (pageRangePtr == nullptr) {
            PRINT_HILOGE("Failed to build print job object from js");
            return false;
        }
        params.pageRange = *pageRangePtr;
    }
    return true;
}

bool PrintJobHelper::GetPrintMargin(napi_env env, napi_value jsValue, PrintJobParams &params)
{
    napi_value jsMargin = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_MARGIN);
    if (jsMargin != nullptr) {
        auto marginPtr = PrintMarginHelper::BuildFromJs(env, jsMargin);
        if (marginPtr == nullptr) {
            PRINT_HILOGE("Failed to build print job object from js");
            return false;
        }
        params.hasMargin = true;
        params.margin = *marginPtr;
    }
    return true;
}

bool PrintJobHelper::GetPrintPreview(napi_env env, napi_value jsValue, PrintJobParams &params)
{
    napi_value jsPreview = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PREVIEW);
    if (jsPreview != nullptr) {
        auto previewPtr = PrintPreviewAttributeHelper::BuildFromJs(env, jsPreview);
        if (previewPtr == nullptr) {
            PRINT_HILOGE("Failed to build print job object from js");
            return false;
        }
        params.hasPreview = true;
        params.preview = *previewPtr;
    }
    return true;
}
}
