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

#include <ani.h>
#include "print_base_ani_util.h"
#include "print_object_ani_util.h"
#include "ani_print_job_helper.h"
#include "ani_print_range_helper.h"
#include "ani_print_page_size_helper.h"
#include "ani_print_margin_helper.h"
#include "ani_print_preview_attribute_helper.h"
#include "print_log.h"

namespace {
const char* FD_LIST_STR = "fdList";
const char* JOB_ID_STR = "jobId";
const char* PRINTER_ID_STR = "printerId";
const char* JOB_STATE_STR = "jobState";
const char* JOB_SUBSTATE_STR = "jobSubstate";
const char* COPY_NUMBER_STR = "copyNumber";
const char* PAGE_RANGE_STR = "pageRange";
const char* IS_SEQUENTIAL_STR = "isSequential";
const char* PAGE_SIZE_STR = "pageSize";
const char* IS_LANDSCAPE_STR = "isLandscape";
const char* COLOR_MODE_STR = "colorMode";
const char* DUPLEX_MODE_STR = "duplexMode";
const char* MARGIN_STR = "margin";
const char* PREVIEW_STR = "preview";
const char* OPTION_STR = "option";
const char* OPTIONS_STR = "options";
}

namespace OHOS::Print {
static const char *CLASS_NAME = "L@ohos/print/print/PrintJobImp;";
PrintJob AniPrintJobHelper::ParsePrintJob(ani_env *env, ani_object jobInfoAni)
{
    PRINT_HILOGI("enter ParsePrintJob");
    PrintJob jobInfo;
    ParsePrintJobStringField(env, jobInfoAni, jobInfo);
    ParsePrintJobDoubleField(env, jobInfoAni, jobInfo);
    ParsePrintJobRefField(env, jobInfoAni, jobInfo);
    return jobInfo;
}

void AniPrintJobHelper::ParsePrintJobStringField(ani_env *env, ani_object jobInfoAni, PrintJob& jobInfo)
{
    std::string jobId;
    if (GetStringProperty(env, jobInfoAni, JOB_ID_STR, jobId)) {
        jobInfo.SetJobId(jobId);
    }
    std::string printerId;
    if (GetStringProperty(env, jobInfoAni, PRINTER_ID_STR, printerId)) {
        jobInfo.SetPrinterId(printerId);
    }
    std::string option;
    if (GetStringProperty(env, jobInfoAni, OPTION_STR, option)) {
        jobInfo.SetOption(option);
    }
}

void AniPrintJobHelper::ParsePrintJobDoubleField(ani_env *env, ani_object jobInfoAni, PrintJob& jobInfo)
{
    std::vector<ani_double> fdList;
    if (GetDoubleArrayProperty(env, jobInfoAni, FD_LIST_STR, fdList)) {
        std::vector<uint32_t> fdUintList;
        for (const auto &fd : fdList) {
            fdUintList.push_back(static_cast<uint32_t>(fd));
        }
        jobInfo.SetFdList(fdUintList);
    }
    ani_double jobState = 0.0;
    if (GetDoubleProperty(env, jobInfoAni, JOB_STATE_STR, jobState)) {
        jobInfo.SetJobState(static_cast<uint32_t>(jobState));
    }
    ani_double jobSubstate = 0.0;
    if (GetDoubleProperty(env, jobInfoAni, JOB_SUBSTATE_STR, jobSubstate)) {
        jobInfo.SetSubState(static_cast<uint32_t>(jobSubstate));
    }
    ani_double copyNumber = 0.0;
    if (GetDoubleProperty(env, jobInfoAni, COPY_NUMBER_STR, copyNumber)) {
        jobInfo.SetCopyNumber(static_cast<uint32_t>(copyNumber));
    }
    bool isLandscape = false;
    if (GetBoolProperty(env, jobInfoAni, IS_LANDSCAPE_STR, isLandscape)) {
        jobInfo.SetIsLandscape(isLandscape);
    }
    ani_double colorMode  = false;
    if (GetDoubleProperty(env, jobInfoAni, COLOR_MODE_STR, colorMode)) {
        jobInfo.SetColorMode(static_cast<uint32_t>(colorMode));
    }
    ani_double duplexMode = false;
    if (GetDoubleProperty(env, jobInfoAni, DUPLEX_MODE_STR, duplexMode)) {
        jobInfo.SetDuplexMode(static_cast<uint32_t>(duplexMode));
    }
}

void AniPrintJobHelper::ParsePrintJobRefField(ani_env *env, ani_object jobInfoAni, PrintJob& jobInfo)
{
    ani_ref marginRef = nullptr;
    if (GetRefProperty(env, jobInfoAni, MARGIN_STR, marginRef)) {
        jobInfo.SetMargin(AniPrintMarginHelper::ParsePrintMargin(env, static_cast<ani_object>(marginRef)));
    }
    ani_ref previewRef = nullptr;
    if (GetRefProperty(env, jobInfoAni, PREVIEW_STR, previewRef)) {
        jobInfo.SetPreview(AniPrintPreviewAttributeHelper::ParsePreviewAttribute(env,
            static_cast<ani_object>(previewRef)));
    }
    ani_ref pageRangeRef = nullptr;
    if (GetRefProperty(env, jobInfoAni, PAGE_RANGE_STR, pageRangeRef)) {
        jobInfo.SetPageRange(AniPrintRangeHelper::ParsePrinterRange(env, static_cast<ani_object>(pageRangeRef)));
    }
    bool isSequential = false;
    if (GetBoolProperty(env, jobInfoAni, IS_SEQUENTIAL_STR, isSequential)) {
        jobInfo.SetIsSequential(isSequential);
    }
    ani_ref pageSizeRef = nullptr;
    if (GetRefProperty(env, jobInfoAni, PAGE_SIZE_STR, pageSizeRef)) {
        jobInfo.SetPageSize(AniPrintPageSizeHelper::ParsePrintPageSize(env, static_cast<ani_object>(pageSizeRef)));
    }
}

ani_object AniPrintJobHelper::CreatePrintJob(ani_env *env, const PrintJob& printJob)
{
    PRINT_HILOGI("enter CreatePrintJob");
    ani_object obj = CreateObject(env, nullptr, CLASS_NAME);
    std::vector<uint32_t> fdList;
    printJob.GetFdList(fdList);
    SetDoubleArrayProperty(env, obj, FD_LIST_STR, std::vector<double>(fdList.begin(), fdList.end()));
    SetStringProperty(env, obj, JOB_ID_STR, printJob.GetJobId());
    SetStringProperty(env, obj, PRINTER_ID_STR, printJob.GetPrinterId());
    SetDoubleProperty(env, obj, JOB_STATE_STR, static_cast<double>(printJob.GetJobState()));
    SetDoubleProperty(env, obj, JOB_SUBSTATE_STR, static_cast<double>(printJob.GetSubState()));
    SetDoubleProperty(env, obj, COPY_NUMBER_STR, static_cast<double>(printJob.GetCopyNumber()));
    PrintRange range;
    printJob.GetPageRange(range);
    ani_ref pageRangeRef = AniPrintRangeHelper::CreatePrinterRange(env, range);
    SetRefProperty(env, obj, PAGE_RANGE_STR, pageRangeRef);
    SetBoolProperty(env, obj, IS_SEQUENTIAL_STR, printJob.GetIsSequential());
    PrintPageSize pageSize;
    printJob.GetPageSize(pageSize);
    ani_ref pageSizeRef = AniPrintPageSizeHelper::CreatePageSize(env, pageSize);
    SetRefProperty(env, obj, PAGE_SIZE_STR, pageSizeRef);
    SetBoolProperty(env, obj, IS_LANDSCAPE_STR, printJob.GetIsLandscape());
    SetDoubleProperty(env, obj, COLOR_MODE_STR, static_cast<double>(printJob.GetColorMode()));
    SetDoubleProperty(env, obj, DUPLEX_MODE_STR, static_cast<double>(printJob.GetDuplexMode()));
    if (printJob.HasMargin()) {
        PrintMargin margin;
        printJob.GetMargin(margin);
        ani_ref marginRef = AniPrintMarginHelper::CreatePrintMargin(env, margin);
        SetRefProperty(env, obj, MARGIN_STR, marginRef);
    }
    if (printJob.HasPreview()) {
        PrintPreviewAttribute preview;
        printJob.GetPreview(preview);
        ani_ref marginRef = AniPrintPreviewAttributeHelper::CreatePreviewAttribute(env, preview);
        SetRefProperty(env, obj, PREVIEW_STR, marginRef);
    }
    if (printJob.HasOption()) {
        SetStringProperty(env, obj, OPTIONS_STR, printJob.GetOption());
    }
    return obj;
}

ani_object AniPrintJobHelper::CreatePrintJobArray(ani_env *env, const std::vector<PrintJob>& jobs)
{
    PRINT_HILOGI("enter CreatePrintJobArray");

    ani_object arrayObj = {};
    ani_class cls;
    if (ANI_OK != env->FindClass(CLASS_NAME, &cls)) {
        PRINT_HILOGE("[ANI] find class fail");
        return arrayObj;
    }

    ani_ref undefinedRef = nullptr;
    if (ANI_OK != env->GetUndefined(&undefinedRef)) {
        PRINT_HILOGE("GetUndefined Failed");
        return arrayObj;
    }
    ani_array_ref arrayRef;
    if (ANI_OK != env->Array_New_Ref(cls, jobs.size(), undefinedRef, &arrayRef)) {
        PRINT_HILOGE("Create Array Failed");
        return arrayObj;
    }
    arrayObj = arrayRef;

    for (size_t i = 0; i < jobs.size(); i++) {
        ani_object jobObj = CreatePrintJob(env, jobs[i]);
        if (ANI_OK != env->Array_Set_Ref(arrayRef, i, jobObj)) {
            PRINT_HILOGE("Set Array Element Failed");
            return arrayObj;
        }
    }

    return arrayObj;
}
}  // namespace OHOS::Print
