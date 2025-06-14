/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <ani.h>
#include <array>
#include <iostream>
#include <vector>
#include "refbase.h"
#include "ani_base_context.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_entry.h"
#include "print_callback.h"
#include "print_ani_callback.h"
#include "print_base_ani_util.h"
#include "print_callback_ani_util.h"
#include "print_object_ani_util.h"
#include "ani_print_attributes_helper.h"
#include "ani_print_extension_info_helper.h"
#include "ani_print_job_helper.h"
#include "ani_print_margin_helper.h"
#include "ani_print_page_size_helper.h"
#include "ani_print_preview_attribute_helper.h"
#include "ani_print_range_helper.h"
#include "ani_print_resolution_helper.h"
#include "ani_printer_capability_helper.h"
#include "ani_printer_info_helper.h"

using namespace OHOS::Print;
static void PrintNative(ani_env *env, ani_object arrayObj, ani_object callback)
{
    PRINT_HILOGI("enter PrintNative");
    std::vector<std::string> files;
    if (!GetStdStringArray(env, arrayObj, files)) {
        PRINT_HILOGE("GetStringArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    for (const auto &file : files) {
        PRINT_HILOGD("Array String Content: = %{private}s", file.c_str());
    }
    ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void PrintWithContextNative(ani_env *env, ani_object arrayObj, ani_object context, ani_object callback)
{
    PRINT_HILOGI("enter PrintWithContextNative");
    std::vector<std::string> files;
    if (!GetStdStringArray(env, arrayObj, files)) {
        PRINT_HILOGE("GetStringArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    for (const auto &file : files) {
        PRINT_HILOGD("Array String Content: = %{private}s", file.c_str());
    }
    auto ctx = OHOS::AbilityRuntime::GetStageModeContext(env, context);
    if (ctx == nullptr) {
        PRINT_HILOGE("Get Context Failed");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
    }
    int32_t ret = PrintEntry::GetInstance().StartPrintWithContext(files, ctx);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void PrintWithAttributesNative(ani_env *env, ani_object para, ani_object callback)
{
    PRINT_HILOGI("enter PrintWithAttributesNative");
    std::string jobName;
    const char* jobNameStr = "jobName";
    if (GetStringOrUndefined(env, para, jobNameStr, jobName)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    ani_ref printAdapter;
    const char* printAdapterStr = "printAdapter";
    if (GetRefFieldByName(env, para, printAdapterStr, printAdapter)) {
        PRINT_HILOGE("GetRefFieldByName fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    ani_ref printAttributes;
    const char* printAttributesStr = "printAttributes";
    if (GetRefFieldByName(env, para, printAttributesStr, printAttributes)) {
        PRINT_HILOGE("GetRefFieldByName fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PrintAttributes attributes = AniPrintAttributesHelper::ParsePrintAttributes(env,
        static_cast<ani_object>(printAttributes));
    ani_ref context;
    const char* contextStr = "context";
    if (GetRefFieldByName(env, para, contextStr, context)) {
        PRINT_HILOGE("GetRefFieldByName fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    auto ctx = OHOS::AbilityRuntime::GetStageModeContext(env, static_cast<ani_object>(context));
    if (ctx == nullptr) {
        PRINT_HILOGE("Get Context Failed");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
    }
    ani_vm *vm = nullptr;
    env->GetVM(&vm);
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow)
        PrintAniCallback(vm, static_cast<ani_object>(printAdapter));
    int32_t ret = PrintEntry::GetInstance().StartPrintWithAttributes(jobName, ctx, attributes, callbackWrapper);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void QueryAllPrinterExtensionInfosNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter QueryAllPrinterExtensionInfosNative");
    std::vector<PrintExtensionInfo> extensionInfos;
    int32_t ret = PrintEntry::GetInstance().QueryAllExtension(extensionInfos);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallbackArray(env, callback, stsErrCode,
        AniPrintExtensionInfoHelper::CreatePrinterExtensionInfoArray(env, extensionInfos));
}

static void StartDiscoverPrinterNative(ani_env *env, ani_object arrayObj, ani_object callback)
{
    PRINT_HILOGI("enter StartDiscoverPrinterNative");
    std::vector<std::string> extensionList;
    GetStdStringArray(env, arrayObj, extensionList);
    int32_t ret = PrintEntry::GetInstance().StartDiscoverPrinter(extensionList);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void StopDiscoverPrinterNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter StopDiscoverPrinterNative");
    int32_t ret = PrintEntry::GetInstance().StopDiscoverPrinter();
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void ConnectPrinterNative(ani_env *env, ani_string printerIdAni, ani_object callback)
{
    PRINT_HILOGI("enter ConnectPrinterNative");
    std::string printerId;
    if (!GetStdString(env, printerIdAni, printerId)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", printerId.c_str());
    int32_t ret = PrintEntry::GetInstance().ConnectPrinter(printerId);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void DisconnectPrinterNative(ani_env *env, ani_string printerId, ani_object callback)
{
    PRINT_HILOGI("enter DisconnectPrinterNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", id.c_str());
    int32_t ret = PrintEntry::GetInstance().DisconnectPrinter(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void QueryPrinterCapabilityNative(ani_env *env, ani_string printerId, ani_object callback)
{
    PRINT_HILOGI("enter QueryPrinterCapabilityNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", id.c_str());
    int32_t ret = PrintEntry::GetInstance().QueryPrinterCapability(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void StartPrintJobNative(ani_env *env, ani_object jobInfo, ani_object callback)
{
    PRINT_HILOGI("enter StartPrintJobNative");
    PrintJob job = AniPrintJobHelper::ParsePrintJob(env, jobInfo);
    int32_t ret = PrintEntry::GetInstance().StartPrintJob(job);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void CancelPrintJobNative(ani_env *env, ani_string jobId, ani_object callback)
{
    PRINT_HILOGI("enter CancelPrintJobNative");
    std::string id;
    if (!GetStdString(env, jobId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s", id.c_str());
    int32_t ret = PrintEntry::GetInstance().CancelPrintJob(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void RequestPrintPreviewNative(ani_env *env, ani_object jobInfo, ani_object callback)
{
    PRINT_HILOGI("enter RequestPrintPreviewNative");
    PrintJob job = AniPrintJobHelper::ParsePrintJob(env, jobInfo);
    int32_t result = 0;
    int32_t ret = PrintEntry::GetInstance().RequestPrintPreview(job, result);
    if (ret != E_PRINT_NONE) {
        ani_object stsErrCode = CreateStsError(env, ret);
        AsyncCallback(env, callback, stsErrCode, nullptr);
    } else {
        ani_object resultObj = CreateDouble(env, result);
        AsyncCallback(env, callback, nullptr, resultObj);
    }
}

static void AddPrintersNative(ani_env *env, ani_object printers, ani_object callback)
{
    PRINT_HILOGI("enter AddPrintersNative");
    std::vector<PrinterInfo> printerList;
    if (!PrinterInfoAniHelper::GetPrinterInfoArray(env, printers, printerList)) {
        PRINT_HILOGE("GetPrinterInfoArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    int32_t ret = PrintEntry::GetInstance().AddPrinters(printerList);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void RemovePrintersNative(ani_env *env, ani_object printerIds, ani_object callback)
{
    PRINT_HILOGI("enter RemovePrintersNative");
    std::vector<std::string> ids;
    if (!GetStdStringArray(env, printerIds, ids)) {
        PRINT_HILOGE("GetStringArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    int32_t ret = PrintEntry::GetInstance().RemovePrinters(ids);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdatePrintersNative(ani_env *env, ani_object printers, ani_object callback)
{
    PRINT_HILOGI("enter UpdatePrintersNative");
    std::vector<PrinterInfo> printerList;
    if (!PrinterInfoAniHelper::GetPrinterInfoArray(env, printers, printerList)) {
        PRINT_HILOGE("GetPrinterInfoArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    int32_t ret = PrintEntry::GetInstance().UpdatePrinters(printerList);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdatePrinterStateNative(ani_env *env, ani_string printerId, ani_int enumStateIndex, ani_object callback)
{
    PRINT_HILOGI("enter UpdatePrinterStateNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    const char* enumName = "L@ohos/print/PrinterState;";
    uint32_t enumValue = GetEnumValueInt(env, enumName, enumStateIndex);
    PRINT_HILOGD("enumValue = %{public}u", enumValue);
    int32_t ret = PrintEntry::GetInstance().UpdatePrinterState(id, enumValue);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdatePrintJobStateNative(ani_env *env, ani_string printerId,
    ani_int enumJobStateIndex, ani_int enumJobSubStateIndex, ani_object callback)
{
    PRINT_HILOGI("enter UpdatePrintJobStateNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    const char* enumJobStateName = "L@ohos/print/PrintJobState;";
    uint32_t jobState = GetEnumValueInt(env, enumJobStateName, enumJobStateIndex);
    PRINT_HILOGD("jobState = %{public}u", jobState);
    const char* enumJobSubStateName = "L@ohos/print/PrintJobSubState;";
    uint32_t jobSubState = GetEnumValueInt(env, enumJobSubStateName, enumJobSubStateIndex);
    PRINT_HILOGD("jobSubState = %{public}u", jobSubState);
    int32_t ret = PrintEntry::GetInstance().UpdatePrintJobState(id, jobState, jobSubState);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdateExtensionInfoNative(ani_env *env, ani_string info, ani_object callback)
{
    PRINT_HILOGI("enter UpdateExtensionInfoNative");
    std::string infoStr;
    if (!GetStdString(env, info, infoStr)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Extension Info: %{public}s", infoStr.c_str());
    int32_t ret = PrintEntry::GetInstance().UpdateExtensionInfo(infoStr);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void QueryAllPrintJobsNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter QueryAllPrintJobsNative");
    std::vector<PrintJob> jobs;
    int32_t ret = PrintEntry::GetInstance().QueryAllPrintJobs(jobs);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void QueryPrintJobListNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter QueryPrintJobListNative");
    std::vector<PrintJob> jobs;
    int32_t ret = PrintEntry::GetInstance().QueryPrintJobList(jobs);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, AniPrintJobHelper::CreatePrintJobArray(env, jobs));
}

static void QueryPrintJobByIdNative(ani_env *env, ani_string jobId, ani_object callback)
{
    PRINT_HILOGI("enter QueryPrintJobByIdNative");
    std::string id;
    if (!GetStdString(env, jobId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s", id.c_str());
    PrintJob job;
    int32_t ret = PrintEntry::GetInstance().QueryPrintJobById(id, job);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, AniPrintJobHelper::CreatePrintJob(env, job));
}

static void StartGettingPrintFileNative(ani_env *env, ani_string jobId,
    ani_object printAttributes, ani_int fd, ani_object callback)
{
    PRINT_HILOGI("enter StartGettingPrintFileNative");
    std::string id;
    if (!GetStdString(env, jobId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s, FD: %{public}d", id.c_str(), fd);
    PrintAttributes attrs = AniPrintAttributesHelper::ParsePrintAttributes(env, printAttributes);
    int32_t ret = PrintEntry::GetInstance().StartGettingPrintFile(id, attrs, fd);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void NotifyPrintServiceNative(ani_env *env, ani_string jobId, ani_string typeAni, ani_object callback)
{
    PRINT_HILOGI("enter NotifyPrintServiceNative");
    std::string id;
    if (!GetStdString(env, jobId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s", id.c_str());
    std::string type;
    if (!GetStdString(env, typeAni, type)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s", id.c_str());
    int32_t ret = PrintEntry::GetInstance().NotifyPrintService(id, type);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static ani_int GetAddedPrintersNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter GetAddedPrintersNative");
    std::vector<std::string> printers;
    int32_t ret = PrintEntry::GetInstance().GetAddedPrinters(printers);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, CreateAniStringArray(env, printers));
    return ANI_OK;
}

static void GetPrinterInfoByIdNative(ani_env *env, ani_string printerId, ani_object callback)
{
    PRINT_HILOGI("enter GetPrinterInfoByIdNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", id.c_str());
    PrinterInfo info;
    int32_t ret = PrintEntry::GetInstance().GetPrinterInfoById(id, info);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, PrinterInfoAniHelper::CreatePrinterInfo(env, info));
}

static void NotifyPrintServiceEventNative(ani_env *env, ani_int eventIndex, ani_object callback)
{
    PRINT_HILOGI("enter NotifyPrintServiceEventNative");
    const char* enumApplicationEventName = "L@ohos/print/ApplicationEvent;";
    uint32_t event = GetEnumValueInt(env, enumApplicationEventName, eventIndex);
    PRINT_HILOGD("Event: %{public}d", event);
    int32_t ret = PrintEntry::GetInstance().NotifyPrintServiceEvent(event);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void AddPrinterToDiscoveryNative(ani_env *env, ani_object printerInfo, ani_object callback)
{
    PRINT_HILOGI("enter AddPrinterToDiscoveryNative");
    PrinterInfo info = PrinterInfoAniHelper::ParsePrinterInformation(env, printerInfo);
    int32_t ret = PrintEntry::GetInstance().AddPrinterToDiscovery(info);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdatePrinterInDiscoveryNative(ani_env *env, ani_object printerInfo, ani_object callback)
{
    PRINT_HILOGI("enter UpdatePrinterInDiscoveryNative");
    PrinterInfo info = PrinterInfoAniHelper::ParsePrinterInformation(env, printerInfo);
    int32_t ret = PrintEntry::GetInstance().UpdatePrinterInDiscovery(info);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void RemovePrinterFromDiscoveryNative(ani_env *env, ani_string printerId, ani_object callback)
{
    PRINT_HILOGI("enter RemovePrinterFromDiscoveryNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", id.c_str());
    int32_t ret = PrintEntry::GetInstance().RemovePrinterFromDiscovery(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void GetPrinterInformationByIdNative(ani_env *env, ani_string printerIdAni, ani_object callback)
{
    PRINT_HILOGI("enter GetPrinterInformationByIdNative");
    std::string printerId;
    if (!GetStdString(env, printerIdAni, printerId)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_GENERIC_FAILURE);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("printerId: %{public}s", printerId.c_str());
    PrinterInfo info;
    int32_t ret = PrintEntry::GetInstance().QueryPrinterInfoByPrinterId(printerId, info);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, PrinterInfoAniHelper::CreatePrinterInformation(env, info));
}

static void OnPrinterStateChangeNative(ani_env *env, ani_string type, ani_object callback)
{
    PRINT_HILOGI("enter OnPrinterStateChangeNative");
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        PRINT_HILOGE("GetStdString fail");
        return;
    }
    PRINT_HILOGD("typeStr: %{public}s", typeStr.c_str());
    ani_vm *vm = nullptr;
    env->GetVM(&vm);
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(vm, callback);
    PrintEntry::GetInstance().On(typeStr, callbackWrapper);
}

static void OnJobStateChangeNative(ani_env *env, ani_string type, ani_object callback)
{
    PRINT_HILOGI("enter OnJobStateChangeNative");
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        PRINT_HILOGE("GetStdString fail");
        return;
    }
    PRINT_HILOGD("typeStr: %{public}s", typeStr.c_str());
    ani_vm *vm = nullptr;
    env->GetVM(&vm);
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(vm, callback);
    PrintEntry::GetInstance().On(typeStr, callbackWrapper);
}

static void OnExtInfoChangeNative(ani_env *env, ani_string type, ani_object callback)
{
    PRINT_HILOGI("enter OnExtInfoChangeNative");
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        PRINT_HILOGE("GetStdString fail");
        return;
    }
    PRINT_HILOGD("typeStr: %{public}s", typeStr.c_str());
    ani_vm *vm = nullptr;
    env->GetVM(&vm);
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(vm, callback);
    PrintEntry::GetInstance().On(typeStr, callbackWrapper);
}

static void OffNative(ani_env *env, ani_string type, ani_string string_object)
{
    PRINT_HILOGI("enter OffNative");
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        PRINT_HILOGE("GetStdString fail");
        return;
    }
    PRINT_HILOGD("CallMeWithOptionalString Get = %{public}s", typeStr.c_str());
    PrintEntry::GetInstance().Off(typeStr);
}

template<typename Func>
static inline ani_native_function MakeNativeFunc(const char* etsFuncName, Func cFunc)
{
    return {etsFuncName, nullptr, reinterpret_cast<void*>(cFunc)};
}

static std::array methods = {
    MakeNativeFunc("printNative", PrintNative),
    MakeNativeFunc("printWithContextNative", PrintWithContextNative),
    MakeNativeFunc("printWithAttributesNative", PrintWithAttributesNative),
    MakeNativeFunc("queryAllPrinterExtensionInfosNative", QueryAllPrinterExtensionInfosNative),
    MakeNativeFunc("startDiscoverPrinterNative", StartDiscoverPrinterNative),
    MakeNativeFunc("stopDiscoverPrinterNative", StopDiscoverPrinterNative),
    MakeNativeFunc("connectPrinterNative", ConnectPrinterNative),
    MakeNativeFunc("disconnectPrinterNative", DisconnectPrinterNative),
    MakeNativeFunc("queryPrinterCapabilityNative", QueryPrinterCapabilityNative),
    MakeNativeFunc("startPrintJobNative", StartPrintJobNative),
    MakeNativeFunc("cancelPrintJobNative", CancelPrintJobNative),
    MakeNativeFunc("requestPrintPreviewNative", RequestPrintPreviewNative),
    MakeNativeFunc("addPrintersNative", AddPrintersNative),
    MakeNativeFunc("removePrintersNative", RemovePrintersNative),
    MakeNativeFunc("updatePrintersNative", UpdatePrintersNative),
    MakeNativeFunc("updatePrinterStateNative", UpdatePrinterStateNative),
    MakeNativeFunc("updatePrintJobStateNative", UpdatePrintJobStateNative),
    MakeNativeFunc("updateExtensionInfoNative", UpdateExtensionInfoNative),
    MakeNativeFunc("queryAllPrintJobsNative", QueryAllPrintJobsNative),
    MakeNativeFunc("queryPrintJobListNative", QueryPrintJobListNative),
    MakeNativeFunc("queryPrintJobByIdNative", QueryPrintJobByIdNative),
    MakeNativeFunc("startGettingPrintFileNative", StartGettingPrintFileNative),
    MakeNativeFunc("notifyPrintServiceNative", NotifyPrintServiceNative),
    MakeNativeFunc("getAddedPrintersNative", GetAddedPrintersNative),
    MakeNativeFunc("getPrinterInfoByIdNative", GetPrinterInfoByIdNative),
    MakeNativeFunc("notifyPrintServiceEventNative", NotifyPrintServiceEventNative),
    MakeNativeFunc("addPrinterToDiscoveryNative", AddPrinterToDiscoveryNative),
    MakeNativeFunc("updatePrinterInDiscoveryNative", UpdatePrinterInDiscoveryNative),
    MakeNativeFunc("removePrinterFromDiscoveryNative", RemovePrinterFromDiscoveryNative),
    MakeNativeFunc("getPrinterInformationByIdNative", GetPrinterInformationByIdNative),
    MakeNativeFunc("onPrinterStateChangeNative", OnPrinterStateChangeNative),
    MakeNativeFunc("onJobStateChangeNative", OnJobStateChangeNative),
    MakeNativeFunc("onExtInfoChangeNative", OnExtInfoChangeNative),
    MakeNativeFunc("offNative", OffNative),
};

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    PRINT_HILOGI("enter ANI_Constructor");
    uint32_t status = 0;
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        PRINT_HILOGE("Unsupported ANI_VERSION_1, status = %{public}u", status);
        return ANI_ERROR;
    }

    ani_namespace ns;
    const char* targetNamespace = "L@ohos/print/print;";
    status = env->FindNamespace(targetNamespace, &ns);
    if (status != ANI_OK) {
        PRINT_HILOGE("FindNamespace failed");
        return static_cast<ani_status>(status);
    }
    
    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        PRINT_HILOGE("Cannot bind native methods, status = %{public}u", status);
        return ANI_INVALID_ARGS;
    };

    PRINT_HILOGI("Finish bind native methods");
    *result = ANI_VERSION_1;
    return ANI_OK;
}