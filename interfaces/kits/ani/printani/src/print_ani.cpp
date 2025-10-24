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
#include "print_manager_client.h"
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
#include "ani_print_task_helper.h"

namespace {
    const char* JOB_NAME_STR = "jobName";
    const char* PRINT_ADAPTER_STR = "printAdapter";
    const char* PRINT_ATTRIBUTES_STR = "printAttributes";
    const char* CONTEXT_STR = "context";
}
using namespace OHOS::Print;
static void PrintNative(ani_env *env, ani_object arrayObj, ani_object callback)
{
    PRINT_HILOGI("enter PrintNative");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::vector<std::string> files;
    if (!GetStdStringArray(env, arrayObj, files)) {
        PRINT_HILOGE("GetStringArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    for (const auto &file : files) {
        PRINT_HILOGD("Array String Content: = %{private}s", file.c_str());
    }
    auto nativePrintTask = new AniPrintTask(env);
    if (nativePrintTask == nullptr) {
        PRINT_HILOGE("nativePrintTask is a nullptr");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    int32_t ret = nativePrintTask->StartPrint(files);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, AniPrintTaskHelper::CreatePrintTask(env, nativePrintTask));
}

static void PrintWithContextNative(ani_env *env, ani_object arrayObj, ani_object context, ani_object callback)
{
    PRINT_HILOGI("enter PrintWithContextNative");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::vector<std::string> files;
    if (!GetStdStringArray(env, arrayObj, files)) {
        PRINT_HILOGE("GetStringArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    for (const auto &file : files) {
        PRINT_HILOGD("Array String Content: = %{private}s", file.c_str());
    }
    auto ctx = OHOS::AbilityRuntime::GetStageModeContext(env, context);
    if (ctx == nullptr) {
        PRINT_HILOGE("Get Context Failed");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    auto nativePrintTask = new AniPrintTask(env);
    if (nativePrintTask == nullptr) {
        PRINT_HILOGE("nativePrintTask is a nullptr");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    int32_t ret = nativePrintTask->StartPrintWithContext(files, ctx);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, AniPrintTaskHelper::CreatePrintTask(env, nativePrintTask));
}

static void PrintWithAttributesNative(ani_env *env, ani_object para, ani_object callback)
{
    PRINT_HILOGI("enter PrintWithAttributesNative");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::string jobName;
    if (!GetStringProperty(env, para, JOB_NAME_STR, jobName)) {
        PRINT_HILOGE("GetStdString fail");
        AsyncCallback(env, callback, CreateStsError(env, E_PRINT_INVALID_PARAMETER), nullptr);
        return;
    }
    ani_ref printAdapter;
    if (!GetRefProperty(env, para, PRINT_ADAPTER_STR, printAdapter)) {
        PRINT_HILOGE("GetRefProperty fail");
        AsyncCallback(env, callback, CreateStsError(env, E_PRINT_INVALID_PARAMETER), nullptr);
        return;
    }
    ani_ref printAttributes;
    if (!GetRefProperty(env, para, PRINT_ATTRIBUTES_STR, printAttributes)) {
        PRINT_HILOGE("GetRefProperty fail");
        AsyncCallback(env, callback, CreateStsError(env, E_PRINT_INVALID_PARAMETER), nullptr);
        return;
    }
    PrintAttributes attributes = AniPrintAttributesHelper::ParsePrintAttributes(env,
        static_cast<ani_object>(printAttributes));
    ani_ref context;
    if (!GetRefProperty(env, para, CONTEXT_STR, context)) {
        PRINT_HILOGE("GetRefProperty fail");
        AsyncCallback(env, callback, CreateStsError(env, E_PRINT_INVALID_PARAMETER), nullptr);
        return;
    }
    auto ctx = OHOS::AbilityRuntime::GetStageModeContext(env, static_cast<ani_object>(context));
    if (ctx == nullptr) {
        PRINT_HILOGE("Get Context Failed");
        AsyncCallback(env, callback, CreateStsError(env, E_PRINT_INVALID_PARAMETER), nullptr);
        return;
    }
    auto nativePrintTask = new AniPrintTask(env);
    OHOS::sptr<IPrintCallback> callbackWrapper = new PrintAniCallback(env, static_cast<ani_object>(printAdapter));
    if (nativePrintTask == nullptr || callbackWrapper == nullptr) {
        PRINT_HILOGE("nativePrintTask or callbackWrapper is nullptr");
        AsyncCallback(env, callback, CreateStsError(env, E_PRINT_INVALID_PARAMETER), nullptr);
        return;
    }
    int32_t ret = nativePrintTask->StartPrintWithAttributes(jobName, ctx, attributes, callbackWrapper);
    AsyncCallback(env, callback, CreateStsError(env, ret), AniPrintTaskHelper::CreatePrintTask(env, nativePrintTask));
}

static void QueryAllPrinterExtensionInfosNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter QueryAllPrinterExtensionInfosNative");
    std::vector<PrintExtensionInfo> extensionInfos;
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallbackArray(env, callback, stsErrCode,
        AniPrintExtensionInfoHelper::CreatePrinterExtensionInfoArray(env, extensionInfos));
}

static void StartDiscoverPrinterNative(ani_env *env, ani_object arrayObj, ani_object callback)
{
    PRINT_HILOGI("enter StartDiscoverPrinterNative");
    std::vector<std::string> extensionList;
    GetStdStringArray(env, arrayObj, extensionList);
    for (auto extension : extensionList) {
        PRINT_HILOGD("extension = %{public}s", extension.c_str());
    }
    int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(extensionList);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void StopDiscoverPrinterNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter StopDiscoverPrinterNative");
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void ConnectPrinterNative(ani_env *env, ani_string printerIdAni, ani_object callback)
{
    PRINT_HILOGI("enter ConnectPrinterNative");
    std::string printerId;
    if (!GetStdString(env, printerIdAni, printerId)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", printerId.c_str());
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(printerId);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void DisconnectPrinterNative(ani_env *env, ani_string printerId, ani_object callback)
{
    PRINT_HILOGI("enter DisconnectPrinterNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", id.c_str());
    int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void QueryPrinterCapabilityNative(ani_env *env, ani_string printerId, ani_object callback)
{
    PRINT_HILOGI("enter QueryPrinterCapabilityNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", id.c_str());
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void StartPrintJobNative(ani_env *env, ani_object jobInfo, ani_object callback)
{
    PRINT_HILOGI("enter StartPrintJobNative");
    PrintJob job = AniPrintJobHelper::ParsePrintJob(env, jobInfo);
    int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(job);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void CancelPrintJobNative(ani_env *env, ani_string jobId, ani_object callback)
{
    PRINT_HILOGI("enter CancelPrintJobNative");
    std::string id;
    if (!GetStdString(env, jobId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s", id.c_str());
    int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void RequestPrintPreviewCallbackNative(ani_env *env, ani_object jobInfo, ani_object callback)
{
    PRINT_HILOGI("enter RequestPrintPreviewNative");
    PrintJob job = AniPrintJobHelper::ParsePrintJob(env, jobInfo);
    std::string previewResult;
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(job, previewResult);
    ani_object resultObj = CreateInt(env, ret);
    if (ret != E_PRINT_NONE) {
        StsCallback(env, callback, nullptr);
    } else {
        StsCallback(env, callback, resultObj);
    }
}

static void RequestPrintPreviewAsyncCallbackNative(ani_env *env, ani_object jobInfo, ani_object callback)
{
    PRINT_HILOGI("enter RequestPrintPreviewNative");
    PrintJob job = AniPrintJobHelper::ParsePrintJob(env, jobInfo);
    std::string previewResult;
    int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(job, previewResult);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, CreateInt(env, ret));
}

static void AddPrintersNative(ani_env *env, ani_object printers, ani_object callback)
{
    PRINT_HILOGI("enter AddPrintersNative");
    std::vector<PrinterInfo> printerList;
    if (!PrinterInfoAniHelper::GetPrinterInfoArray(env, printers, printerList)) {
        PRINT_HILOGE("GetPrinterInfoArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(printerList);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void RemovePrintersNative(ani_env *env, ani_object printerIds, ani_object callback)
{
    PRINT_HILOGI("enter RemovePrintersNative");
    std::vector<std::string> ids;
    if (!GetStdStringArray(env, printerIds, ids)) {
        PRINT_HILOGE("GetStringArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    for (auto id : ids) {
        PRINT_HILOGD("id = %{public}s", id.c_str());
    }
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(ids);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdatePrintersNative(ani_env *env, ani_object printers, ani_object callback)
{
    PRINT_HILOGI("enter UpdatePrintersNative");
    std::vector<PrinterInfo> printerList;
    if (!PrinterInfoAniHelper::GetPrinterInfoArray(env, printers, printerList)) {
        PRINT_HILOGE("GetPrinterInfoArray fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(printerList);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdatePrinterStateNative(ani_env *env, ani_string printerId, ani_enum_item enumObj, ani_object callback)
{
    PRINT_HILOGI("enter UpdatePrinterStateNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("id = %{public}s", id.c_str());
    uint32_t enumValue = 0;
    if (!GetEnumValueInt(env, enumObj, enumValue)) {
        PRINT_HILOGE("GetEnumValueInt fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("enumValue = %{public}u", enumValue);
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(id, enumValue);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdatePrintJobStateNative(ani_env *env, ani_string printerId, ani_enum_item enumJobStateObj,
    ani_enum_item enumJobSubStateObj, ani_object callback)
{
    PRINT_HILOGI("enter UpdatePrintJobStateNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    uint32_t jobState = 0;
    if (!GetEnumValueInt(env, enumJobSubStateObj, jobState)) {
        PRINT_HILOGE("GetEnumValueInt fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("jobState = %{public}u", jobState);
    uint32_t jobSubState = 0;
    if (!GetEnumValueInt(env, enumJobStateObj, jobSubState)) {
        PRINT_HILOGE("GetEnumValueInt fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("jobSubState = %{public}u", jobSubState);
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobStateForNormalApp(id, jobState, jobSubState);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdateExtensionInfoNative(ani_env *env, ani_string info, ani_object callback)
{
    PRINT_HILOGI("enter UpdateExtensionInfoNative");
    std::string infoStr;
    if (!GetStdString(env, info, infoStr)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Extension Info: %{public}s", infoStr.c_str());
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(infoStr);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void QueryAllPrintJobsNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter QueryAllPrintJobsNative");
    std::vector<PrintJob> jobs;
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(jobs);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void QueryPrintJobListNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter QueryPrintJobListNative");
    std::vector<PrintJob> jobs;
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(jobs);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallbackArray(env, callback, stsErrCode, AniPrintJobHelper::CreatePrintJobArray(env, jobs));
}

static void QueryPrintJobByIdNative(ani_env *env, ani_string jobId, ani_object callback)
{
    PRINT_HILOGI("enter QueryPrintJobByIdNative");
    std::string id;
    if (!GetStdString(env, jobId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s", id.c_str());
    PrintJob job;
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(id, job);
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
        StsCallback(env, callback, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s, FD: %{public}d", id.c_str(), fd);
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(env, callback);
    std::string typeStr = "getPrintFileCallback_adapter";
    PrintManagerClient::GetInstance()->On("", typeStr, callbackWrapper);
    PrintAttributes attrs = AniPrintAttributesHelper::ParsePrintAttributes(env, printAttributes);
    PrintManagerClient::GetInstance()->StartGetPrintFile(id, attrs, fd);
}

static void NotifyPrintServiceNative(ani_env *env, ani_string jobId, ani_string typeAni, ani_object callback)
{
    PRINT_HILOGI("enter NotifyPrintServiceNative");
    std::string id;
    if (!GetStdString(env, jobId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s", id.c_str());
    std::string type;
    if (!GetStdString(env, typeAni, type)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Job ID: %{public}s", id.c_str());
    int32_t ret = PrintManagerClient::GetInstance()->NotifyPrintService(id, type);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static ani_int GetAddedPrintersNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter GetAddedPrintersNative");
    std::vector<std::string> printers;
    int32_t ret = PrintManagerClient::GetInstance()->QueryAddedPrinter(printers);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallbackArray(env, callback, stsErrCode, CreateAniStringArray(env, printers));
    return ANI_OK;
}

static void GetPrinterInfoByIdNative(ani_env *env, ani_string printerId, ani_object callback)
{
    PRINT_HILOGI("enter GetPrinterInfoByIdNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", id.c_str());
    PrinterInfo info;
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterInfoByPrinterId(id, info);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, PrinterInfoAniHelper::CreatePrinterInfo(env, info));
}

static void NotifyPrintServiceEventNative(ani_env *env, ani_enum_item enumObj, ani_object callback)
{
    PRINT_HILOGI("enter NotifyPrintServiceEventNative");
    uint32_t event = 0;
    if (!GetEnumValueInt(env, enumObj, event)) {
        PRINT_HILOGE("GetEnumValueInt fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Event: %{public}d", event);
    std::string jobId;
    int32_t ret = PrintManagerClient::GetInstance()->NotifyPrintServiceEvent(jobId, event);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void AddPrinterToDiscoveryNative(ani_env *env, ani_object printerInfo, ani_object callback)
{
    PRINT_HILOGI("enter AddPrinterToDiscoveryNative");
    PrinterInfo info = PrinterInfoAniHelper::ParsePrinterInformation(env, printerInfo);
    info.Dump();
    int32_t ret = PrintManagerClient::GetInstance()->AddPrinterToDiscovery(info);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void UpdatePrinterInDiscoveryNative(ani_env *env, ani_object printerInfo, ani_object callback)
{
    PRINT_HILOGI("enter UpdatePrinterInDiscoveryNative");
    PrinterInfo info = PrinterInfoAniHelper::ParsePrinterInformation(env, printerInfo);
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterInDiscovery(info);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void RemovePrinterFromDiscoveryNative(ani_env *env, ani_string printerId, ani_object callback)
{
    PRINT_HILOGI("enter RemovePrinterFromDiscoveryNative");
    std::string id;
    if (!GetStdString(env, printerId, id)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    PRINT_HILOGD("Printer ID: %{public}s", id.c_str());
    int32_t ret = PrintManagerClient::GetInstance()->RemovePrinterFromDiscovery(id);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, nullptr);
}

static void GetPrinterInformationByIdNative(ani_env *env, ani_string printerIdAni, ani_object callback)
{
    PRINT_HILOGI("enter GetPrinterInformationByIdNative");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::string printerId;
    if (!GetStdString(env, printerIdAni, printerId)) {
        PRINT_HILOGE("GetStdString fail");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
        return;
    }
    if (printerId.empty()) {
        PRINT_HILOGE("printerId is empty");
        ani_object stsErrCode = CreateStsError(env, E_PRINT_INVALID_PARAMETER);
        AsyncCallback(env, callback, stsErrCode, nullptr);
    }
    PRINT_HILOGD("printerId: %{public}s", printerId.c_str());
    PrinterInfo info;
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterInfoByPrinterId(printerId, info);
    ani_object stsErrCode = CreateStsError(env, ret);
    AsyncCallback(env, callback, stsErrCode, PrinterInfoAniHelper::CreatePrinterInformation(env, info));
}

static void OnPrinterStateChangeNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter OnPrinterStateChangeNative");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr = "printerStateChange";
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(env, callback);
    PrintManagerClient::GetInstance()->On("", typeStr, callbackWrapper);
}

static void OnJobStateChangeNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter OnJobStateChangeNative");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr = "jobStateChange";
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(env, callback);
    PrintManagerClient::GetInstance()->On("", typeStr, callbackWrapper);
}

static void OnExtInfoChangeNative(ani_env *env, ani_object callback)
{
    PRINT_HILOGI("enter OnExtInfoChangeNative");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr = "extInfoChange";
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(env, callback);
    PrintManagerClient::GetInstance()->On("", typeStr, callbackWrapper);
}

static void OnPrintTask(ani_env *env, ani_string type, ani_object callback, ani_object taskObj)
{
    PRINT_HILOGI("enter OnPrintTask");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        PRINT_HILOGE("GetStdString fail");
        return;
    }
    AniPrintTask* printTask = AniPrintTaskHelper::UnwrappPrintTask(env, taskObj);
    if (printTask == nullptr) {
        PRINT_HILOGE("printTask is a nullptr");
        return;
    }
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(env, callback);
    printTask->On(typeStr, callbackWrapper);
}

static void OffPrintTask(ani_env *env, ani_string type, ani_object callback, ani_object taskObj)
{
    PRINT_HILOGI("enter OffPrintTask");
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return;
    }
    std::string typeStr;
    if (!GetStdString(env, type, typeStr)) {
        PRINT_HILOGE("GetStdString fail");
        return;
    }
    AniPrintTask* printTask = AniPrintTaskHelper::UnwrappPrintTask(env, taskObj);
    if (printTask == nullptr) {
        PRINT_HILOGE("printTask is a nullptr");
        return;
    }
    OHOS::sptr<IPrintCallback> callbackWrapper = new (std::nothrow) PrintAniCallback(env, callback);
    printTask->Off(typeStr, callbackWrapper);
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
    PrintManagerClient::GetInstance()->Off("", typeStr);
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
    MakeNativeFunc("requestPrintPreviewCallbackNative", RequestPrintPreviewCallbackNative),
    MakeNativeFunc("requestPrintPreviewAsyncCallbackNative", RequestPrintPreviewAsyncCallbackNative),
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
    MakeNativeFunc("onPrintTask", OnPrintTask),
    MakeNativeFunc("offPrintTask", OffPrintTask),
    MakeNativeFunc("offNative", OffNative),
};

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    PRINT_HILOGI("enter ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        PRINT_HILOGE("vm or result is nullptr");
        return ANI_ERROR;
    }
    uint32_t status = 0;
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        PRINT_HILOGE("Unsupported ANI_VERSION_1, status = %{public}u", status);
        return ANI_ERROR;
    }

    ani_namespace ns {};
    const char* targetNamespace = "@ohos.print.print";
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