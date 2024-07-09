/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ohprint.h"
#include "print_manager_client.h"
#include "print_constant.h"
#include "print_log.h"
#include "ability_manager_client.h"
#include "print_util.h"
#include "print_callback.h"
#include "print_converter.h"
#include "print_helper.h"

using namespace OHOS::Print;

static Print_PrinterDiscoveryCallback printerDiscoverCallback = nullptr;
static Print_PrinterChangeCallback printerInfoCallback = nullptr;

static bool NativePrinterDiscoverFunction(uint32_t event, const PrinterInfo &info)
{
    PRINT_HILOGD("NativePrinterDiscoverFunction event: %{public}d, printerId: [%{public}s]",
        event, info.GetPrinterId().c_str());
    if (printerDiscoverCallback == nullptr) {
        PRINT_HILOGW("printerDiscoverCallback is null");
        return false;
    }
    Print_PrinterInfo *nativePrinterInfo = ConvertToNativePrinterInfo(info);
    if (nativePrinterInfo == nullptr) {
        PRINT_HILOGW("nativePrinterInfo is null.");
        return false;
    }
    printerDiscoverCallback(static_cast<Print_DiscoveryEvent>(event), nativePrinterInfo);
    OH_Print_ReleasePrinterInfo(nativePrinterInfo);
    nativePrinterInfo = nullptr;
    return true;
}

static bool NativePrinterInfoFunction(uint32_t event, const PrinterInfo &info)
{
    PRINT_HILOGD("NativePrinterInfoFunction event: [%{public}d, printerId: [%{public}s]",
        event, info.GetPrinterId().c_str());
    if (printerInfoCallback == nullptr) {
        PRINT_HILOGW("printerInfoCallback is null");
        return false;
    }
    Print_PrinterInfo *nativePrinterInfo = ConvertToNativePrinterInfo(info);
    if (nativePrinterInfo == nullptr) {
        PRINT_HILOGW("nativePrinterInfo is null.");
        return false;
    }
    printerInfoCallback(static_cast<Print_PrinterEvent>(event), nativePrinterInfo);
    OH_Print_ReleasePrinterInfo(nativePrinterInfo);
    nativePrinterInfo = nullptr;
    return true;
}

// 初始化
Print_ErrorCode OH_Print_Init()
{
    int32_t ret = PrintManagerClient::GetInstance()->Init();
    PRINT_HILOGI("OH_Print_Init ret = [%{public}d]", ret);
    return ConvertToNativeErrorCode(ret);
}

// 反初始化
Print_ErrorCode OH_Print_Release()
{
    int32_t ret = PrintManagerClient::GetInstance()->Release();
    PRINT_HILOGI("OH_Print_Release ret = [%{public}d]", ret);
    return ConvertToNativeErrorCode(ret);
}

Print_ErrorCode OH_Print_StartPrinterDiscovery(Print_PrinterDiscoveryCallback callback)
{
    printerDiscoverCallback = callback;
    std::vector<PrintExtensionInfo> extensionInfos;
    int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(extensionInfos);
    PRINT_HILOGI("QueryAllExtension ret = [%{public}d]", ret);
    if (ret == PRINT_ERROR_NONE) {
        std::vector<std::string> extensionIds;
        for (auto &extensionInfo : extensionInfos) {
            extensionIds.emplace_back(extensionInfo.GetExtensionId());
        }
        PRINT_HILOGI("extensionIds size = [%{public}zu]", extensionIds.size());
        PrintManagerClient::GetInstance()->SetNativePrinterChangeCallback(
            PRINTER_DISCOVER_EVENT_TYPE, NativePrinterDiscoverFunction);
        ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(extensionIds);
        PRINT_HILOGI("StartDiscoverPrinter ret = [%{public}d]", ret);
    }
    return ConvertToNativeErrorCode(ret);
}

Print_ErrorCode OH_Print_StopPrinterDiscovery()
{
    PrintManagerClient::GetInstance()->SetNativePrinterChangeCallback(PRINTER_DISCOVER_EVENT_TYPE, nullptr);
    printerDiscoverCallback = nullptr;
    int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
    PRINT_HILOGI("StopDiscoverPrinter ret = [%{public}d]", ret);
    return ConvertToNativeErrorCode(ret);
}

Print_ErrorCode OH_Print_ConnectPrinter(const char *printerId)
{
    if (printerId == nullptr) {
        PRINT_HILOGW("printerId is null.");
        return PRINT_ERROR_INVALID_PRINTER;
    }
    std::string nativePrinterId = printerId;
    int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(nativePrinterId);
    PRINT_HILOGI("ConnectPrinter ret = [%{public}d]", ret);
    return ConvertToNativeErrorCode(ret);
}

Print_ErrorCode OH_Print_StartPrintJob(const Print_PrintJob *printJob)
{
    if (printJob == nullptr) {
        PRINT_HILOGI("printJob is null.");
        return PRINT_ERROR_INVALID_PRINT_JOB;
    }
    PrintJob curPrintJob;
    int32_t ret = ConvertNativeJobToPrintJob(*printJob, curPrintJob);
    if (ret != 0) {
        PRINT_HILOGW("ConvertNativeJobToPrintJob fail.");
        return PRINT_ERROR_INVALID_PRINT_JOB;
    }
    ret = PrintManagerClient::GetInstance()->StartNativePrintJob(curPrintJob);
    PRINT_HILOGI("StartNativePrintJob ret = [%{public}d]", ret);
    return ConvertToNativeErrorCode(ret);
}

Print_ErrorCode OH_Print_RegisterPrinterChangeListener(Print_PrinterChangeCallback callback)
{
    printerInfoCallback = callback;
    PrintManagerClient::GetInstance()->SetNativePrinterChangeCallback(
        PRINTER_CHANGE_EVENT_TYPE, NativePrinterInfoFunction);
    return PRINT_ERROR_NONE;
}

void OH_Print_UnregisterPrinterChangeListener()
{
    PrintManagerClient::GetInstance()->SetNativePrinterChangeCallback(PRINTER_CHANGE_EVENT_TYPE, nullptr);
    printerInfoCallback = nullptr;
}

Print_ErrorCode OH_Print_QueryPrinterList(Print_StringList *printerIdList)
{
    if (printerIdList == nullptr) {
        PRINT_HILOGW("printerIdList is null.");
        return PRINT_ERROR_INVALID_PARAMETER;
    }
    std::vector<std::string> printerNameList;
    int32_t ret = PrintManagerClient::GetInstance()->QueryAddedPrinter(printerNameList);
    size_t count = printerNameList.size();
    PRINT_HILOGI("OH_Print_QueryPrinterList ret = %{public}d, count = %{public}zu.", ret, count);
    if (ret != 0 || count == 0) {
        return PRINT_ERROR_INVALID_PRINTER;
    }
    printerIdList->list = new (std::nothrow) char *[count];
    if (printerIdList->list == nullptr) {
        PRINT_HILOGW("printerIdList->list is null");
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    if (memset_s(printerIdList->list, count * sizeof(char *), 0, count * sizeof(char *)) != 0) {
        PRINT_HILOGW("memset_s fail");
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    for (size_t i = 0; i < count; ++i) {
        printerIdList->list[i] = CopyString(printerNameList[i]);
    }
    printerIdList->count = count;
    return PRINT_ERROR_NONE;
}

void OH_Print_ReleasePrinterList(Print_StringList *printerIdList)
{
    if (printerIdList == nullptr) {
        PRINT_HILOGW("printerIdList is null.");
        return;
    }
    if (printerIdList->list != nullptr) {
        for (uint32_t i = 0; i < printerIdList->count; i++) {
            SAFE_DELETE_ARRAY(printerIdList->list[i]);
        }
        SAFE_DELETE_ARRAY(printerIdList->list);
    }
    printerIdList->count = 0;
}

Print_ErrorCode OH_Print_QueryPrinterInfo(const char *printerId, Print_PrinterInfo **printerInfo)
{
    if (printerId == nullptr || printerInfo == nullptr) {
        PRINT_HILOGW("Invalid parameter.");
        return PRINT_ERROR_INVALID_PARAMETER;
    }
    std::string id(printerId);
    PrinterInfo info;
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterInfoByPrinterId(id, info);
    PRINT_HILOGI("QueryPrinterInfoByPrinterId ret = %{public}d", ret);
    if (info.GetPrinterId() != id || info.GetPrinterName().empty()) {
        PRINT_HILOGI("QueryPrinterInfoByPrinterId invalid printer");
        return PRINT_ERROR_INVALID_PRINTER;
    }
    Print_PrinterInfo *nativePrinterInfo = ConvertToNativePrinterInfo(info);
    if (nativePrinterInfo != nullptr) {
        if (ret != 0) {
            nativePrinterInfo->printerState = PRINTER_UNAVAILABLE;
        }
        *printerInfo = nativePrinterInfo;
    }
    return ConvertToNativeErrorCode(ret);
}

void OH_Print_ReleasePrinterInfo(Print_PrinterInfo *printerInfo)
{
    if (printerInfo == nullptr) {
        PRINT_HILOGW("printerInfo is null.");
        return;
    }
    ReleasePrinterInfo(*printerInfo);
    delete printerInfo;
    printerInfo = nullptr;
}

Print_ErrorCode OH_Print_LaunchPrinterManager()
{
    OHOS::AAFwk::AbilityManagerClient::GetInstance()->Connect();
    OHOS::AAFwk::Want want;
    want.SetElementName("com.huawei.hmos.spooler", "PrinterManagerAbility");
    auto ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    PRINT_HILOGI("StartAbility ret = %{public}d", ret);
    if (ret != 0) {
        PRINT_HILOGW("Failed to start PrinterManagerAbility");
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    PRINT_HILOGI("Succeed to start PrinterManagerAbility");
    return PRINT_ERROR_NONE;
}

int32_t OH_Print_LaunchPrinterPreference(const char* printerName, const char* printerId)
{
    std::string id = printerId;
    std::string name = printerName;
    std::string preferencesParam = id + "id&name" + name;  // 传参和应用层对齐
    OHOS::AAFwk::AbilityManagerClient::GetInstance()->Connect();
    OHOS::AAFwk::Want want;
    want.SetElementName(preferencesParam, "com.huawei.hmos.spooler", "PreferencesAbility", "");
    std::string thirdAppFlag = "window";
    want.SetParam("thirdApp", thirdAppFlag.c_str());
    auto ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    PRINT_HILOGI("StartAbility ret = %{public}d", ret);
    if (ret != 0) {
        PRINT_HILOGW("Failed to start PreferencesAbility");
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    PRINT_HILOGI("Succeed to start PreferencesAbility");
    return PRINT_ERROR_NONE;
}

Print_ErrorCode OH_Print_QueryPrinterProperties(
    const char *printerId, const Print_StringList *propertyKeyList, Print_PropertyList *propertyList)
{
    if (printerId == nullptr || propertyKeyList == nullptr || propertyKeyList->list == nullptr ||
        propertyList == nullptr) {
        PRINT_HILOGW("OH_Print_QueryPrinterProperties invalid parameter.");
        return PRINT_ERROR_INVALID_PRINTER;
    }
    std::vector<std::string> keyList;
    for (uint32_t i = 0; i < propertyKeyList->count; i++) {
        if (propertyKeyList->list[i] == nullptr) {
            continue;
        }
        std::string key(propertyKeyList->list[i]);
        if (key.empty()) {
            continue;
        }
        keyList.emplace_back(key);
    }
    if (keyList.size() == 0) {
        PRINT_HILOGW("empty keyList");
        return PRINT_ERROR_INVALID_PARAMETER;
    }
    std::vector<std::string> valueList;
    int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterProperties(printerId, keyList, valueList);
    PRINT_HILOGI("QueryPrinterProperties ret = %{public}d", ret);
    if (ret != 0) {
        PRINT_HILOGW("QueryPrinterProperties fail");
        return PRINT_ERROR_INVALID_PRINTER;
    }
    return ConvertStringVectorToPropertyList(valueList, propertyList);
}

void OH_Print_ReleasePrinterProperties(Print_PropertyList *propertyList)
{
    if (propertyList == nullptr) {
        PRINT_HILOGW("propertyList is null");
        return;
    }
    if (propertyList->list != nullptr) {
        for (uint32_t i = 0; i < propertyList->count; ++i) {
            SAFE_DELETE_ARRAY(propertyList->list[i].key);
            SAFE_DELETE_ARRAY(propertyList->list[i].value);
        }
        SAFE_DELETE_ARRAY(propertyList->list);
    }
    propertyList->count = 0;
}

Print_ErrorCode OH_Print_UpdatePrinterProperties(const char *printerId, const Print_PropertyList *propertyList)
{
    if (printerId == nullptr || propertyList->list == nullptr || propertyList->count <= 0) {
        PRINT_HILOGW("OH_Print_UpdatePrinterProperties invalid parameter.");
        return PRINT_ERROR_INVALID_PRINTER;
    }
    nlohmann::json settingJson;
    for (uint32_t i = 0; i < propertyList->count; i++) {
        settingJson[propertyList->list[i].key] = propertyList->list[i].value;
    }
    PRINT_HILOGW("OH_Print_UpdatePrinterProperties setting : %{public}s.", settingJson.dump().c_str());
    int32_t ret = PrintManagerClient::GetInstance()->SetPrinterPreference(printerId, settingJson.dump());
    if (ret != 0) {
        PRINT_HILOGW("SetPrinterPreference fail");
        return PRINT_ERROR_INVALID_PRINTER;
    }
    return PRINT_ERROR_NONE;
}

Print_ErrorCode OH_Print_RestorePrinterProperties(const char *printerId, const Print_StringList *propertyKeyList)
{
    return PRINT_ERROR_NONE;
}