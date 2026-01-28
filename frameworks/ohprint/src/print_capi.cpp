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

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "ability_context.h"
#include "iprint_adapter.h"
#include "print_attributes.h"
#include "print_manager_client.h"
#include "print_constant.h"
#include "print_log.h"
#include "ability_manager_client.h"
#include "print_util.h"
#include "print_callback.h"
#include "print_converter.h"
#include "print_helper.h"
#include "printer_preferences.h"
#include "refbase.h"
#include "ui_extension_context.h"
#include "print_json_util.h"

using namespace OHOS::Print;

static std::recursive_mutex g_printerDiscoverMutex;
static Print_PrinterDiscoveryCallback g_printerDiscoverCallback = nullptr;
static std::recursive_mutex g_printerChangeMutex;
static Print_PrinterChangeCallback g_printerChangeCallback = nullptr;

static bool NativePrinterDiscoverFunction(uint32_t event, const PrinterInfo &info)
{
    PRINT_HILOGD(
        "NativePrinterDiscoverFunction event: %{public}d, printerId: %{private}s", event, info.GetPrinterId().c_str());
    if (g_printerDiscoverCallback == nullptr) {
        PRINT_HILOGW("g_printerDiscoverCallback is null");
        return false;
    }
    Print_PrinterInfo *nativePrinterInfo = ConvertToNativePrinterInfo(info);
    if (nativePrinterInfo == nullptr) {
        PRINT_HILOGW("nativePrinterInfo is null.");
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lock(g_printerDiscoverMutex);
        if (g_printerDiscoverCallback != nullptr) {
            g_printerDiscoverCallback(static_cast<Print_DiscoveryEvent>(event), nativePrinterInfo);
        } else {
            PRINT_HILOGW("g_printerDiscoverCallback is null");
        }
    }
    OH_Print_ReleasePrinterInfo(nativePrinterInfo);
    nativePrinterInfo = nullptr;
    return true;
}

static bool NativePrinterInfoFunction(uint32_t event, const PrinterInfo &info)
{
    PRINT_HILOGD(
        "NativePrinterInfoFunction event: %{public}d, printerId: %{private}s", event, info.GetPrinterId().c_str());
    if (g_printerChangeCallback == nullptr) {
        PRINT_HILOGW("g_printerChangeCallback is null");
        return false;
    }
    Print_PrinterInfo *nativePrinterInfo = ConvertToNativePrinterInfo(info);
    if (nativePrinterInfo == nullptr) {
        PRINT_HILOGW("nativePrinterInfo is null.");
        return false;
    }
    {
        std::lock_guard<std::recursive_mutex> lock(g_printerChangeMutex);
        if (g_printerChangeCallback != nullptr) {
            g_printerChangeCallback(static_cast<Print_PrinterEvent>(event), nativePrinterInfo);
        } else {
            PRINT_HILOGW("g_printerChangeCallback is null");
        }
    }
    OH_Print_ReleasePrinterInfo(nativePrinterInfo);
    nativePrinterInfo = nullptr;
    return true;
}

static OHOS::Ace::UIContent *GetUIContent(void *context)
{
    if (context == nullptr) {
        PRINT_HILOGE("input context is null.");
        return nullptr;
    }

    auto weakContext = static_cast<std::weak_ptr<OHOS::AbilityRuntime::Context> *>(context);
    if (weakContext == nullptr) {
        PRINT_HILOGE("cast context to weak is null.");
        return nullptr;
    }
    auto sharedContext = weakContext->lock();
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(sharedContext);
    if (abilityContext != nullptr) {
        PRINT_HILOGD("get ability ui content.");
        return abilityContext->GetUIContent();
    }
    auto uiExtensionContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(sharedContext);
    if (uiExtensionContext != nullptr) {
        PRINT_HILOGD("get ui extension ui content.");
        return uiExtensionContext->GetUIContent();
    }
    PRINT_HILOGE("get ui content failed.");
    return nullptr;
}

static Print_PrintAttributes *NewPrintAttributes(void)
{
    auto attributes = new (std::nothrow) Print_PrintAttributes;
    if (attributes == nullptr) {
        PRINT_HILOGE("OH_Print new attributes failed.");
        return nullptr;
    }
    if (memset_s(attributes, sizeof(Print_PrintAttributes), 0, sizeof(Print_PrintAttributes)) != 0) {
        PRINT_HILOGE("OH_Print attributes memset failed.");
        delete attributes;
        return nullptr;
    }
    return attributes;
}

static void ReleasePrintAttributes(Print_PrintAttributes *attr)
{
    if (attr == nullptr) {
        PRINT_HILOGE("OH_Print release attr is null.");
        return;
    }
    if (attr->pageRange.pagesArray != nullptr) {
        delete[] attr->pageRange.pagesArray;
        attr->pageRange.pagesArray = nullptr;
    }
    delete attr;
}

static void SetInitRawPrinterInfo(const std::string &printerId,
                                  const std::string &printerName,
                                  const std::string &printerUri,
                                  PrinterInfo &info)
{
    PrinterCapability cap;
    std::vector<PrintPageSize> supportedPageSizes;
    PrintPageSize a4PageSize;
    if (PrintPageSize::FindPageSizeById("ISO_A4", a4PageSize)) {
        supportedPageSizes.push_back(a4PageSize);
    }
    cap.SetSupportedPageSize(supportedPageSizes);

    std::vector<uint32_t> supportedColorModes = {PrintColorMode::PRINT_COLOR_MODE_MONOCHROME};
    cap.SetSupportedColorMode(supportedColorModes);
    std::vector<uint32_t> supportedDuplexModes = {PrintDuplexMode::DUPLEX_MODE_NONE};
    cap.SetSupportedDuplexMode(supportedDuplexModes);
    std::vector<uint32_t> supportedQualities = {PrintQualityCode::PRINT_QUALITY_DRAFT};
    cap.SetSupportedQuality(supportedQualities);
    std::vector<uint32_t> supportedOrientations = {PrintOrientationMode::PRINT_ORIENTATION_MODE_PORTRAIT};
    cap.SetSupportedOrientation(supportedOrientations);

    info.SetPrinterId(printerId);
    info.SetPrinterName(printerName);
    info.SetUri(printerUri);
    info.SetCapability(cap);
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

Print_ErrorCode OH_Print_AddRawPrinter(const char *printerId, const char *printerName, const char *printerUri)
{
    PRINT_HILOGI("OH_Print_AddRawPrinter");
    if (printerId == nullptr || printerName == nullptr || printerUri == nullptr) {
        PRINT_HILOGI("OH_Print_AddRawPrinter invalid param.");
        return PRINT_ERROR_INVALID_PARAMETER;
    }

    PrinterInfo info;
    SetInitRawPrinterInfo(printerId, printerName, printerUri, info);
    int32_t ret = PrintManagerClient::GetInstance()->AddRawPrinter(info);
    if (ret != PRINT_ERROR_NONE) {
        PRINT_HILOGI("AddRawPrinter failed, ret = [%{public}d], printerId = [%{private}s].", ret, printerId);
        return ConvertToNativeErrorCode(ret);
    }

    return PRINT_ERROR_NONE;
}

Print_ErrorCode OH_Print_GetRawPrinterList(Print_StringList *printerIdList)
{
    if (printerIdList == nullptr) {
        PRINT_HILOGW("printerIdList is null.");
        return PRINT_ERROR_INVALID_PARAMETER;
    }
    std::vector<std::string> printerNameList;
    int32_t ret = PrintManagerClient::GetInstance()->QueryRawAddedPrinter(printerNameList);
    size_t count = printerNameList.size();
    PRINT_HILOGI("OH_Print_GetRawPrinterList ret = %{public}d, count = %{public}zu.", ret, count);
    if (ret != 0 || count == 0) {
        return PRINT_ERROR_INVALID_PRINTER;
    }
    printerIdList->list = new (std::nothrow) char *[count];
    if (printerIdList->list == nullptr) {
        PRINT_HILOGW("printerIdList->list is null");
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    if (memset_s(printerIdList->list, count * sizeof(char *), 0, count * sizeof(char *)) != 0) {
        delete[] printerIdList->list;
        printerIdList->list = nullptr;
        PRINT_HILOGW("memset_s fail");
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    for (size_t i = 0; i < count; ++i) {
        printerIdList->list[i] = CopyString(printerNameList[i]);
    }
    printerIdList->count = count;
    return PRINT_ERROR_NONE;
}

Print_ErrorCode OH_Print_StartPrinterDiscovery(Print_PrinterDiscoveryCallback callback)
{
    PRINT_HILOGI("OH_Print_StartPrinterDiscovery");
    {
        std::lock_guard<std::recursive_mutex> lock(g_printerDiscoverMutex);
        g_printerDiscoverCallback = callback;
    }
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
    PRINT_HILOGI("OH_Print_StopPrinterDiscovery");
    PrintManagerClient::GetInstance()->SetNativePrinterChangeCallback(PRINTER_DISCOVER_EVENT_TYPE, nullptr);
    {
        std::lock_guard<std::recursive_mutex> lock(g_printerDiscoverMutex);
        g_printerDiscoverCallback = nullptr;
    }
    return PRINT_ERROR_NONE;
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
    PRINT_HILOGI("OH_Print_RegisterPrinterChangeListener");
    {
        std::lock_guard<std::recursive_mutex> lock(g_printerChangeMutex);
        g_printerChangeCallback = callback;
    }
    PrintManagerClient::GetInstance()->SetNativePrinterChangeCallback(
        PRINTER_CHANGE_EVENT_TYPE, NativePrinterInfoFunction);
    return PRINT_ERROR_NONE;
}

void OH_Print_UnregisterPrinterChangeListener()
{
    PRINT_HILOGI("OH_Print_UnregisterPrinterChangeListener");
    PrintManagerClient::GetInstance()->SetNativePrinterChangeCallback(PRINTER_CHANGE_EVENT_TYPE, nullptr);
    {
        std::lock_guard<std::recursive_mutex> lock(g_printerChangeMutex);
        g_printerChangeCallback = nullptr;
    }
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
        delete[] printerIdList->list;
        printerIdList->list = nullptr;
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
    PRINT_HILOGW("Ability context is needed to start ability");
    return PRINT_ERROR_GENERIC_FAILURE;
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
    Json::Value settingJson;
    for (uint32_t i = 0; i < propertyList->count; i++) {
        settingJson[propertyList->list[i].key] = propertyList->list[i].value;
    }
    PRINT_HILOGD(
        "OH_Print_UpdatePrinterProperties setting : %{public}s.", (PrintJsonUtil::WriteString(settingJson)).c_str());
    PrinterPreferences preferences;
    preferences.ConvertJsonToPrinterPreferences(settingJson);
    int32_t ret = PrintManagerClient::GetInstance()->SetPrinterPreference(printerId, preferences);
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

namespace {
class PrintDocumentAdapterWrapper : public PrintDocumentAdapter {
public:
    explicit PrintDocumentAdapterWrapper(Print_PrintDocCallback PrintCallback);
    void onStartLayoutWrite(const std::string &jobId, const PrintAttributes &oldAttrs, const PrintAttributes &newAttrs,
        uint32_t fd, std::function<void(std::string, uint32_t)> writeResultCallback) override;
    void onJobStateChanged(const std::string &jobId, uint32_t state) override;
    void OnWriteResultCallback(const std::string &jobId, uint32_t code);
    static void WriteResultCallback(const char *jobId, uint32_t code);

private:
    Print_PrintAttributes *BuildPrintAttributes(const PrintAttributes &attrs);

    Print_PrintDocCallback printCb_;
    std::function<void(std::string, uint32_t)> writeResultCb_;
    static std::mutex printDocMutex_;
    static std::map<std::string, PrintDocumentAdapterWrapper *> printDocAdapterMap_;
};

std::mutex PrintDocumentAdapterWrapper::printDocMutex_;
std::map<std::string, PrintDocumentAdapterWrapper *> PrintDocumentAdapterWrapper::printDocAdapterMap_;

PrintDocumentAdapterWrapper::PrintDocumentAdapterWrapper(Print_PrintDocCallback PrintCallback)
{
    printCb_ = PrintCallback;
}

void PrintDocumentAdapterWrapper::onStartLayoutWrite(const std::string &jobId, const PrintAttributes &oldAttrs,
    const PrintAttributes &newAttrs, uint32_t fd, std::function<void(std::string, uint32_t)> writeResultCallback)
{
    if (printCb_.startLayoutWriteCb == nullptr) {
        PRINT_HILOGE("OH_Print start layout callback is null.");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(printDocMutex_);
        if (printDocAdapterMap_.find(jobId) == printDocAdapterMap_.end()) {
            printDocAdapterMap_.insert({jobId, this});
        }
    }
    writeResultCb_ = writeResultCallback;
    auto oldAttrsPtr = BuildPrintAttributes(oldAttrs);
    auto newAttrsPtr = BuildPrintAttributes(newAttrs);
    printCb_.startLayoutWriteCb(
        jobId.c_str(), fd, oldAttrsPtr, newAttrsPtr, PrintDocumentAdapterWrapper::WriteResultCallback);
    ReleasePrintAttributes(oldAttrsPtr);
    ReleasePrintAttributes(newAttrsPtr);
    oldAttrsPtr = nullptr;
    newAttrsPtr = nullptr;
}

void PrintDocumentAdapterWrapper::onJobStateChanged(const std::string &jobId, uint32_t state)
{
    if (printCb_.jobStateChangedCb == nullptr) {
        PRINT_HILOGE("OH_Print job state callback is null.");
        return;
    }
    if (state == PRINT_DOC_ADAPTER_PREVIEW_ABILITY_DESTROY_FOR_CANCELED ||
        state == PRINT_DOC_ADAPTER_PREVIEW_ABILITY_DESTROY_FOR_STARTED) {
        std::lock_guard<std::mutex> lock(printDocMutex_);
        printDocAdapterMap_.erase(jobId);
    }
    printCb_.jobStateChangedCb(jobId.c_str(), state);
}

void PrintDocumentAdapterWrapper::WriteResultCallback(const char *jobId, uint32_t code)
{
    if (jobId == nullptr) {
        PRINT_HILOGE("OH_Print write result callback param is null.");
        return;
    }
    std::string jobIdStr = jobId;
    PrintDocumentAdapterWrapper *wrapper = nullptr;
    {
        std::lock_guard<std::mutex> lock(printDocMutex_);
        auto iter = printDocAdapterMap_.find(jobId);
        if (iter != printDocAdapterMap_.end()) {
            wrapper = iter->second;
        }
    }
    if (wrapper == nullptr) {
        PRINT_HILOGE("OH_Print get wrapper failed.");
        return;
    }
    wrapper->OnWriteResultCallback(jobIdStr, code);
}

void PrintDocumentAdapterWrapper::OnWriteResultCallback(const std::string &jobId, uint32_t code)
{
    if (writeResultCb_ == nullptr) {
        PRINT_HILOGE("OH_Print write callback is null.");
        return;
    }
    writeResultCb_(jobId, code);
}

Print_PrintAttributes *PrintDocumentAdapterWrapper::BuildPrintAttributes(const PrintAttributes &attrs)
{
    auto attributesRaw = NewPrintAttributes();
    if (attributesRaw == nullptr) {
        PRINT_HILOGE("OH_Print attribute raw is null.");
        return nullptr;
    }
    std::unique_ptr<Print_PrintAttributes> attributes(attributesRaw);
    attributes->copyNumber = attrs.GetCopyNumber();
    Print_Range printRange;
    PrintRange range;
    attrs.GetPageRange(range);
    printRange.startPage = range.GetStartPage();
    printRange.endPage = range.GetEndPage();
    std::vector<uint32_t> pages;
    range.GetPages(pages);
    auto pageArray = new (std::nothrow) uint32_t[pages.size()];
    if (pageArray == nullptr) {
        PRINT_HILOGE("OH_Print pages array is null.");
        return nullptr;
    }
    std::copy(pages.begin(), pages.end(), pageArray);
    printRange.pagesArray = pageArray;
    printRange.pagesArrayLen = pages.size();
    attributes->pageRange = printRange;
    attributes->isSequential = attrs.GetIsSequential();
    Print_PageSize printPageSize;
    PrintPageSize pageSize;
    attrs.GetPageSize(pageSize);
    printPageSize.width = pageSize.GetWidth();
    printPageSize.height = pageSize.GetHeight();
    attributes->pageSize = printPageSize;
    attributes->isLandscape = attrs.GetIsLandscape();
    attributes->colorMode = attrs.GetColorMode();
    attributes->duplexMode = attrs.GetDuplexMode();
    Print_Margin printMargin;
    PrintMargin margin;
    attrs.GetMargin(margin);
    printMargin.topMargin = margin.GetTop();
    printMargin.bottomMargin = margin.GetBottom();
    printMargin.leftMargin = margin.GetLeft();
    printMargin.rightMargin = margin.GetRight();
    attributes->pageMargin = printMargin;
    return attributes.release();
}
}  // namespace

Print_ErrorCode OH_Print_StartPrintByNative(
    const char *printJobName, Print_PrintDocCallback printDocCallback, void *context)
{
    if (printJobName == nullptr) {
        PRINT_HILOGE("OH_Print start print native print job name is null.");
        return PRINT_ERROR_INVALID_PARAMETER;
    }

    auto uiContent = GetUIContent(context);
    if (uiContent == nullptr) {
        PRINT_HILOGE("OH_Print start print native ui content is null.");
        return PRINT_ERROR_INVALID_PARAMETER;
    }
    auto wrapper = new (std::nothrow) PrintDocumentAdapterWrapper(printDocCallback);
    if (wrapper == nullptr) {
        PRINT_HILOGE("OH_Print start print print doc adapter is null.");
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    OHOS::sptr<IPrintCallback> printCb = new (std::nothrow) PrintCallback(wrapper);
    if (printCb == nullptr) {
        PRINT_HILOGE("OH_Print start print print callback is null.");
        delete wrapper;
        return PRINT_ERROR_GENERIC_FAILURE;
    }
    auto attributes = std::make_shared<PrintAttributes>();
    std::string printJobNameStr = printJobName;
    int32_t ret = PrintManagerClient::GetInstance()->Print(printJobNameStr, printCb, attributes, uiContent);
    if (ret != PRINT_ERROR_NONE) {
        PRINT_HILOGE("OH_Print start print start failed, error code : %{public}d.", ret);
        return ConvertToNativeErrorCode(ret);
    }
    return PRINT_ERROR_NONE;
}
