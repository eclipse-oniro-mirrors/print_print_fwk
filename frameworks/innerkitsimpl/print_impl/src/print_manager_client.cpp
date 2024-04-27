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

#include "print_manager_client.h"

#ifdef PDFIUM_ENABLE
#include "fpdf_edit.h"
#include "cpp/fpdf_scopers.h"
#include "image_diff_png.h"
#include "iostream"
#include "sys/stat.h"
#include "unistd.h"
#endif // PDFIUM_ENABLE

#include "iservice_registry.h"
#include "print_constant.h"
#include "print_extension_callback_stub.h"
#include "print_log.h"
#include "print_sync_load_callback.h"
#include "print_utils.h"
#include "system_ability_definition.h"

namespace OHOS::Print {
std::mutex PrintManagerClient::instanceLock_;
sptr<PrintManagerClient> PrintManagerClient::instance_ = nullptr;

PrintManagerClient::PrintManagerClient() : printServiceProxy_(nullptr), deathRecipient_(nullptr) {}

PrintManagerClient::~PrintManagerClient() {}

sptr<PrintManagerClient> PrintManagerClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new PrintManagerClient;
        }
    }
    return instance_;
}

bool PrintManagerClient::GetPrintServiceProxy()
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    if (printServiceProxy_ != nullptr) {
        PRINT_HILOGD("printServiceProxy_ is not null");
        return true;
    }
    bool result = false;
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager != nullptr) {
        auto systemAbility = systemAbilityManager->GetSystemAbility(PRINT_SERVICE_ID, "");
        if (systemAbility != nullptr) {
            deathRecipient_ = new (std::nothrow) PrintSaDeathRecipient();
            if (deathRecipient_ != nullptr) {
                systemAbility->AddDeathRecipient(deathRecipient_);
                printServiceProxy_ = iface_cast<IPrintService>(systemAbility);
                PRINT_HILOGD("Getting PrintManagerClientProxy succeeded.");
                result = true;
            }
        }
    }
    PRINT_HILOGD("Getting PrintManagerClientProxy ret[%{public}d].", result);
    return result;
}

void PrintManagerClient::OnRemoteSaDied(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(proxyLock_);
    PRINT_HILOGD("start");
    if (remote == nullptr) {
        PRINT_HILOGE("remote is nullptr");
        return;
    }
    if (printServiceProxy_ == nullptr) {
        PRINT_HILOGE("printServiceProxy_ is null");
        return;
    }
    auto serviceRemote = printServiceProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        PRINT_HILOGD("need reset");
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        printServiceProxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
}

int32_t PrintManagerClient::StartPrint(const std::vector<std::string> &fileList,
    const std::vector<uint32_t> &fdList, std::string &taskId)
{
    PRINT_HILOGD("PrintManagerClient StartPrint start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartPrint(fileList, fdList, taskId);
        PRINT_HILOGD("PrintManagerClient StartPrint out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StartPrint(const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList,
    std::string &taskId, const sptr<IRemoteObject> &token)
{
    PRINT_HILOGD("PrintManagerClient StartPrint start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartPrint(fileList, fdList, taskId, token);
        PRINT_HILOGD("PrintManagerClient StartPrint out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StopPrint(const std::string &taskId)
{
    PRINT_HILOGD("PrintManagerClient StopPrint start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StopPrint(taskId);
        PRINT_HILOGD("PrintManagerClient StopPrint out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::ConnectPrinter(const std::string &printerId)
{
    PRINT_HILOGD("PrintManagerClient ConnectPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->ConnectPrinter(printerId);
        PRINT_HILOGD("PrintManagerClient ConnectPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::DisconnectPrinter(const std::string &printerId)
{
    PRINT_HILOGD("PrintManagerClient DisconnectPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->DisconnectPrinter(printerId);
        PRINT_HILOGD("PrintManagerClient DisconnectPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryAllExtension(std::vector<PrintExtensionInfo> &extensionInfos)
{
    PRINT_HILOGD("PrintManagerClient QueryAllExtension start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryAllExtension(extensionInfos);
        PRINT_HILOGD("PrintManagerClient QueryAllExtension out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StartDiscoverPrinter(const std::vector<std::string> &extensionList)
{
    PRINT_HILOGD("PrintManagerClient StartDiscoverPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartDiscoverPrinter(extensionList);
        PRINT_HILOGD("PrintManagerClient StartDiscoverPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StopDiscoverPrinter()
{
    PRINT_HILOGD("PrintManagerClient StopDiscoverPrinter start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StopDiscoverPrinter();
        PRINT_HILOGD("PrintManagerClient StopDiscoverPrinter out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::StartPrintJob(const PrintJob &jobinfo)
{
    PRINT_HILOGD("PrintManagerClient StartPrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->StartPrintJob(jobinfo);
        PRINT_HILOGD("PrintManagerClient StartPrintJob out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::CancelPrintJob(const std::string &jobId)
{
    PRINT_HILOGD("PrintManagerClient CancelPrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->CancelPrintJob(jobId);
        PRINT_HILOGD("PrintManagerClient CancelPrintJob out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::AddPrinters(const std::vector<PrinterInfo> &printerInfos)
{
    PRINT_HILOGD("PrintManagerClient AddPrinters start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->AddPrinters(printerInfos);
        PRINT_HILOGD("PrintManagerClient AddPrinters out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RemovePrinters(const std::vector<std::string> &printerIds)
{
    PRINT_HILOGD("PrintManagerClient RemovePrinters start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RemovePrinters(printerIds);
        PRINT_HILOGD("PrintManagerClient RemovePrinters out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrinters(const std::vector<PrinterInfo> &printerInfos)
{
    PRINT_HILOGD("PrintManagerClient UpdatePrinters start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrinters(printerInfos);
        PRINT_HILOGD("PrintManagerClient UpdatePrinters out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrinterState(const std::string &printerId, uint32_t state)
{
    PRINT_HILOGD("PrintManagerClient UpdatePrinterState start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrinterState(printerId, state);
        PRINT_HILOGD("PrintManagerClient UpdatePrinterState out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdatePrintJobState(const std::string &jobId, uint32_t state, uint32_t subState)
{
    PRINT_HILOGD("PrintManagerClient UpdatePrintJobState start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdatePrintJobState(jobId, state, subState);
        PRINT_HILOGD("PrintManagerClient UpdatePrintJobState out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UpdateExtensionInfo(const std::string &extInfo)
{
    PRINT_HILOGD("PrintManagerClient UpdateExtensionInfo start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UpdateExtensionInfo(extInfo);
        PRINT_HILOGD("PrintManagerClient UpdateExtensionInfo out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RequestPreview(const PrintJob &jobinfo, std::string &previewResult)
{
    PRINT_HILOGD("PrintManagerClient RequestPreview start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RequestPreview(jobinfo, previewResult);
        PRINT_HILOGD("PrintManagerClient RequestPreview out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryPrinterCapability(const std::string &printerId)
{
    PRINT_HILOGD("PrintManagerClient QueryPrinterCapability start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryPrinterCapability(printerId);
        PRINT_HILOGD("PrintManagerClient QueryPrinterCapability out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryAllPrintJob(std::vector<PrintJob> &printJobs)
{
    PRINT_HILOGD("PrintManagerClient QueryAllPrintJob start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryAllPrintJob(printJobs);
        PRINT_HILOGD("PrintManagerClient QueryAllPrintJob out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryPrintJobById(std::string &printJobId, PrintJob &printjob)
{
    PRINT_HILOGD("PrintManagerClient QueryPrintJobById start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryPrintJobById(printJobId, printjob);
        PRINT_HILOGD("PrintManagerClient QueryPrintJobById out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
    const std::string &printerMake)
{
    PRINT_HILOGD("PrintManagerClient AddPrinterToCups start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->AddPrinterToCups(printerUri, printerName, printerMake);
        PRINT_HILOGD("PrintManagerClient AddPrinterToCups out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
    PrinterCapability &printerCaps)
{
    PRINT_HILOGD("PrintManagerClient QueryPrinterCapabilityByUri start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
        PRINT_HILOGD("PrintManagerClient QueryPrinterCapabilityByUri out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::On(const std::string &taskId, const std::string &type, const sptr<IPrintCallback> &listener)
{
    PRINT_HILOGD("PrintManagerClient On start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->On(taskId, type, listener);
        PRINT_HILOGD("PrintManagerClient On out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::Off(const std::string &taskId, const std::string &type)
{
    PRINT_HILOGD("PrintManagerClient Off start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->Off(taskId, type);
        PRINT_HILOGD("PrintManagerClient Off out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const std::shared_ptr<PrintAttributes> &printAttributes)
{
    std::string taskId = "";
    return Print(printJobName, listener, *printAttributes, taskId, nullptr);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const std::shared_ptr<PrintAttributes> &printAttributes, void* contextToken)
{
    std::string taskId = "";
    return Print(printJobName, listener, *printAttributes, taskId, contextToken);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const PrintAttributes &printAttributes)
{
    std::string taskId = "";
    return Print(printJobName, listener, printAttributes, taskId, nullptr);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const PrintAttributes &printAttributes, void* contextToken)
{
    std::string taskId = "";
    return Print(printJobName, listener, printAttributes, taskId, contextToken);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const PrintAttributes &printAttributes, std::string &taskId)
{
    return Print(printJobName, listener, printAttributes, taskId, nullptr);
}

int32_t PrintManagerClient::Print(const std::string &printJobName, const sptr<IPrintCallback> &listener,
    const PrintAttributes &printAttributes, std::string &taskId, void* contextToken)
{
    auto func = [printJobName, listener, printAttributes, &taskId, contextToken](sptr<IPrintService> serviceProxy) {
        serviceProxy->On("", PRINT_CALLBACK_ADAPTER, listener);
        sptr<IRemoteObject> token = static_cast<IRemoteObject*>(contextToken);
        return serviceProxy->PrintByAdapter(printJobName, printAttributes, taskId, token);
    };
    return CALL_COMMON_CLIENT(func);
}

int32_t PrintManagerClient::StartGetPrintFile(const std::string &jobId, const PrintAttributes &printAttributes,
    const uint32_t fd)
{
    auto func = [jobId, printAttributes, fd](sptr<IPrintService> serviceProxy) {
        return serviceProxy->StartGetPrintFile(jobId, printAttributes, fd);
    };
    return CALL_COMMON_CLIENT(func);
}

int32_t PrintManagerClient::NotifyPrintService(const std::string &jobId, const std::string &type)
{
    PRINT_HILOGD("PrintManagerClient NotifyPrintService start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->NotifyPrintService(jobId, type);
        PRINT_HILOGD("PrintManagerClient NotifyPrintService out ret = [%{public}d].", ret);
    }
    return ret;
}

#ifdef PDFIUM_ENABLE
#ifndef INT_MAX
#define INT_MAX 2147483647
#endif
static constexpr const int FPDF_CONFIG_VERSION = 2;
static constexpr const double SCALING_RATE = 300.0 / 72.0;
static int pdfiumInitRequestCount = 0;

static void initializeLibraryIfNeeded()
{
    if (pdfiumInitRequestCount == 0) {
        // Init
        FPDF_LIBRARY_CONFIG config;
        config.version = FPDF_CONFIG_VERSION;
        config.m_pUserFontPaths = NULL;
        config.m_pIsolate = NULL;
        config.m_v8EmbedderSlot = 0;
        FPDF_InitLibraryWithConfig(&config);
    }
    pdfiumInitRequestCount++;
}

static void destroyLibraryIfNeeded()
{
    if (pdfiumInitRequestCount == 1) {
        FPDF_DestroyLibrary();
    }
    pdfiumInitRequestCount--;
}

static FPDF_DOCUMENT LoadPdfFile(const std::string filePath)
{
    initializeLibraryIfNeeded();
    // Load pdf file
    FPDF_DOCUMENT doc = FPDF_LoadDocument(filePath.c_str(), nullptr);
    return doc;
}

static bool CheckDimensions(int stride, int width, int height)
{
    if (stride <= 0 || width <= 0 || height <= 0) {
        return false;
    }
    if (height > 0 && stride > INT_MAX / height) {
        return false;
    }
    return true;
}

static std::vector<uint8_t> EncodePng(pdfium::span<const uint8_t> input, int height, int width, int format, int stride)
{
    std::vector<uint8_t> png;
    switch (format) {
        case FPDFBitmap_Unknown:
            break;
        case FPDFBitmap_Gray:
            PRINT_HILOGD("EncodePng FPDFBitmap_Gray\n");
            png = image_diff_png::EncodeGrayPNG(input, width, height, stride);
            break;
        case FPDFBitmap_BGR:
            PRINT_HILOGD("EncodePng FPDFBitmap_BGR\n");
            png = image_diff_png::EncodeBGRPNG(input, width, height, stride);
            break;
        case FPDFBitmap_BGRx:
            PRINT_HILOGD("EncodePng FPDFBitmap_BGRx\n");
            png = image_diff_png::EncodeBGRAPNG(input, width, height, stride, true);
            break;
        case FPDFBitmap_BGRA:
            PRINT_HILOGD("EncodePng FPDFBitmap_BGRA\n");
            png = image_diff_png::EncodeBGRAPNG(input, width, height, stride, false);
            break;
    }
    return png;
}

static bool WritePng(std::string imagePath, void *buffer, int width, int height, int stride)
{
    if (!CheckDimensions(stride, width, height)) {
        return false;
    }
    auto input = pdfium::make_span(static_cast<uint8_t *>(buffer), stride * height);
    std::vector<uint8_t> png_encoding = EncodePng(input, height, width, FPDFBitmap_BGRA, stride);
    if (png_encoding.empty()) {
        PRINT_HILOGE("Failed to convert bitmap to PNG\n");
        return false;
    }
    FILE *fp = fopen(imagePath.c_str(), "wb");
    if (!fp) {
        PRINT_HILOGE("Failed to open %s for output\n", imagePath.c_str());
        return false;
    }
    size_t bytes_written = fwrite(&png_encoding.front(), 1, png_encoding.size(), fp);
    if (bytes_written != png_encoding.size()) {
        PRINT_HILOGE("Failed to write to %s\n", imagePath.c_str());
    }
    (void)fclose(fp);
    return true;
}

static std::string GetImagePathByIndex(std::string basePngName, int32_t pageIndex)
{
    std::string imagePath = basePngName + "-" + std::to_string(pageIndex) + ".png";
    return imagePath;
}

static ScopedFPDFBitmap BitmapInit(FPDF_PAGE page, uint32_t width, uint32_t height)
{
    int alpha = FPDFPage_HasTransparency(page) ? 1 : 0;
    ScopedFPDFBitmap bitmap(FPDFBitmap_Create(width, height, alpha));
    FPDF_DWORD fill_color = alpha ? 0x00000000 : 0xFFFFFFFF;
    FPDFBitmap_FillRect(bitmap.get(), 0, 0, width, height, fill_color);
    int rotation = 0;
    int flags = FPDF_ANNOT;
    FPDF_RenderPageBitmap(bitmap.get(), page, 0, 0, width, height, rotation, flags);
    return bitmap;
}

int32_t PrintManagerClient::PdfRenderInit(const std::string filePath, const std::string sandBoxPath,
    std::string &basePngName, int32_t &pageCount, FPDF_DOCUMENT &doc)
{
    if (access(sandBoxPath.c_str(), F_OK) != 0) {
        PRINT_HILOGE("PdfRenderInit SandBoxPath can't be opened.");
        return E_PRINT_INVALID_PARAMETER;
    }
    // Create floder when the floder isn't exist;
    std::string floderPath = sandBoxPath + "/preview/";
    if (access(floderPath.c_str(), F_OK) != 0) {
        mkdir(floderPath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
        if (access(floderPath.c_str(), F_OK) == 0) {
            PRINT_HILOGD("PdfRenderInit Create floder %{public}s success.", floderPath.c_str());
        }
    }
    PRINT_HILOGD("PdfRenderInit SandBoxPath:%{public}s.", sandBoxPath.c_str());
    doc = LoadPdfFile(filePath);
    if (doc == NULL) {
        PRINT_HILOGE("PdfRenderInit Pdfium LoadPdfFile failed.");
        return E_PRINT_FILE_IO;
    }
    size_t filename_start = filePath.find_last_of("/");
    size_t filename_end = filePath.find_last_of(".");
    if (filename_start == filePath.npos || filename_end == filePath.npos) {
        PRINT_HILOGE("PdfRenderInit Find filename failed.");
        return E_PRINT_INVALID_PARAMETER;
    }
    std::string filename = filePath.substr(filename_start + 1, filename_end - filename_start - 1);
    basePngName = floderPath + filename;
    PRINT_HILOGD("PdfRenderInit basePngName:%{public}s.", basePngName.c_str());
    // Get pdf file pageCount
    pageCount = FPDF_GetPageCount(doc);
    if (pageCount == 0) {
        PRINT_HILOGE("PdfRenderInit Pdfium GetPageCount failed.");
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGD("PdfRenderInit filePath:%{public}s count %{public}d.", filePath.c_str(), pageCount);
    return E_PRINT_NONE;
}

int32_t PrintManagerClient::PdfRenderDestroy(const std::string basePngName, const int32_t pageCount,
    FPDF_DOCUMENT &doc)
{
    for (int32_t pageIndex = 0; pageIndex < pageCount; pageIndex++) {
        std::string imagePath = GetImagePathByIndex(basePngName, pageIndex);
        if (imagePath.empty()) {
            PRINT_HILOGE("PdfRenderDestroy This imagePath is empty.");
            return E_PRINT_INVALID_PARAMETER;
        }
        if (access(imagePath.c_str(), F_OK) == 0) {
            PRINT_HILOGD("PdfRenderDestroy Start delete floder %{public}s.", imagePath.c_str());
            unlink(imagePath.c_str());
        }
    }
    FPDF_CloseDocument(doc);
    destroyLibraryIfNeeded();
    return E_PRINT_NONE;
}

int32_t PrintManagerClient::GetPdfPageSize(const int32_t pageIndex, uint32_t &width, uint32_t &height,
    FPDF_DOCUMENT &doc)
{
    if (doc == NULL) {
        PRINT_HILOGE("GetPdfPageSize loaded doc is null.");
        return E_PRINT_FILE_IO;
    }
    // Get page of pageIndex from pdf
    FPDF_PAGE page = FPDF_LoadPage(doc, pageIndex);
    if (page == NULL) {
        PRINT_HILOGE("GetPdfPageSize Pdfium FPDF_LoadPage failed.");
        return E_PRINT_FILE_IO;
    }
    // Get pdf's width and length
    width = static_cast<uint32_t>(FPDF_GetPageWidth(page) * SCALING_RATE);
    height = static_cast<uint32_t>(FPDF_GetPageHeight(page) * SCALING_RATE);
    PRINT_HILOGD("GetPdfPageSize page width: %{public}d, height: %{public}d.", width, height);
    FPDF_ClosePage(page);
    return E_PRINT_NONE;
}

int32_t PrintManagerClient::RenderPdfToPng(const std::string basePngName, const int32_t pageIndex,
    std::string &imagePath, FPDF_DOCUMENT &doc)
{
    if (doc == NULL) {
        PRINT_HILOGE("RenderPdfToPng  loaded doc is null..");
        return E_PRINT_FILE_IO;
    }
    imagePath = GetImagePathByIndex(basePngName, pageIndex);
    if (imagePath.empty()) {
        PRINT_HILOGE("RenderPdfToPng This imagePath is empty.");
        return E_PRINT_INVALID_PARAMETER;
    }
    if (access(imagePath.c_str(), F_OK) != -1) {
        PRINT_HILOGD("RenderPdfToPng This page image is exist %{public}s.", imagePath.c_str());
        return E_PRINT_NONE;
    }
    // Get pdf file pageCount.
    int pageCount = FPDF_GetPageCount(doc);
    if (pageCount == 0) {
        PRINT_HILOGE("RenderPdfToPng Pdfium GetPageCount failed.");
        return E_PRINT_INVALID_PARAMETER;
    }
    PRINT_HILOGD("RenderPdfToPng %{public}s count %{public}d.", basePngName.c_str(), pageCount);
    // Get page of pageIndex from pdf.
    FPDF_PAGE page = FPDF_LoadPage(doc, pageIndex);
    if (page == NULL) {
        PRINT_HILOGE("RenderPdfToPng Pdfium FPDF_LoadPage failed.");
        return E_PRINT_FILE_IO;
    }
    // Get pdf's width and length.
    uint32_t width = static_cast<uint32_t>(FPDF_GetPageWidth(page) * SCALING_RATE);
    uint32_t height = static_cast<uint32_t>(FPDF_GetPageHeight(page) * SCALING_RATE);
    if (width <= 0 || height <= 0) {
        PRINT_HILOGE("RenderPdfToPng pdfium get page's width or height error.");
        return E_PRINT_GENERIC_FAILURE;
    }
    PRINT_HILOGD("RenderPdfToPng  page width: %{public}d height: %{public}d.", width, height);
    ScopedFPDFBitmap bitmap = BitmapInit(page, width, height);
    FPDF_ClosePage(page);
    if (bitmap) {
        void *buffer = FPDFBitmap_GetBuffer(bitmap.get());
        int stride = FPDFBitmap_GetStride(bitmap.get());
        PRINT_HILOGD("RenderPdfToPng bitmap stride %{public}d.", stride);
        if (!WritePng(imagePath, buffer, width, height, stride)) {
            unlink(imagePath.c_str());
        }
    } else {
        PRINT_HILOGE("RenderPdfToPng FPDF_RenderPageBitmap error.");
        return E_PRINT_GENERIC_FAILURE;
    }
    return E_PRINT_NONE;
}
#endif // PDFIUM_ENABLE

int32_t PrintManagerClient::runBase(const char* callerFunName, std::function<int32_t(sptr<IPrintService>)> func)
{
    PRINT_HILOGI("PrintManagerClient %{public}s start.", callerFunName);
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (!LoadServer()) {
        PRINT_HILOGE("LoadServer error");
        return ret;
    }

    if (!GetPrintServiceProxy()) {
        PRINT_HILOGE("GetPrintServiceProxy error");
        return ret;
    }

    ret = func(printServiceProxy_);
    PRINT_HILOGI("PrintManagerClient %{public}s end ret = [%{public}d].", callerFunName, ret);
    return ret;
}

int32_t PrintManagerClient::RegisterExtCallback(const std::string &extensionId,
    uint32_t callbackId, PrintExtCallback cb)
{
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }
    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    std::string extensionCID = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto it = extCallbackMap_.find(extensionCID);
    if (it == extCallbackMap_.end()) {
        callbackStub = new (std::nothrow) PrintExtensionCallbackStub;
        if (callbackStub != nullptr) {
            callbackStub->SetExtCallback(cb);
            extCallbackMap_.insert(std::make_pair(extensionCID, callbackStub));
        }
    } else {
        callbackStub = it->second;
        callbackStub->SetExtCallback(cb);
    }
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RegisterExtCallback(extensionCID, callbackStub);
        PRINT_HILOGD("PrintManagerClient RegisterExtCallback out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RegisterExtCallback(const std::string &extensionId,
    uint32_t callbackId, PrintJobCallback cb)
{
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }

    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    std::string extensionCID = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto it = extCallbackMap_.find(extensionCID);
    if (it == extCallbackMap_.end()) {
        callbackStub = new (std::nothrow) PrintExtensionCallbackStub;
        if (callbackStub != nullptr) {
            callbackStub->SetPrintJobCallback(cb);
            extCallbackMap_.insert(std::make_pair(extensionCID, callbackStub));
        }
    } else {
        callbackStub = it->second;
        callbackStub->SetPrintJobCallback(cb);
    }

    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RegisterExtCallback(extensionCID, callbackStub);
        PRINT_HILOGD("PrintManagerClient RegisterExtCallback out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RegisterExtCallback(const std::string &extensionId,
    uint32_t callbackId, PrinterCapabilityCallback cb)
{
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }

    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    std::string extensionCID = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto it = extCallbackMap_.find(extensionCID);
    if (it == extCallbackMap_.end()) {
        callbackStub = new (std::nothrow) PrintExtensionCallbackStub;
        if (callbackStub != nullptr) {
            callbackStub->SetCapabilityCallback(cb);
            extCallbackMap_.insert(std::make_pair(extensionCID, callbackStub));
        }
    } else {
        callbackStub = it->second;
        callbackStub->SetCapabilityCallback(cb);
    }

    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RegisterExtCallback(extensionCID, callbackStub);
        PRINT_HILOGD("PrintManagerClient RegisterExtCallback out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::RegisterExtCallback(const std::string &extensionId,
    uint32_t callbackId, PrinterCallback cb)
{
    PRINT_HILOGD("PrintManagerClient RegisterExtCallback start.");
    if (callbackId >= PRINT_EXTCB_MAX) {
        PRINT_HILOGE("Invalid callback id [%{public}d].", callbackId);
        return E_PRINT_INVALID_PARAMETER;
    }

    sptr<PrintExtensionCallbackStub> callbackStub = nullptr;
    std::string extensionCID = PrintUtils::EncodeExtensionCid(extensionId, callbackId);
    auto it = extCallbackMap_.find(extensionCID);
    if (it == extCallbackMap_.end()) {
        callbackStub = new (std::nothrow) PrintExtensionCallbackStub;
        if (callbackStub != nullptr) {
            callbackStub->SetPrinterCallback(cb);
            extCallbackMap_.insert(std::make_pair(extensionCID, callbackStub));
        }
    } else {
        callbackStub = it->second;
        callbackStub->SetPrinterCallback(cb);
    }

    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->RegisterExtCallback(extensionCID, callbackStub);
        PRINT_HILOGD("PrintManagerClient RegisterExtCallback out ret = [%{public}d].", ret);
    }
    return ret;
}

int32_t PrintManagerClient::UnregisterAllExtCallback(const std::string &extensionId)
{
    PRINT_HILOGD("PrintManagerClient UnregisterAllExtCallback start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->UnregisterAllExtCallback(extensionId);
        PRINT_HILOGD("PrintManagerClient UnregisterAllExtCallback out ret = [%{public}d].", ret);
    }
    extCallbackMap_.clear();
    return ret;
}

int32_t PrintManagerClient::LoadExtSuccess(const std::string &extensionId)
{
    PRINT_HILOGD("PrintManagerClient LoadExtSuccess start.");
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (LoadServer() && GetPrintServiceProxy()) {
        ret = printServiceProxy_->LoadExtSuccess(extensionId);
        PRINT_HILOGD("PrintManagerClient LoadExtSuccess out ret = [%{public}d].", ret);
    }
    return ret;
}

bool PrintManagerClient::LoadServer()
{
    if (ready_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(loadMutex_);
    if (ready_) {
        return true;
    }

    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        PRINT_HILOGE("GetSystemAbilityManager return null");
        return false;
    }

    sptr<PrintSyncLoadCallback> loadCallback_ = new (std::nothrow) PrintSyncLoadCallback();
    if (loadCallback_ == nullptr) {
        PRINT_HILOGE("new PrintSyncLoadCallback fail");
        return false;
    }

    int32_t result = sm->LoadSystemAbility(PRINT_SERVICE_ID, loadCallback_);
    if (result != ERR_OK) {
        PRINT_HILOGE("LoadSystemAbility %{public}d failed, result: %{public}d", PRINT_SERVICE_ID, result);
        return false;
    }

    {
        std::unique_lock<std::mutex> conditionLock(conditionMutex_);
        auto waitStatus = syncCon_.wait_for(
            conditionLock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS), [this]() { return ready_; });
        if (!waitStatus) {
            PRINT_HILOGE("print server load sa timeout");
            return false;
        }
    }
    return true;
}

void PrintManagerClient::LoadServerSuccess()
{
    std::unique_lock<std::mutex> lock(conditionMutex_);
    ready_ = true;
    syncCon_.notify_one();
    PRINT_HILOGD("load print server success");
}

void PrintManagerClient::LoadServerFail()
{
    ready_ = false;
    PRINT_HILOGE("load print server fail");
}
void PrintManagerClient::SetProxy(const sptr<IRemoteObject> &obj)
{
    if (printServiceProxy_ != nullptr) {
        auto serviceRemote = printServiceProxy_->AsObject();
        if (serviceRemote != nullptr) {
            serviceRemote->RemoveDeathRecipient(deathRecipient_);
            printServiceProxy_ = nullptr;
            deathRecipient_ = nullptr;
        }
    }
    deathRecipient_ = new (std::nothrow) PrintSaDeathRecipient();
    if (deathRecipient_ != nullptr) {
        obj->AddDeathRecipient(deathRecipient_);
        PRINT_HILOGD("Getting PrintManagerClientProxy succeeded.");
    }
    printServiceProxy_ = iface_cast<IPrintService>(obj);
}
void PrintManagerClient::ResetProxy()
{
    printServiceProxy_ = nullptr;
}
} // namespace OHOS::Print
