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

#include "print_service_stub.h"
#include "ipc_skeleton.h"
#include "iprint_service.h"
#include "iwatermark_callback.h"
#include "ikia_interceptor_callback.h"
#include "message_parcel.h"
#include "print_constant.h"
#include "print_extension_info.h"
#include "print_job.h"
#include "print_log.h"
#include "print_util.h"

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;

PrintServiceStub::PrintServiceStub()
{
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_START_PRINT] = &PrintServiceStub::OnStartPrint;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_CONNECTPRINTER] = &PrintServiceStub::OnConnectPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_DISCONNECTPRINTER] = &PrintServiceStub::OnDisconnectPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTDISCOVERPRINTER] = &PrintServiceStub::OnStartDiscoverPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STOPDISCOVERPRINTER] = &PrintServiceStub::OnStopDiscoverPrint;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLEXTENSION] = &PrintServiceStub::OnQueryAllExtension;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB] = &PrintServiceStub::OnStartPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_CANCELPRINTJOB] = &PrintServiceStub::OnCancelPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERS] = &PrintServiceStub::OnAddPrinters;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REMOVEPRINTERS] = &PrintServiceStub::OnRemovePrinters;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERS] = &PrintServiceStub::OnUpdatePrinters;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERSTATE] = &PrintServiceStub::OnUpdatePrinterState;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADAPTERGETFILECALLBACK] =
        &PrintServiceStub::OnAdapterGetFileCallBack;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTJOBSTATE_FORSYSTEMAPP] =
        &PrintServiceStub::OnUpdatePrintJobStateOnlyForSystemApp;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEEXTENSIONINFO] = &PrintServiceStub::OnUpdateExtensionInfo;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REQUESTPREVIEW] = &PrintServiceStub::OnRequestPreview;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITY] =
        &PrintServiceStub::OnQueryPrinterCapability;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ON] = &PrintServiceStub::OnEventOn;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_OFF] = &PrintServiceStub::OnEventOff;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REG_EXT_CB] = &PrintServiceStub::OnRegisterExtCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_LOAD_EXT] = &PrintServiceStub::OnLoadExtSuccess;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADD_RAW_PRINTER] = &PrintServiceStub::OnAddRawPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYRAWADDEDPRINTER] = &PrintServiceStub::OnQueryRawAddedPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLACTIVEPRINTJOB] = &PrintServiceStub::OnQueryAllActivePrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLPRINTJOB] =
        &PrintServiceStub::OnQueryAllPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTJOBBYID] = &PrintServiceStub::OnQueryPrintJobById;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTER] = &PrintServiceStub::OnAddPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERTOCUPS] = &PrintServiceStub::OnAddPrinterToCups;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERCAPABILITYBYURI] =
        &PrintServiceStub::OnQueryPrinterCapabilityByUri;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTPRINTJOB_BY_ADAPTER] = &PrintServiceStub::OnPrintByAdapter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_START_GET_FILE] = &PrintServiceStub::OnStartGetPrintFile;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_PRINT_SERVICE] = &PrintServiceStub::OnNotifyPrintService;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_START_SERVICE] = &PrintServiceStub::OnStartService;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_RELEASE] = &PrintServiceStub::OnRelease;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REG_PRINTER_CB] = &PrintServiceStub::OnRegisterPrinterCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UNREG_PRINTER_CB] = &PrintServiceStub::OnUnregisterPrinterCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERINFOBYPRINTERID] =
        &PrintServiceStub::OnQueryPrinterInfoByPrinterId;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYADDEDPRINTER] = &PrintServiceStub::OnQueryAddedPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYPRINTERPROPERTIES] =
        &PrintServiceStub::OnQueryPrinterProperties;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_STARTNATIVEPRINTJOB] = &PrintServiceStub::OnStartNativePrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_PRINT_SERVICE_EVENT] =
        &PrintServiceStub::OnNotifyPrintServiceEvent;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_SET_PRINTER_PREFERENCE] =
        &PrintServiceStub::OnSetPrinterPreference;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_SET_DEFAULT_PRINTERID] = &PrintServiceStub::OnSetDefaultPrinter;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_DELETE_PRINTER_FROM_CUPS] =
        &PrintServiceStub::OnDeletePrinterFromCups;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_DISCOVER_USB_PRINTERS] = &PrintServiceStub::OnDiscoverUsbPrinters;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ADDPRINTERTODISCOVERY] = &PrintServiceStub::OnAddPrinterToDiscovery;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERINDISCOVERY] =
        &PrintServiceStub::OnUpdatePrinterInDiscovery;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REMOVEPRINTERFROMDISCOVERY] =
        &PrintServiceStub::OnRemovePrinterFromDiscovery;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UPDATEPRINTERINSYSTEM] =
        &PrintServiceStub::OnUpdatePrinterInSystem;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_RESTARTPRINTJOB] = &PrintServiceStub::OnRestartPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_ANALYZEPRINTEVENTS] = &PrintServiceStub::OnAnalyzePrintEvents;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_AUTHPRINTJOB] = &PrintServiceStub::OnAuthPrintJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYALLPPDS] = &PrintServiceStub::OnQueryAllPrinterPpds;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYIPINFO] = &PrintServiceStub::OnQueryPrinterInfoByIp;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_CONNECTPRINTERBYIPANDPPD] =
        &PrintServiceStub::OnConnectPrinterByIpAndPpd;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_SAVEPDFFILEJOB] = &PrintServiceStub::OnSavePdfFileJob;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_CHECKPREFERENCESCONFLICTS] =
        &PrintServiceStub::OnCheckPreferencesConflicts;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_CHECKPRINTJOBCONFLICTS] = &PrintServiceStub::OnCheckPrintJobConflicts;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_GETPRINTERDEFAULTPREFERENCES] =
        &PrintServiceStub::OnGetPrinterDefaultPreferences;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_GET_PRINTER_PREFERENCE] = &PrintServiceStub::OnGetPrinterPreference;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_QUERYRECOMMENDDRVIERSBYID] =
        &PrintServiceStub::OnQueryRecommendDriversById;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_CONNECTPRINTERBYIDANDPPD] =
        &PrintServiceStub::OnConnectPrinterByIdAndPpd;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_GET_SHAREDHOSTS] = &PrintServiceStub::OnGetSharedHosts;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_START_SHARED_HOST_DISCOVERY] =
        &PrintServiceStub::OnStartSharedHostDiscovery;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_AUTH_SMB_DEVICE] = &PrintServiceStub::OnAuthSmbDevice;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REG_WATERMARK_CB] =
        &PrintServiceStub::OnRegisterWatermarkCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_UNREG_WATERMARK_CB] =
        &PrintServiceStub::OnUnregisterWatermarkCallback;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_NOTIFY_WATERMARK_COMPLETE] =
        &PrintServiceStub::OnNotifyWatermarkComplete;
    cmdMap_[OHOS::Print::IPrintInterfaceCode::CMD_REG_KIA_INTERCEPTOR_CB] =
               &PrintServiceStub::OnRegisterKiaInterceptorCallback;
}

int32_t PrintServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("OnRemoteRequest started, code = %{public}u", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_RPC_FAILURE;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            bool result = (this->*requestFunc)(data, reply);
            return result ? E_PRINT_NONE : E_PRINT_GENERIC_FAILURE;
        }
    }
    PRINT_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool PrintServiceStub::OnStartService(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("nativePrint PrintServiceStub::OnStartService in");
    int32_t ret = E_PRINT_INVALID_PARAMETER;
    std::string printType;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printType), false);
    if (printType == "nativePrint") {
        ret = StartService();
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
        PRINT_HILOGI("nativePrint PrintServiceStub::OnStartService out:%{public}d", ret);
    }
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRelease(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("nativePrint PrintServiceStub::OnRelease in");
    int32_t ret = E_PRINT_INVALID_PARAMETER;
    std::string printType;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printType), false);
    if (printType == "nativePrint") {
        ret = Release();
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
        PRINT_HILOGI("nativePrint PrintServiceStub::OnRelease out:%{public}d", ret);
    }
    return ret == E_PRINT_NONE;
}

static bool ReadFdListFromParcel(MessageParcel &data, std::vector<uint32_t> &fdList)
{
    uint32_t len = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadUint32(len), false);
    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        return false;
    }
    for (uint32_t index = 0; index < len; index++) {
        int fdTemp = data.ReadFileDescriptor();
        if (fdTemp >= 0) {
            uint32_t fd = static_cast<uint32_t>(fdTemp);
            fdsan_exchange_owner_tag(fd, 0, PRINT_LOG_DOMAIN);
            PRINT_HILOGD("fdList[%{public}u] = %{public}u", index, fd);
            fdList.emplace_back(fd);
            continue;
        }
        PRINT_HILOGE("invalid fd");
        for (auto fd : fdList) {
            fdsan_close_with_tag(fd, PRINT_LOG_DOMAIN);
        }
        fdList.clear();
        return false;
    }
    return true;
}

bool PrintServiceStub::OnStartPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartPrint in");
    std::vector<std::string> fileList;
    std::vector<uint32_t> fdList;

    bool hasFileList = false;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadBool(hasFileList), false);
    if (hasFileList) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadStringVector(&fileList), false);
        PRINT_HILOGD("Current file is %{public}zd", fileList.size());
        if (fileList.size() > PRINT_MAX_PRINT_COUNT) {
            PRINT_HILOGE("fileList'size is out of range.");
            CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_INVALID_PARAMETER), false);
            return false;
        }
    }

    bool hasFdList = false;
 	CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadBool(hasFdList), false);
 	if (hasFdList) { 
        if (!ReadFdListFromParcel(data, fdList)) {
            CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_INVALID_PARAMETER), false);
            return false;
        }
    }
    std::string taskId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(taskId), false);
    int32_t ret = StartPrint(fileList, fdList, taskId);
    if (ret != E_PRINT_NONE) {
        for (auto fd : fdList) {
            fdsan_close_with_tag(fd, PRINT_LOG_DOMAIN);
        }
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnStartPrint out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnConnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    int32_t ret = ConnectPrinter(printerId);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnConnectPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnDisconnectPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    int32_t ret = DisconnectPrinter(printerId);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnDisconnectPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartDiscoverPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter in");
    std::vector<std::string> extensionList;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadStringVector(&extensionList), false);
    PRINT_HILOGD("Current extensionList is %{public}zd", extensionList.size());
    if (extensionList.size() > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("extensionList'size: %{public}zd, is out of range.", extensionList.size());
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_INVALID_PARAMETER), false);
        return false;
    }
    int32_t ret = StartDiscoverPrinter(extensionList);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnStartDiscoverPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStopDiscoverPrint(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint in");
    int32_t ret = StopDiscoverPrinter();
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnStopDiscoverPrint out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAddRawPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnAddRawPrinter in");
    auto printerInfoPtr = PrinterInfo::Unmarshalling(data);
    if (printerInfoPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printer info");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    printerInfoPtr->Dump();

    int32_t ret = AddRawPrinter(*printerInfoPtr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnAddRawPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllExtension(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryAllExtension in");
    std::vector<PrintExtensionInfo> printerInfo;
    int32_t ret = QueryAllExtension(printerInfo);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(printerInfo.size());
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteUint32(size), false);
        for (uint32_t index = 0; index < size; index++) {
            CHECK_PARCEL_OP_AND_RETURN_VAL(printerInfo[index].Marshalling(reply), false);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryAllExtension out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    auto jobInfoPtr = PrintJob::Unmarshalling(data);
    if (jobInfoPtr != nullptr) {
        jobInfoPtr->Dump();
        ret = StartPrintJob(*jobInfoPtr);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnCancelPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnCancelPrintJob in");
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    int32_t ret = CancelPrintJob(jobId);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnCancelPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAddPrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnAddPrinters in");
    std::vector<PrinterInfo> printerInfos;
    uint32_t len = 0;
    if (!data.ReadUint32(len)) {
        PRINT_HILOGE("read data len failed.");
        return false;
    }
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}u", len);

    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_INVALID_PARAMETER), false);
        return false;
    }
    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = PrinterInfo::Unmarshalling(data);
        if (infoPtr == nullptr) {
            PRINT_HILOGW("invalid printer object");
            continue;
        }
        infoPtr->Dump();
        printerInfos.emplace_back(*infoPtr);
    }
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (printerInfos.size() > 0) {
        ret = AddPrinters(printerInfos);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnAddPrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrinterInfoByPrinterId(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterInfoByPrinterId in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    PrinterInfo info;
    int32_t ret = QueryPrinterInfoByPrinterId(printerId, info);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterInfoByPrinterId out %{private}s", info.GetPrinterName().c_str());
    CHECK_PARCEL_OP_AND_RETURN_VAL(info.Marshalling(reply), false);
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterInfoByPrinterId out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnSetPrinterPreference(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnSetPrinterPreference in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    auto preferencesPtr = PrinterPreferences::Unmarshalling(data);
    if (preferencesPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printer preferences");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }

    int32_t ret = SetPrinterPreference(printerId, *preferencesPtr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAddedPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAddedPrinter in");
    std::vector<std::string> printerNameList;
    int32_t ret = QueryAddedPrinter(printerNameList);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteStringVector(printerNameList), false);
    PRINT_HILOGI("PrintServiceStub::OnQueryAddedPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryRawAddedPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryRawAddedPrinter in");
    std::vector<std::string> printerNameList;

    int32_t ret = QueryRawAddedPrinter(printerNameList);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteStringVector(printerNameList), false);

    PRINT_HILOGI("PrintServiceStub::OnQueryRawAddedPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrinterProperties(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAddedPrinter in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    std::vector<std::string> keyList;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadStringVector(&keyList), false);
    std::vector<std::string> valueList;
    int32_t ret = QueryPrinterProperties(printerId, keyList, valueList);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteStringVector(valueList), false);
    PRINT_HILOGI("PrintServiceStub::OnQueryAddedPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartNativePrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStartNativePrintJob in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    auto printJobPtr = PrintJob::Unmarshalling(data);
    if (printJobPtr != nullptr) {
        printJobPtr->Dump();
        ret = StartNativePrintJob(*printJobPtr);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnStartPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRemovePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters in");
    std::vector<std::string> printerIds;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadStringVector(&printerIds), false);
    PRINT_HILOGD("OnStartDiscoverPrinter len = %{public}zd", printerIds.size());

    if (printerIds.size() > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("printerIds'size is out of range.");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_INVALID_PARAMETER), false);
        return false;
    }
    int32_t ret = RemovePrinters(printerIds);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);

    PRINT_HILOGD("PrintServiceStub::OnRemovePrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinters in");
    std::vector<PrinterInfo> printerInfos;
    uint32_t len = 0;
    if (!data.ReadUint32(len)) {
        PRINT_HILOGE("read data len failed.");
        return false;
    }
    PRINT_HILOGD("OnUpdatePrinters len = %{public}u", len);

    if (len > PRINT_MAX_PRINT_COUNT) {
        PRINT_HILOGE("len is out of range.");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_INVALID_PARAMETER), false);
        return false;
    }
    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = PrinterInfo::Unmarshalling(data);
        if (infoPtr == nullptr) {
            PRINT_HILOGW("invalid printer object");
            continue;
        }
        infoPtr->Dump();
        printerInfos.emplace_back(*infoPtr);
    }
    int32_t ret = E_PRINT_RPC_FAILURE;
    if (printerInfos.size() > 0) {
        ret = UpdatePrinters(printerInfos);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinterState(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    uint32_t state = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadUint32(state), false);
    int32_t ret = UpdatePrinterState(printerId, state);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterState out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAdapterGetFileCallBack(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnAdapterGetFileCallBack in");
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    uint32_t state = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadUint32(state), false);
    uint32_t subState = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadUint32(subState), false);
    PRINT_HILOGD("jobId = %{public}s; state = %{public}u; subState = %{public}u",
        jobId.c_str(), state, subState);
    int32_t ret = AdapterGetFileCallBack(jobId, state, subState);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnAdapterGetFileCallBack out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrintJobStateOnlyForSystemApp(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrintJobStateOnlyForSystemApp in");
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    uint32_t state = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadUint32(state), false);
    uint32_t subState = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadUint32(subState), false);
    PRINT_HILOGD("OnUpdatePrintJobStateOnlyForSystemApp jobId = %{public}s", jobId.c_str());
    PRINT_HILOGD("OnUpdatePrintJobStateOnlyForSystemApp state = %{public}u", state);
    PRINT_HILOGD("OnUpdatePrintJobStateOnlyForSystemApp subState = %{public}u", subState);

    int32_t ret = UpdatePrintJobStateOnlyForSystemApp(jobId, state, subState);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrintJobStateOnlyForSystemApp out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdateExtensionInfo(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdateExtensionInfo in");
    std::string extInfo;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(extInfo), false);
    PRINT_HILOGD("OnUpdateExtensionInfo extInfo = %{public}s", extInfo.c_str());

    int32_t ret = UpdateExtensionInfo(extInfo);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnUpdateExtensionInfo out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRequestPreview(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRequestPreview in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string previewResult = "";
    auto jobInfoPtr = PrintJob::Unmarshalling(data);
    if (jobInfoPtr != nullptr) {
        jobInfoPtr->Dump();
        ret = RequestPreview(*jobInfoPtr, previewResult);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteString(previewResult), false);
    PRINT_HILOGD("PrintServiceStub::OnRequestPreview out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrinterCapability(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    PRINT_HILOGD("printerId : %{private}s", printerId.c_str());
    int32_t ret = QueryPrinterCapability(printerId);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapability out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllActivePrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAllActivePrintJob in");
    std::vector<PrintJob> printJob;
    printJob.clear();
    int32_t ret = QueryAllActivePrintJob(printJob);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(printJob.size());
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteUint32(size), false);
        for (uint32_t index = 0; index < size; index++) {
            CHECK_PARCEL_OP_AND_RETURN_VAL(printJob[index].Marshalling(reply), false);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryAllActivePrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryAllPrintJob in");
    std::vector<PrintJob> printJob;
    printJob.clear();
    int32_t ret = QueryAllPrintJob(printJob);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(printJob.size());
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteUint32(size), false);
        for (uint32_t index = 0; index < size; index++) {
            CHECK_PARCEL_OP_AND_RETURN_VAL(printJob[index].Marshalling(reply), false);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnQueryAllPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrintJobById(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrintJobById in");
    PrintJob printJob;
    std::string printJobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printJobId), false);
    int32_t ret = QueryPrintJobById(printJobId, printJob);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(printJob.Marshalling(reply), false);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrintJobById out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAddPrinterToCups(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnAddPrinterToCups in");
    std::string printerUri;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerUri), false);
    std::string printerName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerName), false);
    std::string printerMake;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerMake), false);
    int32_t ret = AddPrinterToCups(printerUri, printerName, printerMake);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnAddPrinterToCups out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrinterCapabilityByUri(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapabilityByUri in");
    PrinterCapability printerCaps;
    std::string printerUri;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerUri), false);
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    int32_t ret = QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(printerCaps.Marshalling(reply), false);
    PRINT_HILOGD("PrintServiceStub::OnQueryPrinterCapabilityByUri out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnNotifyPrintServiceEvent(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnNotifyPrintServiceEvent in");
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    uint32_t event = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadUint32(event), false);
    PRINT_HILOGD("OnNotifyPrintServiceEvent jobId = %{public}s, event = %{public}u", jobId.c_str(), event);
    int32_t ret = NotifyPrintServiceEvent(jobId, event);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnNotifyPrintServiceEvent out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnSetDefaultPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnSetDefaultPrinter in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    uint32_t printerType = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadUint32(printerType), false);
    int32_t ret = SetDefaultPrinter(printerId, printerType);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnSetDefaultPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnDeletePrinterFromCups(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnDeletePrinterFromCups in");
    std::string printerName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerName), false);
    int32_t ret = DeletePrinterFromCups(printerName);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnDeletePrinterFromCups out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnDiscoverUsbPrinters(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnDiscoverUsbPrinters in");
    std::vector<PrinterInfo> printers;
    int32_t ret = DiscoverUsbPrinters(printers);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(printers.size());
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteUint32(size), false);
        for (uint32_t index = 0; index < size; index++) {
            CHECK_PARCEL_OP_AND_RETURN_VAL(printers[index].Marshalling(reply), false);
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnDiscoverUsbPrinters out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnEventOn(MessageParcel &data, MessageParcel &reply)
{
    std::string taskId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(taskId), false);
    std::string type;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(type), false);
    PRINT_HILOGD("PrintServiceStub::OnEventOn type=%{public}s ", type.c_str());
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn type is null.");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn remote is nullptr");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    sptr<IPrintCallback> listener = iface_cast<IPrintCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn listener is null");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    int32_t ret = On(taskId, type, listener);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnEventOn out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnEventOff(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnEventOff in");
    std::string taskId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(taskId), false);
    std::string type;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(type), false);
    PRINT_HILOGD("PrintServiceStub::OnEventOff type=%{public}s ", type.c_str());
    int32_t ret = Off(taskId, type);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnEventOff out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRegisterPrinterCallback(MessageParcel &data, MessageParcel &reply)
{
    std::string type;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(type), false);
    if (type.empty()) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn type is null.");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnRegisterPrinterCallback type=%{public}s ", type.c_str());
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn remote is nullptr");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    sptr<IPrintCallback> listener = iface_cast<IPrintCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGE("PrintServiceStub::OnEventOn listener is null");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    int32_t ret = RegisterPrinterCallback(type, listener);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnRegisterPrinterCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUnregisterPrinterCallback(MessageParcel &data, MessageParcel &reply)
{
    std::string type;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(type), false);
    if (type.empty()) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    PRINT_HILOGD("PrintServiceStub::OnUnregisterPrinterCallback type=%{public}s ", type.c_str());
    int32_t ret = UnregisterPrinterCallback(type);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnUnregisterPrinterCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRegisterExtCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback in");
    std::string extensionCID;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(extensionCID), false);
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback remote is nullptr");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    sptr<IPrintExtensionCallback> listener = iface_cast<IPrintExtensionCallback>(remote);
    if (listener.GetRefPtr() == nullptr) {
        PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback listener is null");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }

    int32_t ret = RegisterExtCallback(extensionCID, listener);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnRegisterExtCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnLoadExtSuccess(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnLoadExtSuccess in");
    std::string extensionId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(extensionId), false);
    int32_t ret = LoadExtSuccess(extensionId);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnLoadExtSuccess out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnPrintByAdapter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnPrintByAdapter in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string jobName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobName), false);
    auto attrs = PrintAttributes::Unmarshalling(data);
    std::string taskId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(taskId), false);
    if (attrs != nullptr) {
        attrs->Dump();
        ret = PrintByAdapter(jobName, *attrs, taskId);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnPrintByAdapter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartGetPrintFile(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStartGetPrintFile in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    auto attrs = PrintAttributes::Unmarshalling(data);
    int32_t fd = data.ReadFileDescriptor();
    if (fd >= 0) {
        if (attrs != nullptr) {
            ret = StartGetPrintFile(jobId, *attrs, static_cast<uint32_t>(fd));
        }
        close(fd);
    } else {
        PRINT_HILOGE("dup fd failed by RPC");
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnStartGetPrintFile out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnNotifyPrintService(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnNotifyPrintService in");
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    std::string type;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(type), false);
    PRINT_HILOGD(
        "PrintServiceStub::OnNotifyPrintService jobId=%{public}s type=%{public}s ", jobId.c_str(), type.c_str());
    int32_t ret = NotifyPrintService(jobId, type);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnNotifyPrintService out");
    return ret == E_PRINT_NONE;
}


bool PrintServiceStub::OnAddPrinterToDiscovery(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnAddPrinterToDiscovery in");
    auto infoPtr = PrinterInfo::Unmarshalling(data);
    if (infoPtr == nullptr) {
        PRINT_HILOGW("invalid printer object");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        PRINT_HILOGD("PrintServiceStub::OnAddPrinterToDiscovery out with failure");
        return false;
    }
    infoPtr->Dump();
    int32_t ret = AddPrinterToDiscovery(*infoPtr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnAddPrinterToDiscovery out with ret = %{public}d", ret);
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinterInDiscovery(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterInDiscovery in");

    auto infoPtr = PrinterInfo::Unmarshalling(data);
    if (infoPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printer info");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }

    infoPtr->Dump();
    int32_t ret = UpdatePrinterInDiscovery(*infoPtr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);

    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterInDiscovery out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRemovePrinterFromDiscovery(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGD("PrintServiceStub::OnRemovePrinterFromDiscovery in");

    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);

    int32_t ret = RemovePrinterFromDiscovery(printerId);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);

    PRINT_HILOGD("PrintServiceStub::OnRemovePrinterFromDiscovery out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUpdatePrinterInSystem(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnUpdatePrinterInSystem in");

    auto infoPtr = PrinterInfo::Unmarshalling(data);
    if (infoPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printer info");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }

    infoPtr->Dump();
    int32_t ret = UpdatePrinterInSystem(*infoPtr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);

    PRINT_HILOGD("PrintServiceStub::OnUpdatePrinterInSystem out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRestartPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::RestartPrintJob in");
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    int32_t ret = RestartPrintJob(jobId);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::RestartPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAnalyzePrintEvents(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::AnalyzePrintEvents in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    std::string eventType;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(eventType), false);
    std::string detail;
    int32_t ret = AnalyzePrintEvents(printerId, eventType, detail);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteString(detail), false);
    PRINT_HILOGD("PrintServiceStub::AnalyzePrintEvents out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAuthPrintJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::AuthPrintJob in");
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    std::string userName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(userName), false);
    const uint8_t *outData = data.ReadBuffer(MAX_AUTH_LENGTH_SIZE);
    if (outData == nullptr) {
        PRINT_HILOGE("Read Password Buffer fail.");
        return false;
    }

    char* userPasswd = new (std::nothrow) char[MAX_AUTH_LENGTH_SIZE];
    if (userPasswd == nullptr) {
        PRINT_HILOGE("Allocate Password fail.");
        return false;
    }

    auto memcpyRet = memcpy_s(userPasswd, MAX_AUTH_LENGTH_SIZE, outData, MAX_AUTH_LENGTH_SIZE);
    if (memcpyRet != E_PRINT_NONE) {
        PrintUtil::SafeDeleteAuthInfo(userPasswd);
        PRINT_HILOGE("memcpy_s failed, errorCode:[%{public}d]", memcpyRet);
        return false;
    }
    userPasswd[MAX_AUTH_LENGTH_SIZE - 1] = '\0';

    int32_t ret = AuthPrintJob(jobId, userName, userPasswd);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);

    PrintUtil::SafeDeleteAuthInfo(userPasswd);

    PRINT_HILOGD("PrintServiceStub::AuthPrintJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryAllPrinterPpds(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryAllPrinterPpds in");
    std::vector<PpdInfo> ppdInfos;
    int32_t ret = QueryAllPrinterPpds(ppdInfos);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(ppdInfos.size());
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteUint32(size), false);
        for (uint32_t index = 0; index < size; ++index) {
            if (!ppdInfos[index].Marshalling(reply)) {
                PRINT_HILOGW("Marshalling ppd: %{public}s failed", ppdInfos[index].GetPpdName().c_str());
                return false;
            }
        }
    }
    PRINT_HILOGI("PrintServiceStub::OnQueryAllPrinterPpds out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryPrinterInfoByIp(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterInfoByIp in");
    std::string printerIp;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerIp), false);
    int32_t ret = QueryPrinterInfoByIp(printerIp);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnQueryPrinterInfoByIp out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnConnectPrinterByIpAndPpd(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnConnectPrinterByIpAndPpd in");
    std::string printerIp;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerIp), false);
    std::string protocol;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(protocol), false);
    std::string ppdName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(ppdName), false);
    int32_t ret = ConnectPrinterByIpAndPpd(printerIp, protocol, ppdName);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnConnectPrinterByIpAndPpd out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnSavePdfFileJob(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnSavePdfFileJob in");
    int32_t ret = E_PRINT_RPC_FAILURE;
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    int32_t fd = data.ReadFileDescriptor();
    if (fd >= 0) {
        ret = SavePdfFileJob(jobId, static_cast<uint32_t>(fd));
        if (close(fd) != 0) {
            PRINT_HILOGI("Close File Failure.");
        }
    } else {
        PRINT_HILOGE("dup fd failed by RPC");
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnSavePdfFileJob out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnCheckPreferencesConflicts(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnCheckPreferencesConflicts in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    std::string changedType;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(changedType), false);
    auto preferencesPtr = PrinterPreferences::Unmarshalling(data);
    if (preferencesPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printerPreferences");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    std::vector<std::string> conflictingOptions;
    int32_t ret = CheckPreferencesConflicts(printerId, changedType, *preferencesPtr, conflictingOptions);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteStringVector(conflictingOptions), false);

    PRINT_HILOGI("PrintServiceStub::OnCheckPreferencesConflicts out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnCheckPrintJobConflicts(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnCheckPrintJobConflicts in");
    std::string changedType;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(changedType), false);
    auto printJobPtr = PrintJob::Unmarshalling(data);
    if (printJobPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall printJob");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    std::vector<std::string> conflictingOptions;
    int32_t ret = CheckPrintJobConflicts(changedType, *printJobPtr, conflictingOptions);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteStringVector(conflictingOptions), false);

    PRINT_HILOGI("PrintServiceStub::OnCheckPrintJobConflicts out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnGetPrinterDefaultPreferences(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnGetPrinterDefaultPreferences in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    PrinterPreferences defaultPreferences;
    int32_t ret = GetPrinterDefaultPreferences(printerId, defaultPreferences);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(defaultPreferences.Marshalling(reply), false);
    PRINT_HILOGI("PrintServiceStub::OnGetPrinterDefaultPreferences out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnGetPrinterPreference(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnGetPrinterPreference in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    PrinterPreferences printerPreference;
    int32_t ret = GetPrinterPreference(printerId, printerPreference);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(printerPreference.Marshalling(reply), false);
    PRINT_HILOGI("PrintServiceStub::OnGetPrinterPreference out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnQueryRecommendDriversById(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnQueryRecommendDriversById in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    std::vector<PpdInfo> ppdInfos;
    int32_t ret = QueryRecommendDriversById(printerId, ppdInfos);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    if (ret == E_PRINT_NONE) {
        uint32_t size = static_cast<uint32_t>(ppdInfos.size());
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteUint32(size), false);
        for (uint32_t index = 0; index < size; ++index) {
            if (!ppdInfos[index].Marshalling(reply)) {
                PRINT_HILOGW("Marshalling ppd: %{public}s failed", ppdInfos[index].GetPpdName().c_str());
                return false;
            }
        }
    }
    PRINT_HILOGI("PrintServiceStub::OnQueryRecommendDriversById out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnConnectPrinterByIdAndPpd(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnConnectPrinterByIdAndPpd in");
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    std::string protocol;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(protocol), false);
    std::string ppdName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(ppdName), false);
    int32_t ret = ConnectPrinterByIdAndPpd(printerId, protocol, ppdName);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnConnectPrinterByIdAndPpd out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnGetSharedHosts(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnGetSharedHosts in");
    std::vector<PrintSharedHost> sharedHosts;
    int32_t ret = GetSharedHosts(sharedHosts);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    if (ret == E_PRINT_NONE) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(static_cast<int32_t>(sharedHosts.size())), false);
        for (auto sharedHost : sharedHosts) {
            if (!sharedHost.Marshalling(reply)) {
                PRINT_HILOGW("Marshalling sharedHost fail");
                return false;
            }
        }
    }
    PRINT_HILOGI("PrintServiceStub::OnGetSharedHosts out");
    return ret == E_PRINT_NONE;
}

static bool ReadSmbPasswordFromParcel(MessageParcel &data, char *&userPasswd)
{
    const uint8_t *outData = data.ReadBuffer(MAX_AUTH_LENGTH_SIZE);
    if (outData == nullptr) {
        PRINT_HILOGE("Read Password Buffer fail.");
        return false;
    }
    userPasswd = new (std::nothrow) char[MAX_AUTH_LENGTH_SIZE]{};
    if (userPasswd == nullptr) {
        PRINT_HILOGE("Allocate Password fail.");
        return false;
    }
    auto memcpyRet = memcpy_s(userPasswd, MAX_AUTH_LENGTH_SIZE, outData, MAX_AUTH_LENGTH_SIZE);
    if (memcpyRet != E_PRINT_NONE) {
        PrintUtil::SafeDeleteAuthInfo(userPasswd);
        PRINT_HILOGE("memcpy_s failed, errorCode:[%{public}d]", memcpyRet);
        return false;
    }
    userPasswd[MAX_AUTH_LENGTH_SIZE - 1] = '\0';
    return true;
}

bool PrintServiceStub::OnAuthSmbDevice(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnAuthSmbDevice in");

    auto sharedHostPtr = PrintSharedHost::Unmarshalling(data);
    if (sharedHostPtr == nullptr) {
        PRINT_HILOGE("Failed to unmarshall PrintSharedHost");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }

    std::string userName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(userName), false);
    char* userPasswd = nullptr;
    if (!userName.empty()) {
        if (!ReadSmbPasswordFromParcel(data, userPasswd)) {
            return false;
        }
    }
    std::vector<PrinterInfo> printerInfos;
    int32_t ret = AuthSmbDevice(*sharedHostPtr, userName, userPasswd, printerInfos);
    if (userPasswd) {
        PrintUtil::SafeDeleteAuthInfo(userPasswd);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    if (ret == E_PRINT_NONE) {
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(static_cast<int32_t>(printerInfos.size())), false);
        for (const auto& printerInfo : printerInfos) {
            printerInfo.Dump();
            if (!printerInfo.Marshalling(reply)) {
                PRINT_HILOGW("Marshalling printerInfo fail");
                return false;
            }
        }
    }
    PRINT_HILOGD("PrintServiceStub::OnAuthSmbDevice out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRegisterWatermarkCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnRegisterWatermarkCallback in");
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        PRINT_HILOGE("Failed to read remote object");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    sptr<IWatermarkCallback> callback = iface_cast<IWatermarkCallback>(remoteObject);
    if (callback == nullptr) {
        PRINT_HILOGE("Failed to cast to IWatermarkCallback");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    int32_t ret = RegisterWatermarkCallback(callback);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnRegisterWatermarkCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnUnregisterWatermarkCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnUnregisterWatermarkCallback in");
    int32_t ret = UnregisterWatermarkCallback();
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnUnregisterWatermarkCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnNotifyWatermarkComplete(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnNotifyWatermarkComplete in");
    std::string jobId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(jobId), false);
    int32_t watermarkResult = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadInt32(watermarkResult), false);
    int32_t ret = NotifyWatermarkComplete(jobId, watermarkResult);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnNotifyWatermarkComplete out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnRegisterKiaInterceptorCallback(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnRegisterKiaInterceptorCallback in");
    auto remoteObject = data.ReadRemoteObject();
    if (remoteObject == nullptr) {
        PRINT_HILOGE("Failed to read remote object");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    sptr<IKiaInterceptorCallback> callback = iface_cast<IKiaInterceptorCallback>(remoteObject);
    if (callback == nullptr) {
        PRINT_HILOGE("Failed to cast to IKiaInterceptorCallback");
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(E_PRINT_RPC_FAILURE), false);
        return false;
    }
    int32_t ret = RegisterKiaInterceptorCallback(callback);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGI("PrintServiceStub::OnRegisterKiaInterceptorCallback out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnAddPrinter(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnAddPrinter in");
    std::string printerName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerName), false);
    std::string uri;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(uri), false);
    std::string ppdName;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(ppdName), false);
    std::string options;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(options), false);
    int32_t ret = AddPrinter(printerName, uri, ppdName, options);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnAddPrinter out");
    return ret == E_PRINT_NONE;
}

bool PrintServiceStub::OnStartSharedHostDiscovery(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintServiceStub::OnStartSharedHostDiscovery in");
    int32_t ret = StartSharedHostDiscovery();
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteInt32(ret), false);
    PRINT_HILOGD("PrintServiceStub::OnStartSharedHostDiscovery out");
    return ret == E_PRINT_NONE;
}

} // namespace OHOS::Print
