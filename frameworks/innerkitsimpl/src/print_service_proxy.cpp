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
#include "print_service_proxy.h"
#include "iremote_broker.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_job.h"
#include "print_log.h"
#include "printer_info.h"

namespace OHOS::Print {
using namespace OHOS::HiviewDFX;

PrintServiceProxy::PrintServiceProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IPrintService>(object) {}

int32_t PrintServiceProxy::StartPrint(const std::vector<std::string> &fileList,
                                      std::string &taskId) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  PRINT_HILOGD("Current file is %{public}d", fileList.size());
  for (auto file : fileList) {
    PRINT_HILOGD("file is %{public}s", file.c_str());
  }
  data.WriteStringVector(fileList);
  PRINT_HILOGD("PrintServiceProxy StartPrint started.");
  int32_t ret = Remote()->SendRequest(CMD_START_PRINT, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("StartPrint, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }
  ret = reply.ReadInt32();
  taskId = reply.ReadString();
  PRINT_HILOGD(
      "PrintServiceProxy StartPrint ret = [%{public}d] TaskId = %{public}s",
      ret, taskId.c_str());
  return ret;
}

int32_t PrintServiceProxy::StopPrint(const std::string &taskId) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(taskId);
  PRINT_HILOGD("PrintServiceProxy StopPrint started.");
  int32_t ret = Remote()->SendRequest(CMD_STOP_PRINT, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("StopPrint, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy StopPrint out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::ConnectPrinter(const std::string &printerId) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(printerId);
  PRINT_HILOGD("PrintServiceProxy ConnectPrinter started.");
  int32_t ret = Remote()->SendRequest(CMD_CONNECTPRINTER, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("ConnectPrinter, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy ConnectPrinter out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::DisconnectPrinter(const std::string &printerId) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(printerId);
  PRINT_HILOGD("PrintServiceProxy DisconnectPrinter started.");
  int32_t ret =
      Remote()->SendRequest(CMD_DISCONNECTPRINTER, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("DisconnectPrinter, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy DisconnectPrinter out. ret = [%{public}d]",
               ret);
  return ret;
}

int32_t PrintServiceProxy::QueryAllExtension(
    std::vector<PrintExtensionInfo> &extensionInfos) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  PRINT_HILOGD("PrintServiceProxy QueryAllExtension started.");
  int32_t ret =
      Remote()->SendRequest(CMD_QUERYALLEXTENSION, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("QueryAllExtension, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  if (ret != E_PRINT_NONE) {
    PRINT_HILOGD("PrintServiceProxy QueryAllExtension Failed.");
    return ret;
  }

  uint32_t len = reply.ReadUint32();
  for (uint32_t i = 0; i < len; i++) {
    auto infoPtr = PrintExtensionInfo::Unmarshalling(reply);
    if (infoPtr == nullptr) {
      PRINT_HILOGE("wrong information from data");
      return E_PRINT_GENERIC_FAILURE;
    }
    extensionInfos.emplace_back(*infoPtr);
  }
  PRINT_HILOGD("PrintServiceProxy QueryAllExtension succeeded.");
  return E_PRINT_NONE;
}

int32_t PrintServiceProxy::StartDiscoverPrinter(
    const std::vector<std::string> &extensionList) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteStringVector(extensionList);
  PRINT_HILOGD("PrintServiceProxy StartDiscoverPrinter started.");
  int32_t ret =
      Remote()->SendRequest(CMD_STARTDISCOVERPRINTER, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("StartDiscoverPrinter, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy StartDiscoverPrinter out. ret = [%{public}d]",
               ret);
  return ret;
}

int32_t PrintServiceProxy::StopDiscoverPrinter() {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  PRINT_HILOGD("PrintServiceProxy StopDiscoverPrinter started.");
  int32_t ret =
      Remote()->SendRequest(CMD_STOPDISCOVERPRINTER, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("StopDiscoverPrinter, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy StopDiscoverPrinter out. ret = [%{public}d]",
               ret);
  return ret;
}

int32_t PrintServiceProxy::StartPrintJob(const PrintJob &jobinfo) {
  MessageParcel data, reply;
  MessageOption option;

  data.WriteInterfaceToken(GetDescriptor());
  jobinfo.Marshalling(data);
  PRINT_HILOGD("PrintServiceProxy StartPrintJob started.");
  int32_t ret = Remote()->SendRequest(CMD_STARTPRINTJOB, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("StartPrintJob, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy StartPrintJob out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::CancelPrintJob(const std::string &jobId) {
  MessageParcel data, reply;
  MessageOption option;

  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(jobId);
  PRINT_HILOGD("PrintServiceProxy CancelPrintJob started.");
  int32_t ret = Remote()->SendRequest(CMD_CANCELPRINTJOB, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("CancelPrintJob, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy CancelPrintJob out. ret = [%{public}d]", ret);
  return ret;
}

int32_t
PrintServiceProxy::AddPrinters(const std::vector<PrinterInfo> &printerInfos) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteUint32(printerInfos.size());
  PRINT_HILOGD("AddPrinters printerInfos.size() = %{public}zu",
               printerInfos.size());
  for (uint32_t i = 0; i < printerInfos.size(); i++) {
    printerInfos[i].Marshalling(data);
  }
  PRINT_HILOGD("PrintServiceProxy AddPrinters started.");
  int32_t ret = Remote()->SendRequest(CMD_ADDPRINTERS, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("AddPrinters, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy AddPrinters out. ret = [%{public}d]", ret);
  return ret;
}

int32_t
PrintServiceProxy::RemovePrinters(const std::vector<std::string> &printerIds) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteStringVector(printerIds);

  PRINT_HILOGD("PrintServiceProxy RemovePrinters started.");
  int32_t ret = Remote()->SendRequest(CMD_REMOVEPRINTERS, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("RemovePrinters, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy RemovePrinters out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::UpdatePrinters(
    const std::vector<PrinterInfo> &printerInfos) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteUint32(printerInfos.size());
  PRINT_HILOGD("UpdatePrinters printerInfos.size() = %{public}zu",
               printerInfos.size());
  for (uint32_t i = 0; i < printerInfos.size(); i++) {
    printerInfos[i].Marshalling(data);
  }
  PRINT_HILOGD("PrintServiceProxy UpdatePrinters started.");
  int32_t ret = Remote()->SendRequest(CMD_UPDATEPRINTERS, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("UpdatePrinters, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy UpdatePrinters out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::UpdatePrinterState(const std::string &printerId,
                                              uint32_t state) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(printerId);
  data.WriteUint32(state);
  PRINT_HILOGD("PrintServiceProxy UpdatePrinterState started.");
  int32_t ret =
      Remote()->SendRequest(CMD_UPDATEPRINTERSTATE, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("UpdatePrinterState, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy UpdatePrinterState out. ret = [%{public}d]",
               ret);
  return ret;
}

int32_t PrintServiceProxy::UpdatePrintJobState(const std::string &jobId,
                                               uint32_t state,
                                               uint32_t subState) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(jobId);
  data.WriteUint32(state);
  data.WriteUint32(subState);
  PRINT_HILOGD("PrintServiceProxy UpdatePrintJobState started.");
  int32_t ret =
      Remote()->SendRequest(CMD_UPDATEPRINTJOBSTATE, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("UpdatePrintJobState, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy UpdatePrintJobState out. ret = [%{public}d]",
               ret);
  return ret;
}

int32_t PrintServiceProxy::UpdateExtensionInfo(const std::string &extensionId,
                                               const std::string &extInfo) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(extensionId);
  data.WriteString(extInfo);
  PRINT_HILOGD("PrintServiceProxy UpdateExtensionInfo started.");
  int32_t ret =
      Remote()->SendRequest(CMD_UPDATEEXTENSIONINFO, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("UpdateExtensionInfo, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy UpdateExtensionInfo out. ret = [%{public}d]",
               ret);
  return ret;
}

int32_t PrintServiceProxy::RequestPreview(const PrintJob &jobinfo,
                                          std::string &previewResult) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  jobinfo.Marshalling(data);
  PRINT_HILOGD("PrintServiceProxy RequestPreview started.");
  int32_t ret = Remote()->SendRequest(CMD_REQUESTPREVIEW, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("RequestPreview, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  previewResult = reply.ReadString();
  PRINT_HILOGD("PrintServiceProxy RequestPreview ret = [%{public}d] "
               "previewResult = %{public}s",
               ret, previewResult.c_str());
  return ret;
}

int32_t
PrintServiceProxy::QueryPrinterCapability(const std::string &printerId) {
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(printerId);
  PRINT_HILOGD("PrintServiceProxy QueryPrinterCapability started.");
  int32_t ret =
      Remote()->SendRequest(CMD_QUERYPRINTERCAPABILITY, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("QueryPrinterCapability, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD(
      "PrintServiceProxy QueryPrinterCapability out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::On(const std::string taskId, const std::string &type,
                              const sptr<IPrintCallback> &listener) {
  PRINT_HILOGD("PrintServiceProxy::On listener=%{public}p",
               listener.GetRefPtr());
  if (listener == nullptr) {
    PRINT_HILOGE("listener is nullptr");
    return E_PRINT_INVALID_PARAMETER;
  }

  if (type.empty()) {
    PRINT_HILOGE("PrintServiceProxy::On type is null.");
    return E_PRINT_INVALID_PARAMETER;
  }

  MessageParcel data, reply;
  MessageOption option;

  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(taskId);
  data.WriteString(type);
  data.WriteRemoteObject(listener->AsObject().GetRefPtr());
  int32_t ret = Remote()->SendRequest(CMD_ON, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("On, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy On out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::Off(const std::string taskId,
                               const std::string &type) {
  PRINT_HILOGD("PrintServiceProxy::Off in");
  if (type.empty()) {
    PRINT_HILOGE("PrintServiceProxy::On type is null.");
    return E_PRINT_INVALID_PARAMETER;
  }

  MessageParcel data, reply;
  MessageOption option;

  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(taskId);
  data.WriteString(type);
  int32_t ret = Remote()->SendRequest(CMD_OFF, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("On, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy Off out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::RegisterExtCallback(
    const std::string &extensionCID,
    const sptr<IPrintExtensionCallback> &listener) {
  PRINT_HILOGD("PrintServiceProxy::RegisterExtCallback in: %{public}s",
               extensionCID.c_str());
  MessageParcel data, reply;
  MessageOption option;

  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(extensionCID);
  data.WriteRemoteObject(listener->AsObject().GetRefPtr());

  int32_t ret = Remote()->SendRequest(CMD_REG_EXT_CB, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("RegisterExtCallback, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy RegisterExtCallback out. ret = [%{public}d]",
               ret);
  return ret;
}

int32_t
PrintServiceProxy::UnregisterAllExtCallback(const std::string &extensionId) {
  PRINT_HILOGD("PrintServiceProxy::UnregisterAllExtCallback in");
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(extensionId);
  int32_t ret = Remote()->SendRequest(CMD_UNREG_EXT_CB, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("UnregisterAllExtCallback, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD(
      "PrintServiceProxy UnregisterAllExtCallback out. ret = [%{public}d]",
      ret);
  return ret;
}

int32_t PrintServiceProxy::LoadExtSuccess(const std::string &extensionId) {
  PRINT_HILOGD("PrintServiceProxy::LoadExtSuccess in");
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(extensionId);
  int32_t ret = Remote()->SendRequest(CMD_LOAD_EXT, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("LoadExtSuccess, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy LoadExtSuccess out. ret = [%{public}d]", ret);
  return ret;
}

int32_t PrintServiceProxy::Read(std::vector<uint8_t> &fileRead,
                                const std::string &uri, uint32_t offset,
                                uint32_t max) {
  PRINT_HILOGD("PrintServiceProxy::Read in");
  MessageParcel data, reply;
  MessageOption option;
  data.WriteInterfaceToken(GetDescriptor());
  data.WriteString(uri);
  data.WriteUint32(offset);
  data.WriteUint32(max);
  int32_t ret = Remote()->SendRequest(CMD_READ_DATA, data, reply, option);
  if (ret != ERR_NONE) {
    PRINT_HILOGE("Read, rpc error code = %{public}d", ret);
    return E_PRINT_RPC_FAILURE;
  }

  ret = reply.ReadInt32();
  PRINT_HILOGD("PrintServiceProxy Read out. ret = [%{public}d]", ret);
  if (ret == E_PRINT_NONE) {
    reply.ReadUInt8Vector(&fileRead);
    PRINT_HILOGD("PrintServiceProxy Read succeeded.");
  }
  return ret;
}
} // namespace OHOS::Print
