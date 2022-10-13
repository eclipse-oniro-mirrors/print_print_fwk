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

#include "napi_print_ext.h"

#include "napi_print_utils.h"
#include "print_log.h"
#include "print_manager_client.h"

namespace OHOS::Print {
napi_value NapiPrintExt::AddPrinters(napi_env env, napi_callback_info info) {
  PRINT_HILOGD("Enter ---->");
  auto context = std::make_shared<NapiPrintExtContext>();
  auto input = [context](napi_env env, size_t argc, napi_value *argv,
                         napi_value self) -> napi_status {
    auto extensionId = NapiPrintUtils::GetExtensionId(env, argv);
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE,
                      " should 1 parameter!", napi_invalid_arg);
    bool isArray = false;
    napi_is_array(env, argv[NapiPrintUtils::INDEX_ZERO], &isArray);
    PRINT_ASSERT_BASE(env, isArray, " is not array!", napi_array_expected);

    uint32_t len = 0;
    napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &len);

    for (uint32_t index = 0; index < len; index++) {
      napi_value value;
      napi_get_element(env, argv[NapiPrintUtils::INDEX_ZERO], index, &value);
      auto printerInfoPtr = PrinterInfo::BuildFromJs(env, value);
      if (printerInfoPtr == nullptr) {
        context->SetErrorIndex(ERROR_INVALID_PARAMETER);
        PRINT_HILOGE("PrinterInfo format error!");
        return napi_invalid_arg;
      }
      printerInfoPtr->SetPrinterId(NapiPrintUtils::GetGlobalId(
          extensionId, printerInfoPtr->GetPrinterId()));
      PRINT_HILOGD("printerInfoPtr->GetPrinterId().c_str() = %{public}s",
                   printerInfoPtr->GetPrinterId().c_str());
      context->printerInfos.emplace_back(*printerInfoPtr);
    }
    if (context->printerInfos.empty()) {
      context->SetErrorIndex(ERROR_INVALID_PARAMETER);
      PRINT_HILOGE("no valid printer info exists!");
      return napi_invalid_arg;
    }
    return napi_ok;
  };
  auto output = [context](napi_env env, napi_value *result) -> napi_status {
    napi_status status = napi_get_boolean(env, context->result, result);
    PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]",
                 context->result ? "true" : "false", status);
    return status;
  };
  auto exec = [context](PrintAsyncCall::Context *ctx) {
    int32_t ret =
        PrintManagerClient::GetInstance()->AddPrinters(context->printerInfos);
    context->result = ret == ERROR_NONE;
    if (ret != ERROR_NONE) {
      PRINT_HILOGE("Failed to add printers");
      context->SetErrorIndex(ret);
    }
  };
  context->SetAction(std::move(input), std::move(output));
  PrintAsyncCall asyncCall(
      env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
  return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::RemovePrinters(napi_env env, napi_callback_info info) {
  PRINT_HILOGD("Enter ---->");
  auto context = std::make_shared<NapiPrintExtContext>();
  auto input = [context](napi_env env, size_t argc, napi_value *argv,
                         napi_value self) -> napi_status {
    auto extensionId = NapiPrintUtils::GetExtensionId(env, argv);
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());
    PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE,
                      " should 1 parameter!", napi_invalid_arg);

    bool isArray = false;
    napi_is_array(env, argv[NapiPrintUtils::INDEX_ZERO], &isArray);
    PRINT_ASSERT_BASE(env, isArray, " is not array!", napi_array_expected);

    uint32_t len = 0;
    napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &len);

    for (uint32_t index = 0; index < len; index++) {
      napi_value value;
      napi_get_element(env, argv[NapiPrintUtils::INDEX_ZERO], index, &value);
      std::string printerId =
          NapiPrintUtils::GetStringFromValueUtf8(env, value);
      if (printerId != "") {
        context->printerIds.emplace_back(
            NapiPrintUtils::GetGlobalId(extensionId, printerId));
      }
    }
    if (context->printerIds.empty()) {
      context->SetErrorIndex(ERROR_INVALID_PARAMETER);
      PRINT_HILOGE("no valid printer info exists!");
      return napi_invalid_arg;
    }
    return napi_ok;
  };
  auto output = [context](napi_env env, napi_value *result) -> napi_status {
    napi_status status = napi_get_boolean(env, context->result, result);
    PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]",
                 context->result ? "true" : "false", status);
    return status;
  };
  auto exec = [context](PrintAsyncCall::Context *ctx) {
    int32_t ret =
        PrintManagerClient::GetInstance()->RemovePrinters(context->printerIds);
    context->result = ret == ERROR_NONE;
    if (ret != ERROR_NONE) {
      PRINT_HILOGE("Failed to remove printers");
      context->SetErrorIndex(ret);
    }
  };
  context->SetAction(std::move(input), std::move(output));
  PrintAsyncCall asyncCall(
      env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
  return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdatePrinters(napi_env env, napi_callback_info info) {
  PRINT_HILOGD("Enter ---->");
  auto context = std::make_shared<NapiPrintExtContext>();
  auto input = [context](napi_env env, size_t argc, napi_value *argv,
                         napi_value self) -> napi_status {
    auto extensionId = NapiPrintUtils::GetExtensionId(env, argv);
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE,
                      " should 1 parameter!", napi_invalid_arg);
    bool isArray = false;
    napi_is_array(env, argv[NapiPrintUtils::INDEX_ZERO], &isArray);
    PRINT_ASSERT_BASE(env, isArray, " is not array!", napi_array_expected);

    uint32_t len = 0;
    napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &len);

    for (uint32_t index = 0; index < len; index++) {
      napi_value value;
      napi_get_element(env, argv[NapiPrintUtils::INDEX_ZERO], index, &value);
      auto printerInfoPtr = PrinterInfo::BuildFromJs(env, value);
      if (printerInfoPtr == nullptr) {
        context->SetErrorIndex(ERROR_INVALID_PARAMETER);
        PRINT_HILOGE("PrinterInfo format error!");
        return napi_invalid_arg;
      }
      printerInfoPtr->SetPrinterId(NapiPrintUtils::GetGlobalId(
          extensionId, printerInfoPtr->GetPrinterId()));
      context->printerInfos.emplace_back(*printerInfoPtr);
    }
    if (context->printerInfos.empty()) {
      context->SetErrorIndex(ERROR_INVALID_PARAMETER);
      PRINT_HILOGE("no valid printer info exists!");
      return napi_invalid_arg;
    }
    return napi_ok;
  };
  auto output = [context](napi_env env, napi_value *result) -> napi_status {
    napi_status status = napi_get_boolean(env, context->result, result);
    PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]",
                 context->result ? "true" : "false", status);
    return status;
  };
  auto exec = [context](PrintAsyncCall::Context *ctx) {
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(
        context->printerInfos);
    context->result = ret == ERROR_NONE;
    if (ret != ERROR_NONE) {
      PRINT_HILOGE("Failed to update printers");
      context->SetErrorIndex(ret);
    }
  };
  context->SetAction(std::move(input), std::move(output));
  PrintAsyncCall asyncCall(
      env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
  return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdatePrinterState(napi_env env,
                                            napi_callback_info info) {
  PRINT_HILOGD("Enter ---->");
  auto context = std::make_shared<NapiPrintExtContext>();
  auto input = [context](napi_env env, size_t argc, napi_value *argv,
                         napi_value self) -> napi_status {
    auto extensionId = NapiPrintUtils::GetExtensionId(env, argv);
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO,
                      " should 2 parameter!", napi_invalid_arg);
    napi_valuetype valuetype;
    PRINT_CALL_BASE(
        env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype),
        napi_invalid_arg);
    PRINT_ASSERT_BASE(env, valuetype == napi_string,
                      "printerId is not a string", napi_string_expected);

    PRINT_CALL_BASE(
        env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype),
        napi_invalid_arg);
    PRINT_ASSERT_BASE(env, valuetype == napi_number,
                      "printerStateis not a number", napi_number_expected);

    std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(
        env, argv[NapiPrintUtils::INDEX_ZERO]);
    PRINT_HILOGD("printerId : %{public}s", printerId.c_str());

    uint32_t printerState = NapiPrintUtils::GetUint32FromValue(
        env, argv[NapiPrintUtils::INDEX_ONE]);
    PRINT_HILOGD("printerState : %{public}d", printerState);

    if (printerId == "" || !IsValidPrinterState(printerState)) {
      PRINT_HILOGE("invalid printer id or printer state");
      context->SetErrorIndex(ERROR_INVALID_PARAMETER);
      return napi_invalid_arg;
    }

    context->printerId = NapiPrintUtils::GetGlobalId(extensionId, printerId);
    PRINT_HILOGD("context->printerId : %{public}s", context->printerId.c_str());
    context->printerState = printerState;
    return napi_ok;
  };
  auto output = [context](napi_env env, napi_value *result) -> napi_status {
    napi_status status = napi_get_boolean(env, context->result, result);
    PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]",
                 context->result ? "true" : "false", status);
    return status;
  };
  auto exec = [context](PrintAsyncCall::Context *ctx) {
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(
        context->printerId, context->printerState);
    context->result = ret == ERROR_NONE;
    if (ret != ERROR_NONE) {
      PRINT_HILOGE("Failed to update state of printer");
      context->SetErrorIndex(ret);
    }
  };
  context->SetAction(std::move(input), std::move(output));
  PrintAsyncCall asyncCall(
      env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
  return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdatePrintJobState(napi_env env,
                                             napi_callback_info info) {
  PRINT_HILOGD("Enter ---->");
  auto context = std::make_shared<NapiPrintExtContext>();
  auto input = [context](napi_env env, size_t argc, napi_value *argv,
                         napi_value self) -> napi_status {
    PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_THREE,
                      " should 3 parameter!", napi_invalid_arg);
    napi_valuetype valuetype;
    PRINT_CALL_BASE(
        env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype),
        napi_invalid_arg);
    PRINT_ASSERT_BASE(env, valuetype == napi_string,
                      "printJobId is not a string", napi_string_expected);

    PRINT_CALL_BASE(
        env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype),
        napi_invalid_arg);
    PRINT_ASSERT_BASE(env, valuetype == napi_number,
                      "printJobState is not a number", napi_number_expected);

    PRINT_CALL_BASE(
        env, napi_typeof(env, argv[NapiPrintUtils::INDEX_TWO], &valuetype),
        napi_invalid_arg);
    PRINT_ASSERT_BASE(env, valuetype == napi_number, "reason is not a number",
                      napi_number_expected);

    std::string printJobId = NapiPrintUtils::GetStringFromValueUtf8(
        env, argv[NapiPrintUtils::INDEX_ZERO]);
    PRINT_HILOGD("printJobId : %{public}s", printJobId.c_str());

    uint32_t printJobState = NapiPrintUtils::GetUint32FromValue(
        env, argv[NapiPrintUtils::INDEX_ONE]);
    PRINT_HILOGD("printerJobState : %{public}d", printJobState);

    uint32_t jobSubState = NapiPrintUtils::GetUint32FromValue(
        env, argv[NapiPrintUtils::INDEX_TWO]);
    PRINT_HILOGD("jobSubState : %{public}d", jobSubState);

    if (printJobId == "" || !IsValidPrintJobState(printJobState) ||
        !IsValidPrintJobSubState(jobSubState)) {
      PRINT_HILOGE("invalid job id, job state or job substate");
      context->SetErrorIndex(ERROR_INVALID_PARAMETER);
      return napi_invalid_arg;
    }

    context->printJobId = printJobId;
    context->printJobState = printJobState;
    context->jobSubState = jobSubState;
    return napi_ok;
  };
  auto output = [context](napi_env env, napi_value *result) -> napi_status {
    napi_status status = napi_get_boolean(env, context->result, result);
    PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]",
                 context->result ? "true" : "false", status);
    return status;
  };
  auto exec = [context](PrintAsyncCall::Context *ctx) {
    int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobState(
        context->printJobId, context->printJobState, context->jobSubState);
    context->result = ret == ERROR_NONE;
    if (ret != ERROR_NONE) {
      PRINT_HILOGE("Failed to update state of print job");
      context->SetErrorIndex(ret);
    }
  };
  context->SetAction(std::move(input), std::move(output));
  PrintAsyncCall asyncCall(
      env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
  return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdateExtensionInfo(napi_env env,
                                             napi_callback_info info) {
  PRINT_HILOGD("Enter ---->");
  auto context = std::make_shared<NapiPrintExtContext>();
  auto input = [context](napi_env env, size_t argc, napi_value *argv,
                         napi_value self) -> napi_status {
    auto extensionId = NapiPrintUtils::GetExtensionId(env, argv);
    PRINT_HILOGD("extensionId = %{public}s", extensionId.c_str());

    PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE,
                      " should 1 parameter!", napi_invalid_arg);
    napi_valuetype valuetype;
    PRINT_CALL_BASE(
        env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype),
        napi_invalid_arg);
    PRINT_ASSERT_BASE(env, valuetype == napi_string, "extInfo is not a string",
                      napi_string_expected);

    std::string extInfo = NapiPrintUtils::GetStringFromValueUtf8(
        env, argv[NapiPrintUtils::INDEX_ZERO]);
    PRINT_HILOGD("extInfo : %{public}s", extInfo.c_str());

    if (extensionId == "" || extInfo == "") {
      PRINT_HILOGE("invalid extension id or extension information");
      context->SetErrorIndex(ERROR_INVALID_PARAMETER);
      return napi_invalid_arg;
    }
    context->extensionId = extensionId;
    context->extInfo = extInfo;
    return napi_ok;
  };
  auto output = [context](napi_env env, napi_value *result) -> napi_status {
    napi_status status = napi_get_boolean(env, context->result, result);
    PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]",
                 context->result ? "true" : "false", status);
    return status;
  };
  auto exec = [context](PrintAsyncCall::Context *ctx) {
    int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(
        context->extensionId, context->extInfo);
    context->result = ret == ERROR_NONE;
    if (ret != ERROR_NONE) {
      PRINT_HILOGE("Failed to update extension information");
      context->SetErrorIndex(ret);
    }
  };
  context->SetAction(std::move(input), std::move(output));
  PrintAsyncCall asyncCall(
      env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
  return asyncCall.Call(env, exec);
}

bool NapiPrintExt::IsValidPrinterState(uint32_t state) {
  if (state >= PRINTER_ADDED && state < PRINTER_UNKNOWN) {
    return true;
  }
  return false;
}

bool NapiPrintExt::IsValidPrintJobState(uint32_t state) {
  if (state >= PRINT_JOB_PREPARED && state <= PRINT_JOB_UNKNOWN) {
    return true;
  }
  return false;
}

bool NapiPrintExt::IsValidPrintJobSubState(uint32_t subState) {
  if (subState >= PRINT_JOB_COMPLETED_SUCCESS &&
      subState <= PRINT_JOB_BLOCKED_UNKNOWN) {
    return true;
  }
  return false;
}
} // namespace OHOS::Print
