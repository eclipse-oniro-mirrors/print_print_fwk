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

#include "napi_inner_print.h"

#include "async_call.h"
#include "napi_print_utils.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "print_parse_type.h"
#include "print_task.h"

namespace OHOS::Print {
napi_value NapiInnerPrint::QueryExtensionInfo(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == PrintNapiUtils::NO_ARG, " should 0 parameter!", napi_invalid_arg);
        PRINT_HILOGD("input over---->");
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        napi_status status = napi_create_array(env, result);
        uint32_t PrinterExtensionInfoLength = context->arrayPrinterExtensionInfo.size();
        for (uint32_t i = 0; i < PrinterExtensionInfoLength; i++) {
            PRINT_HILOGD(
                "PrintServiceProxy, ExtensionId = %{public}d", context->arrayPrinterExtensionInfo[i].GetExtensionId());
            PRINT_HILOGD(
                "PrintServiceProxy, VendorId = %{public}d", context->arrayPrinterExtensionInfo[i].GetVendorId());
            PRINT_HILOGD("PrintServiceProxy, VendorName = %{public}s",
                context->arrayPrinterExtensionInfo[i].GetVendorName().c_str());
            PRINT_HILOGD(
                "PrintServiceProxy, VendorIcon = %{public}d", context->arrayPrinterExtensionInfo[i].GetVendorIcon());
            PRINT_HILOGD(
                "PrintServiceProxy, Version = %{public}s", context->arrayPrinterExtensionInfo[i].GetVersion().c_str());
            napi_value PrinterInfo;
            napi_create_object(env, &PrinterInfo);
            PrintNapiUtils::SetUint32Property(
                env, PrinterInfo, "extensionId", context->arrayPrinterExtensionInfo[i].GetExtensionId());
            PrintNapiUtils::SetUint32Property(
                env, PrinterInfo, "vendorId", context->arrayPrinterExtensionInfo[i].GetVendorId());
            PrintNapiUtils::SetStringPropertyUtf8(
                env, PrinterInfo, "vendorName", context->arrayPrinterExtensionInfo[i].GetVendorName().c_str());
            PrintNapiUtils::SetUint32Property(
                env, PrinterInfo, "vendorIcon", context->arrayPrinterExtensionInfo[i].GetVendorIcon());
            PrintNapiUtils::SetStringPropertyUtf8(
                env, PrinterInfo, "version", context->arrayPrinterExtensionInfo[i].GetVersion().c_str());
            status = napi_set_element(env, *result, i, PrinterInfo);
        }
        PRINT_HILOGD("output ---- status[%{public}d]", status);
        PRINT_HILOGD("ouput over---->");
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        PRINT_HILOGD("exec enter---->");
        context->result = PrintManagerClient::GetInstance()->QueryAllExtension(context->arrayPrinterExtensionInfo);
        if (context->result == true) {
            PRINT_HILOGD("exec over---->");
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StartDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StartDiscovery---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        uint32_t result_size = 0;
        napi_get_array_length(env, argv[PrintNapiUtils::FIRST_ARGV], &result_size);
        napi_value array = argv[PrintNapiUtils::FIRST_ARGV];
        bool isArray = false;
        napi_is_array(env, array, &isArray);
        NAPI_ASSERT_BASE(env, isArray, " is not array!", napi_invalid_arg);
        for (uint32_t i = 0; i < result_size; i++) {
            napi_value value;
            napi_get_element(env, array, i, &value);
            uint32_t valueNumber;
            napi_get_value_uint32(env, value, &valueNumber);
            PRINT_HILOGD("output for :---- extensionVector value is :[%{public}d]", valueNumber);
            context->extensionVector.push_back((int32_t)valueNumber);
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->StartDiscoverPrinter(context->extensionVector);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StopDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StopDiscovery---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 0, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::ConnectPrint(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ConnectPrint---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, "should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerId number is not a number", napi_invalid_arg);
        uint32_t printId;
        napi_get_value_uint32(env, argv[PrintNapiUtils::FIRST_ARGV], &printId);
        PRINT_HILOGD("printId : %{public}d", printId);
        context->printConnId = printId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->ConnectPrinter(context->printConnId);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::DisconnectPrint(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter DisconnectPrint---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerId number is not a number", napi_invalid_arg);
        uint32_t printId;
        napi_get_value_uint32(env, argv[PrintNapiUtils::FIRST_ARGV], &printId);
        PRINT_HILOGD("printId : %{public}d", printId);
        context->printDisConnId = printId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->DisconnectPrinter(context->printDisConnId);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StartPrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StartPrintJob---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_value value = argv[PrintNapiUtils::FIRST_ARGV];
        PrintJob printJob;
        if (!ParseType::ParseJob(env, value, printJob)) {
            PRINT_HILOGD("ParseJob type error!");
        }
        context->printStartJob = printJob;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->StartPrintJob(context->printStartJob);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::CancelPrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter CancelPrintJob---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_value value = argv[PrintNapiUtils::FIRST_ARGV];
        PrintJob printJob;
        if (!ParseType::ParseJob(env, value, printJob)) {
            PRINT_HILOGD("ParseJob type error!");
        }
        context->printCancelJob = printJob;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->CancelPrintJob(context->printCancelJob);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context), 0);
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::RequestPreview(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_value value = argv[PrintNapiUtils::FIRST_ARGV];
        PrintJob printJob;
        if (!ParseType::ParseJob(env, value, printJob)) {
            PRINT_HILOGD("ParseJob type error!");
        }
        context->printReqPreviewJob = printJob;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_string_utf8(env, context->previewResult.c_str(), NAPI_AUTO_LENGTH, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result =
            PrintManagerClient::GetInstance()->RequestPreview(context->printReqPreviewJob, context->previewResult);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryCapability(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryCapability---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "number is not a number", napi_invalid_arg);
        uint32_t number;
        napi_get_value_uint32(env, argv[PrintNapiUtils::FIRST_ARGV], &number);
        PRINT_HILOGD("printjob : %{public}d", number);
        context->printCapacityId = number;
        PRINT_HILOGD("input over---->");
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        context->printerCapability.ConvertToJs(env, result);
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->QueryPrinterCapability(
            context->printCapacityId, context->printerCapability); //
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::On(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    napi_value result = nullptr;
    size_t argc = PrintNapiUtils::MAX_ARGC;
    napi_value argv[PrintNapiUtils::MAX_ARGC] = { nullptr };
    napi_value thisVal = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVal, &data));
    if (argc != PrintNapiUtils::ONE_ARG) {
        PRINT_HILOGE("Wrong number of arguments, requires 1");
        return result;
    }

    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype));
    NAPI_ASSERT(env, valuetype == napi_string, "type is not a string");
    char event[PrintNapiUtils::MAX_LEN] = { 0 };
    size_t len = 0;
    napi_get_value_string_utf8(env, argv[PrintNapiUtils::FIRST_ARGV], event, PrintNapiUtils::MAX_LEN, &len);
    std::string type = event;
    PRINT_HILOGD("type : %{public}s", type.c_str());

    PrintTask *task;
    PRINT_HILOGD("napi_unwrap begin.");
    NAPI_CALL(env, napi_unwrap(env, thisVal, reinterpret_cast<void **>(&task)));
    PRINT_HILOGD("state judge begin.");
    if (task->IsSupportPrinterStateType(type)) {
        PRINT_HILOGD("State type is Printer State. value is : %{public}s", type.c_str());
    } else if (task->IsSupportJobStateType(type)) {
        PRINT_HILOGD("State type is Print Job State. value is : %{public}s", type.c_str());
    } else {
        PRINT_HILOGD("state error!");
        return result;
    }
    PRINT_HILOGD("state judge end.");
    napi_ref callbackRef = nullptr;
    napi_create_reference(env, argv[argc - 1], 1, &callbackRef);
    return nullptr;
}

napi_value NapiInnerPrint::Off(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter Off---->");
    if (!PrintManagerClient::GetInstance()->LoadServer()) {
        PRINT_HILOGE("load print server fail");
        return nullptr;
    }
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGW("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == PrintNapiUtils::ONE_ARG, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_string, "valuetype is not a number", napi_invalid_arg);
        char buf[PrintNapiUtils::MAX_LEN] = {};
        size_t len = 0;
        napi_get_value_string_utf8(env, argv[PrintNapiUtils::FIRST_ARGV], buf, PrintNapiUtils::MAX_LEN, &len);
        PRINT_HILOGD("printerId :");
        context->type = buf;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->Off(context->type);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

int32_t NapiInnerPrint::GetEventType(const std::string &type)
{
    if (type == EVENT_SUCCESS) {
        return TWO_ARG_EVENT;
    } else if (type == EVENT_FAIL) {
        return ONE_ARG_EVENT;
    }
    return NO_ARG_EVENT;
}

sptr<IPrintCallback> NapiInnerPrint::CreateNotify(napi_env env, const std::string &type, napi_ref callbackRef)
{
    sptr<IPrintCallback> listener = nullptr;
    int32_t eventType = GetEventType(type);
    switch (eventType) {
        case NO_ARG_EVENT:
            break;

        case ONE_ARG_EVENT:
            break;

        case TWO_ARG_EVENT:
            break;

        default:
            PRINT_HILOGE("not support event type");
            break;
    }
    return listener;
}
} // namespace OHOS::Print
