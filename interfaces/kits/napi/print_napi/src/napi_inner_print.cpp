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

#include "napi_print_utils.h"
#include "print_callback.h"
#include "print_extension_info_helper.h"
#include "print_job_helper.h"
#include "print_attributes_helper.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "print_task.h"
#include "iprint_adapter_inner.h"
#include "printer_info_helper.h"
#include "printer_preferences_helper.h"
#include "ppd_info_helper.h"
#include "print_util.h"

namespace OHOS::Print {
const std::string PRINTER_EVENT_TYPE = "printerStateChange";
const std::string PRINTJOB_EVENT_TYPE = "jobStateChange";
const std::string EXTINFO_EVENT_TYPE = "extInfoChange";
const std::string PRINT_QUERY_INFO_EVENT_TYPE = "printerInfoQuery";
const uint32_t ARRAY_LENGTH_ONE_THOUSAND = 1000;

napi_value NapiInnerPrint::QueryExtensionInfo(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        napi_status status = napi_create_array(env, result);
        uint32_t index = 0;
        for (auto extInfo : context->allExtensionInfos) {
            PRINT_HILOGD("ExtensionId = %{public}s", extInfo.GetExtensionId().c_str());
            PRINT_HILOGD("VendorId = %{public}s", extInfo.GetVendorId().c_str());
            PRINT_HILOGD("VendorName = %{public}s", extInfo.GetVendorName().c_str());
            PRINT_HILOGD("VendorIcon = %{public}d", extInfo.GetVendorIcon());
            PRINT_HILOGD("Version = %{public}s", extInfo.GetVersion().c_str());
            status = napi_set_element(env, *result, index++, PrintExtensionInfoHelper::MakeJsObject(env, extInfo));
            if (status != napi_ok) {
                PRINT_HILOGE("napi_set_element failed");
            }
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->QueryAllExtension(context->allExtensionInfos);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query all ext info");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StartDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StartDiscovery---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        bool isArray = false;
        napi_is_array(env, argv[NapiPrintUtils::INDEX_ZERO], &isArray);
        PRINT_ASSERT_BASE(env, isArray, " is not array!", napi_array_expected);

        uint32_t len = 0;
        napi_get_array_length(env, argv[0], &len);
        if (len > ARRAY_LENGTH_ONE_THOUSAND) {
            PRINT_HILOGE("The length of array is too long");
            return napi_invalid_arg;
        }

        for (uint32_t index = 0; index < len; index++) {
            napi_value value;
            napi_get_element(env, argv[NapiPrintUtils::INDEX_ZERO], index, &value);
            std::string extensionId = NapiPrintUtils::GetStringFromValueUtf8(env, value);
            PRINT_HILOGD("output for :---- extensionList value is :[%{public}s]", extensionId.c_str());
            if (extensionId != "") {
                context->extensionList.emplace_back(extensionId);
            }
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->StartDiscoverPrinter(context->extensionList);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to start discover printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StopDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StopDiscovery---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to stop discover printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::ConnectPrinter(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ConnectPrinter---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerId : %{private}s", printerId.c_str());
        context->printerId = printerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->ConnectPrinter(context->printerId);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to connect the printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::DisconnectPrinter(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter DisconnectPrinter---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerId : %{private}s", printerId.c_str());
        context->printerId = printerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->DisconnectPrinter(context->printerId);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to connect the printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StartPrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StartPrintJob---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        auto printJobPtr = PrintJobHelper::BuildFromJs(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printJobPtr == nullptr) {
            PRINT_HILOGE("ParseJob type error!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->printJob = *printJobPtr;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        context->printJob.Dump();
        int32_t ret = PrintManagerClient::GetInstance()->StartPrintJob(context->printJob);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to start print job");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StartRawPrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StartRawPrintJob---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        auto printJobPtr = PrintJobHelper::BuildRawPrintJobFromJs(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printJobPtr == nullptr) {
            PRINT_HILOGE("ParseJob type error!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->printJob = *printJobPtr;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        context->printJob.Dump();
        int32_t ret = PrintManagerClient::GetInstance()->StartNativePrintJob(context->printJob);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to start raw print job");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::CancelPrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter CancelPrintJob---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "jobId is not a string", napi_string_expected);
        std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (jobId == "") {
            PRINT_HILOGE("Parse JobId error!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->jobId = jobId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        context->printJob.Dump();
        int32_t ret = PrintManagerClient::GetInstance()->CancelPrintJob(context->jobId);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to start print job");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::RestartPrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter RestartPrintJob---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "jobId is not a string", napi_string_expected);
        std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (jobId == "") {
            PRINT_HILOGE("Parse JobId error!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->jobId = jobId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        context->printJob.Dump();
        int32_t ret = PrintManagerClient::GetInstance()->RestartPrintJob(context->jobId);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to start print job");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::CheckPreferencesConflicts(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter CheckPreferencesConflicts---->");
    auto context = std::make_shared<InnerPrintContext>();
    
    auto input = [context](
        napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_THREE, " should 3 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "changedType is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_TWO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_object, "printerPreference is not an object", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGI("NapiInnerPrint, printerId = %{public}s", printerId.c_str());
        std::string changedType = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ONE]);
        auto preferencesPtr = PrinterPreferencesHelper::BuildFromJs(env, argv[NapiPrintUtils::INDEX_TWO]);
        if (preferencesPtr == nullptr) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("printerPreference format error!");
            return napi_invalid_arg;
        }
        context->printerId = printerId;
        context->changedType = changedType;
        context->printerPreference = *preferencesPtr;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_array(env, result);
        uint32_t index = 0;
        for (auto conflictingOption : context->conflictingOptions) {
            PRINT_HILOGD("conflictingOption = %{public}s", conflictingOption.c_str());
            status = napi_set_element(env, *result, index++, NapiPrintUtils::CreateStringUtf8(env, conflictingOption));
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->CheckPreferencesConflicts(
            context->printerId, context->changedType, context->printerPreference, context->conflictingOptions);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("CheckPreferencesConflicts failed!");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::CheckPrintJobConflicts(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter CheckPrintJobConflicts---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "changedType is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_object, "printJob is not an object", napi_string_expected);
        std::string changedType = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        auto printJobPtr = PrintJobHelper::BuildFromJs(env, argv[NapiPrintUtils::INDEX_ONE]);
        if (printJobPtr == nullptr) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("printJob format error!");
            return napi_invalid_arg;
        }
        context->changedType = changedType;
        context->printJob = *printJobPtr;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_array(env, result);
        uint32_t index = 0;
        for (auto conflictingOption : context->conflictingOptions) {
            PRINT_HILOGD("conflictingOption = %{public}s", conflictingOption.c_str());
            status = napi_set_element(env, *result, index++, NapiPrintUtils::CreateStringUtf8(env, conflictingOption));
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->CheckPrintJobConflicts(context->changedType,
            context->printJob, context->conflictingOptions);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("CheckPrintJobConflicts failed!");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::RequestPreview(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        auto printJobPtr = PrintJobHelper::BuildFromJs(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printJobPtr == nullptr) {
            PRINT_HILOGE("ParseJob type error!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->printJob = *printJobPtr;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_string_utf8(env, context->previewResult.c_str(), NAPI_AUTO_LENGTH, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        PRINT_HILOGD("exec----");
        context->printJob.Dump();
        int32_t ret = PrintManagerClient::GetInstance()->RequestPreview(context->printJob, context->previewResult);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to request preview of print job");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryCapability(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryCapability---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId number is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerId : %{private}s", printerId.c_str());
        context->printerId = printerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapability(context->printerId);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query capability of printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryAllPrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryAllPrintJob---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        napi_status status = napi_create_array(env, result);
        uint32_t index = 0;
        for (auto printJob : context->allPrintJobs) {
            PRINT_HILOGD("PrinterId = %{public}s", printJob.GetPrinterId().c_str());
            PRINT_HILOGD("JobId = %{public}s", printJob.GetJobId().c_str());
            status = napi_set_element(env, *result, index++, PrintJobHelper::MakeJsObject(env, printJob));
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->QueryAllPrintJob(context->allPrintJobs);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query printJobList");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryAllActivePrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGI("Enter QueryAllActivePrintJob---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        napi_status status = napi_create_array(env, result);
        uint32_t index = 0;
        for (auto printJob : context->allPrintJobs) {
            PRINT_HILOGD("PrinterId = %{public}s", printJob.GetPrinterId().c_str());
            PRINT_HILOGD("JobId = %{public}s", printJob.GetJobId().c_str());
            status = napi_set_element(env, *result, index++, PrintJobHelper::MakeJsObject(env, printJob));
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->QueryAllActivePrintJob(context->allPrintJobs);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query printJobList");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryPrintJobById(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryPrintJobById---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId number is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerId : %{private}s", printerId.c_str());
        context->printerId = printerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        *result = PrintJobHelper::MakeJsObject(env, context->printJob);
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->QueryPrintJobById(context->printerId, context->printJob);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query printJob from printList");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::SetPrinterPreference(napi_env env, napi_callback_info info)
{
    PRINT_HILOGI("Enter SetPrinterPreference---->");
    auto context = std::make_shared<InnerPrintContext>();
    if (context == nullptr) {
        PRINT_HILOGE("InnerPrintContext context nullptr");
        return nullptr;
    }
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_object, "printerPreference is not an object", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        auto preferencesPtr = PrinterPreferencesHelper::BuildFromJs(env, argv[NapiPrintUtils::INDEX_ONE]);
        if (preferencesPtr == nullptr) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("printerPreference format error!");
            return napi_invalid_arg;
        }
        context->printerId = printerId;
        context->printerPreference = *preferencesPtr;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret =
            PrintManagerClient::GetInstance()->SetPrinterPreference(context->printerId, context->printerPreference);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to SetPrinterPreference");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::On(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    size_t argc = NapiPrintUtils::MAX_ARGC;
    napi_value argv[NapiPrintUtils::MAX_ARGC] = {nullptr};
    napi_value thisVal = nullptr;
    void *data = nullptr;
    PRINT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVal, &data));
    PRINT_ASSERT(env, argc == NapiPrintUtils::ARGC_TWO, "need 2 parameter!");

    napi_valuetype valuetype;
    PRINT_CALL(env, napi_typeof(env, argv[0], &valuetype));
    PRINT_ASSERT(env, valuetype == napi_string, "type is not a string");
    std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
    PRINT_HILOGD("type : %{public}s", type.c_str());

    if (type == PRINTER_EVENT_TYPE || type == PRINTJOB_EVENT_TYPE || type == EXTINFO_EVENT_TYPE ||
        type == PRINT_QUERY_INFO_EVENT_TYPE) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            NapiThrowError(env, E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return nullptr;
        }
    }

    if (!NapiInnerPrint::IsSupportType(type)) {
        PRINT_HILOGE("Event On type : %{public}s not support", type.c_str());
        NapiThrowError(env, E_PRINT_INVALID_PARAMETER);
        return nullptr;
    }

    valuetype = napi_undefined;
    napi_typeof(env, argv[1], &valuetype);
    PRINT_ASSERT(env, valuetype == napi_function, "callback is not a function");

    napi_ref callbackRef = NapiPrintUtils::CreateReference(env, argv[1]);
    sptr<IPrintCallback> callback = new (std::nothrow) PrintCallback(env, callbackRef);
    if (callback == nullptr) {
        NapiPrintUtils::DeleteReference(env, callbackRef);
        PRINT_HILOGE("create print callback object fail");
        return nullptr;
    }
    int32_t ret = PrintManagerClient::GetInstance()->On("", type, callback);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("Failed to register event");
        NapiThrowError(env, ret);
        return nullptr;
    }
    return nullptr;
}

napi_value NapiInnerPrint::Off(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    size_t argc = NapiPrintUtils::MAX_ARGC;
    napi_value argv[NapiPrintUtils::MAX_ARGC] = {nullptr};
    napi_value thisVal = nullptr;
    void *data = nullptr;
    PRINT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVal, &data));
    PRINT_ASSERT(env, argc == NapiPrintUtils::ARGC_ONE || argc == NapiPrintUtils::ARGC_TWO, "need 1-2 parameter!");

    napi_valuetype valuetype;
    PRINT_CALL(env, napi_typeof(env, argv[0], &valuetype));
    PRINT_ASSERT(env, valuetype == napi_string, "type is not a string");
    std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
    PRINT_HILOGD("type : %{public}s", type.c_str());

    if (type == PRINTER_EVENT_TYPE || type == PRINTJOB_EVENT_TYPE || type == EXTINFO_EVENT_TYPE ||
        type == PRINT_QUERY_INFO_EVENT_TYPE) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            NapiThrowError(env, E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return nullptr;
        }
    }

    if (!NapiInnerPrint::IsSupportType(type)) {
        PRINT_HILOGE("Event Off type : %{public}s not support", type.c_str());
        NapiThrowError(env, E_PRINT_INVALID_PARAMETER);
        return nullptr;
    }

    if (argc == NapiPrintUtils::ARGC_TWO) {
        valuetype = napi_undefined;
        napi_typeof(env, argv[1], &valuetype);
        PRINT_ASSERT(env, valuetype == napi_function, "callback is not a function");
    }

    int32_t ret = PrintManagerClient::GetInstance()->Off("", type);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("Failed to unregister event");
        NapiThrowError(env, ret);
        return nullptr;
    }
    return nullptr;
}

napi_value NapiInnerPrint::StartGetPrintFile(napi_env env, napi_callback_info info)
{
    PRINT_HILOGI("StartGetPrintFile start ---->");
    if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
        PRINT_HILOGE("Non-system applications use system APIS!");
        NapiThrowError(env, E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
        return nullptr;
    }
    napi_value argv[NapiPrintUtils::MAX_ARGC] = {nullptr};
    size_t argc = NapiPrintUtils::GetJsVal(env, info, argv, NapiPrintUtils::MAX_ARGC);
    PRINT_ASSERT(env, argc == NapiPrintUtils::ARGC_FOUR, "StartGetPrintFile need 4 parameter!");

    napi_valuetype valuetype;
    PRINT_CALL(env, napi_typeof(env, argv[0], &valuetype));
    PRINT_ASSERT(env, valuetype == napi_string, "type is not a string");
    std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);

    if (static_cast<uint32_t>(argc) > NapiPrintUtils::INDEX_THREE) {
        napi_ref callbackRef = NapiPrintUtils::CreateReference(env, argv[NapiPrintUtils::INDEX_THREE]);
        sptr<IPrintCallback> callback = new (std::nothrow) PrintCallback(env, callbackRef);
        if (callback == nullptr) {
            NapiPrintUtils::DeleteReference(env, callbackRef);
            PRINT_HILOGE("create startGetPrintFile callback object fail");
            return nullptr;
        }
        int32_t retCallback = PrintManagerClient::GetInstance()->On("", PRINT_GET_FILE_CALLBACK_ADAPTER, callback);
        if (retCallback != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to register startGetPrintFile callback");
            NapiThrowError(env, retCallback);
            return nullptr;
        }
    }

    auto printAttributes = PrintAttributesHelper::BuildFromJs(env, argv[1]);
    if (printAttributes == nullptr) {
        PRINT_HILOGE("printAttributes is nullptr");
        return nullptr;
    }
    if (static_cast<uint32_t>(argc) > NapiPrintUtils::INDEX_TWO) {
        uint32_t fd = NapiPrintUtils::GetUint32FromValue(env, argv[NapiPrintUtils::INDEX_TWO]);
        int32_t ret = PrintManagerClient::GetInstance()->StartGetPrintFile(jobId, *printAttributes, fd);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to StartGetPrintFile");
            NapiThrowError(env, ret);
            return nullptr;
        }
    }
    return nullptr;
}

napi_value NapiInnerPrint::NotifyPrintService(napi_env env, napi_callback_info info)
{
    PRINT_HILOGI("Enter NotifyPrintService---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[0], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "jobId is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[1], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "info type is not a string", napi_string_expected);
        std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
        std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[1]);
        if (type == "") {
            PRINT_HILOGE("Parse type error!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->jobId = jobId;
        context->type = type;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->NotifyPrintService(context->jobId, context->type);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to NotifyPrintService");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryAddedPrinter(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryAddedPrinter---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        napi_status status = napi_create_array(env, result);
        uint32_t index = 0;
        for (auto printerId : context->allPrinters) {
            PRINT_HILOGD("PrinterId = %{public}s", printerId.c_str());
            status = napi_set_element(env, *result, index++, NapiPrintUtils::CreateStringUtf8(env, printerId));
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->QueryAddedPrinter(context->allPrinters);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query printerList");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryPrinterInfoByPrinterId(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryPrinterInfoByPrinterId---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId number is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerId : %{public}s", printerId.c_str());
        context->printerId = printerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        *result = PrinterInfoHelper::MakeJsObject(env, context->printerInfo);
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret =
            PrintManagerClient::GetInstance()->QueryPrinterInfoByPrinterId(context->printerId, context->printerInfo);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query printerInfo from printerList");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::NotifyPrintServiceEvent(napi_env env, napi_callback_info info)
{
    PRINT_HILOGI("Enter NotifyPrintServiceEvent---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env,
            argc == NapiPrintUtils::ARGC_ONE || argc == NapiPrintUtils::ARGC_TWO,
            "should 1 or 2 parameter!",
            napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        uint32_t event = NapiPrintUtils::GetUint32FromValue(env, argv[NapiPrintUtils::INDEX_ZERO]);
        std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ONE]);
        PRINT_HILOGI("jobId: %{public}s, event : %{public}d", jobId.c_str(), event);
        if (!IsValidApplicationEvent(event)) {
            PRINT_HILOGE("invalid event");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->jobId = jobId;
        context->applicationEvent = event;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret =
            PrintManagerClient::GetInstance()->NotifyPrintServiceEvent(context->jobId, context->applicationEvent);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to NotifyPrintServiceEvent");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::SetDefaultPrinter(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter SetDefaultPrinter---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);

        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_number, "defaultPrinterType is not a number", napi_number_expected);
        uint32_t type = NapiPrintUtils::GetUint32FromValue(env, argv[NapiPrintUtils::INDEX_ONE]);
        if (!IsValidDefaultPrinterType(type)) {
            PRINT_HILOGE("invalid defaultPrinterType");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        PRINT_HILOGD("printerId : %{public}s", printerId.c_str());
        context->printerId = printerId;
        context->defaultPrinterType = type;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret =
            PrintManagerClient::GetInstance()->SetDefaultPrinter(context->printerId, context->defaultPrinterType);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to set default printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::GetAddedPrinterInfoById(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter GetAddedPrinterInfoById---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId number is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printerId.empty()) {
            PRINT_HILOGE("printerId is empty!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        PRINT_HILOGD("printerId : %{public}s", printerId.c_str());
        context->printerId = printerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        *result = PrinterInfoHelper::MakeJsObject(env, context->printerInfo);
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret =
            PrintManagerClient::GetInstance()->QueryPrinterInfoByPrinterId(context->printerId, context->printerInfo);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query printerInfo from printerList");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::AnalyzePrintEvents(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter AnalyzePrintEvents---->");
    auto context = std::make_shared<InnerPrintContext>();

    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should have 2 parameters!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "eventType is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        std::string eventType = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ONE]);
        PRINT_HILOGD("printerId : %{private}s, eventType: %{private}s", printerId.c_str(), eventType.c_str());
        if (printerId.empty() || eventType.empty()) {
            PRINT_HILOGE("parameter is empty!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->printerId = printerId;
        context->type = eventType;
        return napi_ok;
    };

    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_string_utf8(env, context->stateType_.c_str(), NAPI_AUTO_LENGTH, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };

    auto exec = [context](PrintAsyncCall::Context *ctx) {
        std::string detail;
        int32_t ret = PrintManagerClient::GetInstance()->AnalyzePrintEvents(context->printerId,
            context->type, detail);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query printerInfo from printerList");
            context->SetErrorIndex(ret);
        }
        context->stateType_ = detail;
    };

    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::AuthPrintJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter AuthPrintJob---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_THREE, " should 3 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "jobId is not a string", napi_string_expected);
        std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);

        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "userName is not a string", napi_string_expected);
        std::string userName = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ONE]);

        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_TWO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "userPasswd is not a string", napi_string_expected);
        char *userPasswd = NapiPrintUtils::GetCharPtrFromValueUtf8(env, argv[NapiPrintUtils::INDEX_TWO]);
        
        context->jobId = jobId;
        context->userName = userName;
        context->userPasswd = userPasswd;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            PrintUtil::SafeDeleteAuthInfo(context->userPasswd);
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret =
            PrintManagerClient::GetInstance()->AuthPrintJob(context->jobId, context->userName, context->userPasswd);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to set default printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryAllPrinterPpds(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryAllPrinterPpds---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGI("QueryAllPrinterPpds output Enter ---->");
        napi_status status = napi_create_array(env, result);
        if (status != napi_ok) {
            return status;
        }
        uint32_t index = 0;
        for (auto &ppdInfo : context->allPpdInfos) {
            PRINT_HILOGD("ppdName = %{public}s", ppdInfo.GetPpdName().c_str());
            status = napi_set_element(env, *result, index++, PpdInfoHelper::MakeJsSimpleObject(env, ppdInfo));
            if (status != napi_ok) {
                return status;
            }
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret =
            PrintManagerClient::GetInstance()->QueryAllPrinterPpds(context->allPpdInfos);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to query ppdList");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryPrinterInfoByIp(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryPrinterInfoByIp---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valueType;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valueType), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valueType == napi_string, "printerIp is not a string", napi_string_expected);
        std::string printerIp = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printerIp.empty()) {
            PRINT_HILOGE("printerIp is empty!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->printerId = printerIp;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret =
            PrintManagerClient::GetInstance()->QueryPrinterInfoByIp(context->printerId);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to Query printer info");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::ConnectPrinterByIpAndPpd(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ConnectPrinterByIpAndPpd---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_THREE, " should 3 parameter!", napi_invalid_arg);
        napi_valuetype valueType;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valueType), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valueType == napi_string, "printerIp is not a string", napi_string_expected);
        std::string printerIp = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valueType), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valueType == napi_string, "protocol is not a string", napi_string_expected);
        std::string protocol = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ONE]);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_TWO], &valueType), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valueType == napi_string, "ppdName is not a string", napi_string_expected);
        std::string ppdName = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_TWO]);
        context->printerId = printerIp;
        context->fileUri = protocol;
        context->type = ppdName;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret =
            PrintManagerClient::GetInstance()->ConnectPrinterByIpAndPpd(context->printerId,
                context->fileUri, context->type);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to connect printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::SavePdfFileJob(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter SavePdfFileJob---->");
    auto context = std::make_shared<InnerPrintContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameters!", napi_invalid_arg);
        napi_valuetype valueType;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valueType), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valueType == napi_string, "jobId is not a string", napi_string_expected);
        std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valueType), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valueType == napi_number, "fd is not a number", napi_number_expected);
        uint32_t fd = NapiPrintUtils::GetUint32FromValue(env, argv[NapiPrintUtils::INDEX_ONE]);
        context->jobId = jobId;
        context->fileOffset = fd;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (!NapiPrintUtils::CheckCallerIsSystemApp()) {
            PRINT_HILOGE("Non-system applications use system APIS!");
            context->result = false;
            context->SetErrorIndex(E_PRINT_ILLEGAL_USE_OF_SYSTEM_API);
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->SavePdfFileJob(context->jobId, context->fileOffset);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to save pdf file");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

bool NapiInnerPrint::IsSupportType(const std::string &type)
{
    if (type == PRINTER_EVENT_TYPE || type == PRINTJOB_EVENT_TYPE || type == EXTINFO_EVENT_TYPE ||
        type == PRINTER_CHANGE_EVENT_TYPE || type == PRINT_QUERY_INFO_EVENT_TYPE) {
        return true;
    }
    return false;
}

bool NapiInnerPrint::IsValidApplicationEvent(uint32_t event)
{
    if (event >= APPLICATION_CREATED && event <= APPLICATION_CLOSED_FOR_CANCELED) {
        return true;
    }
    return false;
}

bool NapiInnerPrint::IsValidDefaultPrinterType(uint32_t type)
{
    if (type >= DEFAULT_PRINTER_TYPE_SETTED_BY_USER && type <= DEFAULT_PRINTER_TYPE_LAST_USED_PRINTER) {
        return true;
    }
    return false;
}

void NapiInnerPrint::NapiThrowError(napi_env env, const int32_t errCode)
{
    napi_value result = nullptr;
    napi_create_error(env,
        NapiPrintUtils::CreateInt32(env, errCode),
        NapiPrintUtils::CreateStringUtf8(env, NapiPrintUtils::GetPrintErrorMsg(errCode)),
        &result);
    napi_throw(env, result);
}
}  // namespace OHOS::Print
