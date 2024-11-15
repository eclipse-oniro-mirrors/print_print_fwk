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

namespace OHOS::Print {
const std::string PRINTER_EVENT_TYPE = "printerStateChange";
const std::string PRINTJOB_EVENT_TYPE = "jobStateChange";
const std::string EXTINFO_EVENT_TYPE = "extInfoChange";
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
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
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

napi_value NapiInnerPrint::GetPrinterPreference(napi_env env, napi_callback_info info)
{
    PRINT_HILOGI("Enter GetPrinterPreference---->");
    auto context = std::make_shared<InnerPrintContext>();
    if (context == nullptr) {
        PRINT_HILOGE("InnerPrintContext context nullptr");
        return nullptr;
    }
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
        napi_status status = napi_create_string_utf8(env, context->printerPreference.c_str(), NAPI_AUTO_LENGTH, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        PRINT_HILOGD("exec----");
        int32_t ret = PrintManagerClient::GetInstance()->GetPrinterPreference(context->printerId,
            context->printerPreference);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to Get PrinterPreference");
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
        PRINT_CALL_BASE(env, napi_typeof(env, argv[0], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[1], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerPreference is not a string", napi_string_expected);
        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
        std::string printerPreference = NapiPrintUtils::GetStringFromValueUtf8(env, argv[1]);
        if (printerPreference == "") {
            PRINT_HILOGE("Parse error!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->printerId = printerId;
        context->printerPreference = printerPreference;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->SetPrinterPreference(context->printerId,
            context->printerPreference);
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
    napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
    napi_value thisVal = nullptr;
    void *data = nullptr;
    PRINT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVal, &data));
    PRINT_ASSERT(env, argc == NapiPrintUtils::ARGC_TWO, "need 2 parameter!");

    napi_valuetype valuetype;
    PRINT_CALL(env, napi_typeof(env, argv[0], &valuetype));
    PRINT_ASSERT(env, valuetype == napi_string, "type is not a string");
    std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
    PRINT_HILOGD("type : %{public}s", type.c_str());

    if (!NapiInnerPrint::IsSupportType(type)) {
        PRINT_HILOGE("Event On type : %{public}s not support", type.c_str());
        return NapiThrowError(env, E_PRINT_INVALID_PARAMETER);
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
        return NapiThrowError(env, ret);
    }
    return nullptr;
}

napi_value NapiInnerPrint::Off(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    size_t argc = NapiPrintUtils::MAX_ARGC;
    napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
    napi_value thisVal = nullptr;
    void *data = nullptr;
    PRINT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVal, &data));
    PRINT_ASSERT(env, argc == NapiPrintUtils::ARGC_ONE || argc == NapiPrintUtils::ARGC_TWO, "need 1-2 parameter!");

    napi_valuetype valuetype;
    PRINT_CALL(env, napi_typeof(env, argv[0], &valuetype));
    PRINT_ASSERT(env, valuetype == napi_string, "type is not a string");
    std::string type = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
    PRINT_HILOGD("type : %{public}s", type.c_str());

    if (!NapiInnerPrint::IsSupportType(type)) {
        PRINT_HILOGE("Event Off type : %{public}s not support", type.c_str());
        return NapiThrowError(env, E_PRINT_INVALID_PARAMETER);
    }

    if (argc == NapiPrintUtils::ARGC_TWO) {
        valuetype = napi_undefined;
        napi_typeof(env, argv[1], &valuetype);
        PRINT_ASSERT(env, valuetype == napi_function, "callback is not a function");
    }

    int32_t ret = PrintManagerClient::GetInstance()->Off("", type);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("Failed to unregister event");
        return NapiThrowError(env, ret);
    }
    return nullptr;
}

napi_value NapiInnerPrint::StartGetPrintFile(napi_env env, napi_callback_info info)
{
    PRINT_HILOGI("StartGetPrintFile start ---->");
    napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
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
            return NapiThrowError(env, ret);
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
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "jobId is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_number, "event is not a number", napi_number_expected);
        std::string jobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        uint32_t event = NapiPrintUtils::GetUint32FromValue(env, argv[NapiPrintUtils::INDEX_ONE]);
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

bool NapiInnerPrint::IsSupportType(const std::string &type)
{
    if (type == PRINTER_EVENT_TYPE || type == PRINTJOB_EVENT_TYPE || type == EXTINFO_EVENT_TYPE ||
        type == PRINTER_CHANGE_EVENT_TYPE) {
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
    if (type >= DEFAULT_PRINTER_TYPE_SETTED_BY_USER &&
        type <= DEFAULT_PRINTER_TYPE_LAST_USED_PRINTER) {
        return true;
    }
    return false;
}

napi_value NapiInnerPrint::NapiThrowError(napi_env env, const int32_t errCode)
{
    napi_value result = nullptr;
    napi_create_error(env, NapiPrintUtils::CreateInt32(env, errCode),
        NapiPrintUtils::CreateStringUtf8(env, NapiPrintUtils::GetPrintErrorMsg(errCode)), &result);
    napi_throw(env, result);
    return nullptr;
}
} // namespace OHOS::Print
