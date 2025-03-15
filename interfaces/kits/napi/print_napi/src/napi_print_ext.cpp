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
#include "printer_info_helper.h"
#include "printer_capability_helper.h"

namespace OHOS::Print {
napi_value NapiPrintExt::AddPrinters(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](
        napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        bool isArray = false;
        napi_is_array(env, argv[NapiPrintUtils::INDEX_ZERO], &isArray);
        PRINT_ASSERT_BASE(env, isArray, " is not array!", napi_array_expected);
        uint32_t len = 0;
        napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &len);
        for (uint32_t index = 0; index < len; index++) {
            napi_value value;
            napi_get_element(env, argv[NapiPrintUtils::INDEX_ZERO], index, &value);
            auto printerInfoPtr = PrinterInfoHelper::BuildFromJs(env, value);
            if (printerInfoPtr == nullptr) {
                context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
                PRINT_HILOGE("PrinterInfo format error!");
                return napi_invalid_arg;
            }
            printerInfoPtr->SetPrinterId(printerInfoPtr->GetPrinterId());
            context->printerInfos.emplace_back(*printerInfoPtr);
        }
        if (context->printerInfos.empty()) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("no valid printer info exists!");
            return napi_invalid_arg;
        }
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
        int32_t ret = PrintManagerClient::GetInstance()->AddPrinters(context->printerInfos);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::RemovePrinters(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);

        bool isArray = false;
        napi_is_array(env, argv[NapiPrintUtils::INDEX_ZERO], &isArray);
        PRINT_ASSERT_BASE(env, isArray, " is not array!", napi_array_expected);

        uint32_t len = 0;
        napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &len);

        for (uint32_t index = 0; index < len; index++) {
            napi_value value;
            napi_get_element(env, argv[NapiPrintUtils::INDEX_ZERO], index, &value);
            std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, value);
            if (printerId != "") {
                context->printerIds.emplace_back(printerId);
            }
        }
        if (context->printerIds.empty()) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("no valid printer info exists!");
            return napi_invalid_arg;
        }
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
        int32_t ret = PrintManagerClient::GetInstance()->RemovePrinters(context->printerIds);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to remove printers");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdatePrinters(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        bool isArray = false;
        napi_is_array(env, argv[NapiPrintUtils::INDEX_ZERO], &isArray);
        PRINT_ASSERT_BASE(env, isArray, " is not array!", napi_array_expected);
        uint32_t len = 0;
        napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &len);
        for (uint32_t index = 0; index < len; index++) {
            napi_value value;
            napi_get_element(env, argv[NapiPrintUtils::INDEX_ZERO], index, &value);
            auto printerInfoPtr = PrinterInfoHelper::BuildFromJs(env, value);
            if (printerInfoPtr == nullptr) {
                context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
                PRINT_HILOGE("PrinterInfo format error!");
                return napi_invalid_arg;
            }
            context->printerInfos.emplace_back(*printerInfoPtr);
        }
        if (context->printerInfos.empty()) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("no valid printer info exists!");
            return napi_invalid_arg;
        }
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
        int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinters(context->printerInfos);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to update printers");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdatePrinterState(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);

        PRINT_CALL_BASE(env, napi_typeof(env, argv[1], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_number, "printerStateis not a number", napi_number_expected);

        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerId : %{public}s", printerId.c_str());

        uint32_t printerState = NapiPrintUtils::GetUint32FromValue(env, argv[1]);
        PRINT_HILOGD("printerState : %{public}d", printerState);

        if (printerId == "" || !IsValidPrinterState(printerState)) {
            PRINT_HILOGE("invalid printer id or printer state");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }

        context->printerId = printerId;
        PRINT_HILOGD("context->printerId : %{private}s", context->printerId.c_str());
        context->printerState = printerState;
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
        int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterState(context->printerId, context->printerState);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to update state of printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdatePrintJobStateOnlyForSystemApp(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_THREE, " should 3 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printJobId is not a string", napi_string_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[1], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_number, "printJobState is not a number", napi_number_expected);
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_TWO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_number, "reason is not a number", napi_number_expected);
        std::string printJobId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        uint32_t printJobState = NapiPrintUtils::GetUint32FromValue(env, argv[1]);
        uint32_t jobSubState = NapiPrintUtils::GetUint32FromValue(env, argv[NapiPrintUtils::INDEX_TWO]);
        PRINT_HILOGD("printJobId : %{public}s, printerJobState : %{public}d", printJobId.c_str(), printJobState);
        PRINT_HILOGD("jobSubState : %{public}d", jobSubState);
        if (printJobId == "" || !IsValidPrintJobState(printJobState) || !IsValidPrintJobSubState(jobSubState)) {
            PRINT_HILOGE("invalid job id, job state or job substate");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->printJobId = printJobId;
        context->printJobState = printJobState;
        context->jobSubState = jobSubState;
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
        int32_t ret = PrintManagerClient::GetInstance()->UpdatePrintJobStateOnlyForSystemApp(context->printJobId,
            context->printJobState, context->jobSubState);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to update state of print job");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdateExtensionInfo(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "extInfo is not a string", napi_string_expected);

        std::string extInfo = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
        PRINT_HILOGD("extInfo : %{public}s", extInfo.c_str());

        if (extInfo == "") {
            PRINT_HILOGE("invalid extension id or extension information");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->extInfo = extInfo;
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
        int32_t ret = PrintManagerClient::GetInstance()->UpdateExtensionInfo(context->extInfo);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to update extension information");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::AddPrinterToCups(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter AddPrinterToCups---->");
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_THREE, " should 3 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerUri is not a string", napi_string_expected);

        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerName is not a string", napi_string_expected);

        std::string printerUri = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerUri : %{private}s", printerUri.c_str());
        context->printerUri = printerUri;

        std::string printerName = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ONE]);
        PRINT_HILOGD("printerName : %{private}s", printerName.c_str());
        context->printerName = printerName;

        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_TWO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerMake is not a string", napi_string_expected);
        std::string printerMake = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_TWO]);
        PRINT_HILOGD("printerMake : %{private}s", printerMake.c_str());
        context->printerMake = printerMake;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->AddPrinterToCups(context->printerUri, context->printerName,
            context->printerMake);
        PRINT_HILOGD("ret: %{public}d", ret);
        context->result = (ret == E_PRINT_NONE);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to set cups printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::QueryPrinterCapabilityByUri(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryPrinterCapabilityByUri---->");
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env,
            argc == NapiPrintUtils::ARGC_ONE || argc == NapiPrintUtils::ARGC_TWO,
            " should 1 or 2 parameter!",
            napi_invalid_arg);

        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerUri is not a string", napi_string_expected);

        std::string printerUri = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerUri : %{private}s", printerUri.c_str());
        context->printerUri = printerUri;

        if (argc == NapiPrintUtils::ARGC_TWO) {
            PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
            PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);

            std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ONE]);
            PRINT_HILOGD("printerId : %{private}s", printerId.c_str());
            context->printerId = printerId;
        }
        return napi_ok;
    };
    // promise return
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("output enter ---->");
        *result = PrinterCapabilityHelper::MakeJsObject(env, context->printerCaps);
        return napi_ok;
    };

    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->QueryPrinterCapabilityByUri(context->printerUri,
            context->printerId, context->printerCaps);
        context->result = (ret == E_PRINT_NONE);
        PRINT_HILOGD("ret: %d", ret);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to get printers caps");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::DeletePrinterFromCups(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter DeletePrinterFromCups---->");
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input =
        [context](
            napi_env env, size_t argc, napi_value *argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;

        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerName is not a string", napi_string_expected);

        std::string printerName = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        PRINT_HILOGD("printerName : %{private}s", printerName.c_str());
        context->printerName = printerName;

        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret =
            PrintManagerClient::GetInstance()->DeletePrinterFromCups(context->printerName);
        PRINT_HILOGD("ret: %d", ret);
        context->result = (ret == E_PRINT_NONE);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to delete cups printer");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::DiscoverUsbPrinters(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter DiscoverUsbPrinters---->");
    auto context = std::make_shared<NapiPrintExtContext>();
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
        for (auto info : context->printerInfos) {
            PRINT_HILOGD("PrinterId = %{public}s", info.GetPrinterId().c_str());
            PRINT_HILOGD("PrinterName = %{private}s", info.GetPrinterName().c_str());
            status = napi_set_element(env, *result, index++, PrinterInfoHelper::MakeJsObject(env, info));
        }
        return napi_ok;
    };
    auto exec = [context](PrintAsyncCall::Context *ctx) {
        int32_t ret = PrintManagerClient::GetInstance()->DiscoverUsbPrinters(context->printerInfos);
        context->result = (ret == E_PRINT_NONE);
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to discover usb printers");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::AddPrinterToDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter AddPrinterToDiscovery---->");
    auto context = std::make_shared<NapiPrintExtContext>();

    auto input =
        [context](
            napi_env env, size_t argc, napi_value* argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should have 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype);
        PRINT_ASSERT_BASE(env, valuetype == napi_object, " parameter is not an object!", napi_invalid_arg);

        auto printerInfoPtr = PrinterInfoHelper::BuildFromJs(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printerInfoPtr == nullptr) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("PrinterInfo format error!");
            return napi_invalid_arg;
        }

        context->printerInfos.emplace_back(*printerInfoPtr);
        PRINT_HILOGD("printerInfoPtr->GetPrinterId() = %{public}s", printerInfoPtr->GetPrinterId().c_str());

        return napi_ok;
    };

    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };

    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (context->printerInfos.empty()) {
            context->result = false;
            PRINT_HILOGE("printerInfos is empty!");
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->AddPrinterToDiscovery(context->printerInfos.front());
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to add printer");
            context->SetErrorIndex(ret);
        }
    };

    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdatePrinterInDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter UpdatePrinterInDiscovery---->");
    auto context = std::make_shared<NapiPrintExtContext>();

    auto input =
        [context](
            napi_env env, size_t argc, napi_value* argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should have 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype);
        PRINT_ASSERT_BASE(env, valuetype == napi_object, " parameter is not an object!", napi_invalid_arg);

        auto printerInfoPtr = PrinterInfoHelper::BuildFromJs(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printerInfoPtr == nullptr) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("PrinterInfo format error!");
            return napi_invalid_arg;
        }

        context->printerInfos.emplace_back(*printerInfoPtr);
        PRINT_HILOGD("printerInfoPtr->GetPrinterId() = %{public}s", printerInfoPtr->GetPrinterId().c_str());

        return napi_ok;
    };

    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };

    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (context->printerInfos.empty()) {
            context->result = false;
            PRINT_HILOGE("printerInfos is empty!");
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterInDiscovery(context->printerInfos.front());
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to update printer");
            context->SetErrorIndex(ret);
        }
    };

    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::RemovePrinterFromDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter RemovePrinterFromDiscovery---->");
    auto context = std::make_shared<NapiPrintExtContext>();

    auto input =
        [context](
            napi_env env, size_t argc, napi_value* argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should have 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        PRINT_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        PRINT_ASSERT_BASE(env, valuetype == napi_string, "printerId is not a string", napi_string_expected);

        std::string printerId = NapiPrintUtils::GetStringFromValueUtf8(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printerId.empty()) {
            PRINT_HILOGE("printerId is empty!");
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
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
        int32_t ret = PrintManagerClient::GetInstance()->RemovePrinterFromDiscovery(context->printerId);
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to add printer");
            context->SetErrorIndex(ret);
        }
    };

    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::UpdatePrinterInSystem(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter UpdatePrinterInSystem---->");
    auto context = std::make_shared<NapiPrintExtContext>();

    auto input =
        [context](
            napi_env env, size_t argc, napi_value* argv, napi_value self, napi_callback_info info) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should have 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype);
        PRINT_ASSERT_BASE(env, valuetype == napi_object, " parameter is not an object!", napi_invalid_arg);

        auto printerInfoPtr = PrinterInfoHelper::BuildFromJs(env, argv[NapiPrintUtils::INDEX_ZERO]);
        if (printerInfoPtr == nullptr) {
            context->SetErrorIndex(E_PRINT_INVALID_PARAMETER);
            PRINT_HILOGE("UpdatePrinterInSystem PrinterInfo format error!");
            return napi_invalid_arg;
        }

        context->printerInfos.emplace_back(*printerInfoPtr);
        PRINT_HILOGD("UpdatePrinterInSystem printerId = %{public}s", printerInfoPtr->GetPrinterId().c_str());

        return napi_ok;
    };

    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };

    auto exec = [context](PrintAsyncCall::Context *ctx) {
        if (context->printerInfos.empty()) {
            context->result = false;
            PRINT_HILOGE("UpdatePrinterInSystem printerInfos is empty!");
            return;
        }
        int32_t ret = PrintManagerClient::GetInstance()->UpdatePrinterInSystem(context->printerInfos.front());
        context->result = ret == E_PRINT_NONE;
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("UpdatePrinterInSystem Failed to update printer");
        }
    };

    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

bool NapiPrintExt::IsValidPrinterState(uint32_t state)
{
    if (state >= PRINTER_ADDED && state < PRINTER_UNKNOWN) {
        return true;
    }
    return false;
}

bool NapiPrintExt::IsValidPrintJobState(uint32_t state)
{
    if (state >= PRINT_JOB_PREPARED && state <= PRINT_JOB_UNKNOWN) {
        return true;
    }
    return false;
}

bool NapiPrintExt::IsValidPrintJobSubState(uint32_t subState)
{
    if (subState >= PRINT_JOB_COMPLETED_SUCCESS && subState <= PRINT_JOB_BLOCKED_UNKNOWN) {
        return true;
    }
    return false;
}

void NapiPrintExt::NapiThrowError(napi_env env, const int32_t errCode)
{
    napi_value result = nullptr;
    napi_create_error(env, NapiPrintUtils::CreateInt32(env, errCode),
        NapiPrintUtils::CreateStringUtf8(env, NapiPrintUtils::GetPrintErrorMsg(errCode)), &result);
    napi_throw(env, result);
}
}  // namespace OHOS::Print
