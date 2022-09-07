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

#include "async_call.h"
#include "napi_print_utils.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "print_parse_type.h"

namespace OHOS::Print {
napi_value NapiPrintExt::AddPrinters(napi_env env, napi_callback_info info)
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

    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_value array = argv[NapiPrintUtils::INDEX_ZERO];
        bool isArray = false;
        napi_is_array(env, array, &isArray);
        NAPI_ASSERT_BASE(env, isArray, " is not array!", napi_invalid_arg);

        uint32_t result_size;
        napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &result_size);

        PrinterInfo info_;
        for (uint32_t i = 0; i < result_size; i++) {
            napi_value value;
            napi_get_element(env, array, i, &value);
            if (!ParseType::ParseInfo(env, value, info_)) {
                PRINT_HILOGD("PrinterInfo is format error!");
            }
            context->printAddInfoVector.push_back(info_);
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->AddPrinters(context->printAddInfoVector);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiPrintExt::RemovePrinters(napi_env env, napi_callback_info info)
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

    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_value array = argv[NapiPrintUtils::INDEX_ZERO];
        bool isArray = false;
        napi_is_array(env, array, &isArray);
        NAPI_ASSERT_BASE(env, isArray, " is not array!", napi_invalid_arg);

        uint32_t result_size;
        napi_get_array_length(env, argv[NapiPrintUtils::INDEX_ZERO], &result_size);

        PrinterInfo info_;
        for (uint32_t i = 0; i < result_size; i++) {
            napi_value value;
            napi_get_element(env, array, i, &value);
            if (!ParseType::ParseInfo(env, value, info_)) {
                PRINT_HILOGD("PrinterInfo is format error!");
            }
            context->printRemoveInfoVector.push_back(info_);
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->RemovePrinters(context->printRemoveInfoVector);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}
napi_value NapiPrintExt::UpdatePrinterState(napi_env env, napi_callback_info info)
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

    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "valuetype is not a number", napi_invalid_arg);
        uint32_t printerId = 0;
        napi_get_value_uint32(env, argv[NapiPrintUtils::INDEX_ZERO], &printerId);
        PRINT_HILOGD("printerId : %{public}d", printerId);
        context->printerId = printerId;
        napi_valuetype valueSecondtype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valueSecondtype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valueSecondtype == napi_number, "valueSecondtype is not a string", napi_invalid_arg);
        uint32_t printerState = 0;
        napi_get_value_uint32(env, argv[NapiPrintUtils::INDEX_ONE], &printerState);
        PRINT_HILOGD("printerState : %{public}d", printerState);
        context->printerState = printerState;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result =
            PrintManagerClient::GetInstance()->UpdatePrinterState(context->printerId, context->printerState);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}
napi_value NapiPrintExt::UpdatePrintJobState(napi_env env, napi_callback_info info)
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

    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerJobState is not a number", napi_invalid_arg);
        uint32_t printerJobId = 0;
        napi_get_value_uint32(env, argv[NapiPrintUtils::INDEX_ZERO], &printerJobId);
        PRINT_HILOGD("printerJobId : %{public}d", printerJobId);
        context->printerJobId = printerJobId;
        napi_valuetype valueSecondtype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiPrintUtils::INDEX_ONE], &valueSecondtype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valueSecondtype == napi_number, "valueSecondtype is not a string", napi_invalid_arg);
        uint32_t printerJobState = 0;
        napi_get_value_uint32(env, argv[NapiPrintUtils::INDEX_ONE], &printerJobState);
        PRINT_HILOGD("printerJobState : %{public}d", printerJobState);
        context->printerJobState = printerJobState;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result =
            PrintManagerClient::GetInstance()->UpdatePrinterJobState(context->printerJobId, context->printerJobState);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}
} // namespace OHOS::Print
