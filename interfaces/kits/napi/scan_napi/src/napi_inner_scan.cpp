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
#include <string>
#include "securec.h"
#include "napi_scan_utils.h"
#include "scan_log.h"
#include "scan_callback.h"
#include "scan_manager_client.h"
#include "scan_util.h"
#include "napi_inner_scan.h"
#include "napi_scan_helper.h"
#include "tokenid_kit.h"

namespace OHOS::Scan {
const std::string SCAN_DEVICE_FOUND = "scanDeviceFound";
const std::string SCAN_DEVICE_SYNC = "scanDeviceSync";
const std::string SCAN_DEVICE_ADD = "scanDeviceAdd";
const std::string SCAN_DEVICE_DEL = "scanDeviceDel";

napi_value NapiInnerScan::InitScan(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter InitScan---->");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->InitScan();
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to init the scan fwk");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::ExitScan(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter ExitScan---->");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->ExitScan();
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to exit");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::GetScannerList(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter GetScannerList---->");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        auto ScanManagerClientPtr = ScanManagerClient::GetInstance();
        if (ScanManagerClientPtr == nullptr) {
            SCAN_HILOGE("ScanManagerClientPtr is a nullptr");
            context->result = false;
            context->SetErrorIndex(E_SCAN_GENERIC_FAILURE);
            return;
        }
        int32_t ret = ScanManagerClientPtr->GetScannerList();
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to exit");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::OpenScanner(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("start to OpenScanner");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        SCAN_HILOGD("scannerId : %{public}s", scannerId.c_str());
        context->scannerId = scannerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->OpenScanner(context->scannerId);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to open the scanner");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::CloseScanner(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("start to CloseScanner");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        SCAN_HILOGD("scannerId : %{public}s", scannerId.c_str());
        context->scannerId = scannerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->CloseScanner(context->scannerId);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to close the scanner");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::SetScanOption(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter SetScanOption---->");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_THREE, " should 3 parameter!", napi_invalid_arg);

        napi_valuetype valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        context->scannerId = scannerId;

        valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_number, "optionIndex is not a number", napi_number_expected);
        int32_t optionIndex = NapiScanUtils::GetInt32FromValue(env, argv[NapiScanUtils::INDEX_ONE]);
        context->optionIndex = optionIndex;

        auto optionValue = ScanOptionValueHelper::BuildFromJs(env, argv[NapiScanUtils::INDEX_TWO]);
        if (optionValue == nullptr) {
            SCAN_HILOGE("Parse scan option value error!");
            context->SetErrorIndex(E_SCAN_INVALID_PARAMETER);
            return napi_invalid_arg;
        }
        context->optionValue = *optionValue;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->OpScanOptionValue(context->scannerId, context->optionIndex,
        SCAN_ACTION_SET_VALUE, context->optionValue);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to set the scan option");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::SetScanAutoOption(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter SetScanAutoOption---->");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);

        napi_valuetype valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        context->scannerId = scannerId;

        valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_number, "optionIndex is not a number", napi_number_expected);
        int32_t optionIndex = NapiScanUtils::GetInt32FromValue(env, argv[NapiScanUtils::INDEX_ONE]);
        context->optionIndex = optionIndex;

        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->OpScanOptionValue(context->scannerId,
        context->optionIndex, SCAN_ACTION_SET_AUTO, context->optionValue);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to set the auto scan option");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::GetScanOption(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter GetScanOption---->");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);

        napi_valuetype valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        context->scannerId = scannerId;

        valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_number, "optionIndex is not a number", napi_number_expected);
        int32_t optionIndex = NapiScanUtils::GetInt32FromValue(env, argv[NapiScanUtils::INDEX_ONE]);
        context->optionIndex = optionIndex;
        SCAN_HILOGE("success to get the scan option");
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        *result = ScanOptionValueHelper::MakeJsObject(env, context->optionValue);
        return napi_ok;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->OpScanOptionValue(context->scannerId,
        context->optionIndex, SCAN_ACTION_GET_VALUE, context->optionValue);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to get the scan option");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::GetScanParameters(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("start to GetScanParameters");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        context->scannerId = scannerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_array(env, result);
        uint32_t index = 0;
        for (auto desc : context->allDesc) {
            status = napi_set_element(env, *result, index++, ScanOptionDescriptorHelper::MakeJsObject(env, desc));
        }
        return napi_ok;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = NapiScanHelper::GetScannerAllPara(context->scannerId, context->allDesc);
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to get the scan para count");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::StartScan(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("start to StartScan");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valueType = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valueType), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valueType == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        SCAN_HILOGD("scannerId : %{public}s", scannerId.c_str());
        context->scannerId = scannerId;
        valueType = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ONE], &valueType), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valueType == napi_boolean, "batchMode is not a boolean", napi_boolean_expected);
        bool batchMode = NapiScanUtils::GetBooleanFromValue(env, argv[NapiScanUtils::INDEX_ONE]);
        context->batchMode = batchMode;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->StartScan(context->scannerId, context->batchMode);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to start the scan job");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::CancelScan(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("start to CancelScan");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        SCAN_HILOGD("scannerId : %{public}s", scannerId.c_str());
        context->scannerId = scannerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->CancelScan(context->scannerId);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to cancel the scan job");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::On(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter on---->");
    size_t argc = NapiScanUtils::MAX_ARGC;
    napi_value argv[NapiScanUtils::MAX_ARGC] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
        argc != NapiScanUtils::ARGC_TWO) {
        SCAN_HILOGE("need 2 parameter!");
        NapiScanUtils::NapiThrowError(env, E_SCAN_INVALID_PARAMETER);
        return nullptr;
    }
    napi_valuetype valuetype = napi_undefined;
    if (napi_typeof(env, argv[0], &valuetype) != napi_ok || valuetype != napi_string) {
        SCAN_HILOGE("type is not a string");
        NapiScanUtils::NapiThrowError(env, E_SCAN_INVALID_PARAMETER);
        return nullptr;
    }
    std::string type = NapiScanUtils::GetStringFromValueUtf8(env, argv[0]);
    uint32_t ret = NapiInnerScan::IsSupportType(type);
    if (ret != E_SCAN_NONE) {
        NapiScanUtils::NapiThrowError(env, ret);
        return nullptr;
    }
    valuetype = napi_undefined;
    if (napi_typeof(env, argv[1], &valuetype) != napi_ok || valuetype != napi_function) {
        SCAN_HILOGE("callback is not a function");
        NapiScanUtils::NapiThrowError(env, E_SCAN_INVALID_PARAMETER);
        return nullptr;
    }
    napi_ref callbackRef = NapiScanUtils::CreateReference(env, argv[1]);
    sptr<IScanCallback> callback = new (std::nothrow) ScanCallback(env, callbackRef);
    if (callback == nullptr) {
        SCAN_HILOGE("create scan callback object fail");
        NapiScanUtils::NapiThrowError(env, E_SCAN_GENERIC_FAILURE);
        return nullptr;
    }
    ret = static_cast<uint32_t>(ScanManagerClient::GetInstance()->On("", type, callback));
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("Failed to register event");
        NapiScanUtils::NapiThrowError(env, ret);
        return nullptr;
    }
    return nullptr;
}

napi_value NapiInnerScan::Off(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter off---->");
    size_t argc = NapiScanUtils::MAX_ARGC;
    napi_value argv[NapiScanUtils::MAX_ARGC] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
        argc != NapiScanUtils::ARGC_ONE) {
        SCAN_HILOGE("need 1 parameter!");
        NapiScanUtils::NapiThrowError(env, E_SCAN_INVALID_PARAMETER);
        return nullptr;
    }
    napi_valuetype valuetype = napi_undefined;
    if (napi_typeof(env, argv[0], &valuetype) != napi_ok || valuetype != napi_string) {
        SCAN_HILOGE("type is not a string");
        NapiScanUtils::NapiThrowError(env, E_SCAN_INVALID_PARAMETER);
        return nullptr;
    }
    std::string type = NapiScanUtils::GetStringFromValueUtf8(env, argv[0]);
    uint32_t ret = NapiInnerScan::IsSupportType(type);
    if (ret != E_SCAN_NONE) {
        NapiScanUtils::NapiThrowError(env, ret);
        return nullptr;
    }
    ret = static_cast<uint32_t>(ScanManagerClient::GetInstance()->Off("", type));
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("Failed to register event");
        NapiScanUtils::NapiThrowError(env, ret);
        return nullptr;
    }
    return nullptr;
}

napi_value NapiInnerScan::GetScanProgress(napi_env env, napi_callback_info info)
{
    SCAN_HILOGI("start to GetScanProgress");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ONE, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype = napi_undefined;
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scannerId is not a string", napi_string_expected);
        std::string scannerId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        context->scannerId = scannerId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        *result = ScanProgressHelper::MakeJsObject(env, context->prog);
        return napi_ok;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        int32_t ret = ScanManagerClient::GetInstance()->GetScanProgress(context->scannerId, context->prog);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to get the scan progress");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::AddScanner(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("start to AddScanner");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype = napi_undefined;

        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scanner uniqueId is not a string", napi_string_expected);
        std::string uniqueId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        SCAN_HILOGD("uniqueId : %{public}s", uniqueId.c_str());
        std::string ip;
        if (ScanUtil::ExtractIpAddresses(uniqueId, ip)) {
            context->uniqueId = ip;
        } else {
            context->uniqueId = uniqueId;
        }
        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "discoverMode is not a string", napi_string_expected);
        std::string discoverMode = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ONE]);
        SCAN_HILOGD("discoverMode : %{public}s", discoverMode.c_str());
        context->discoverMode = discoverMode;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        if (!NapiScanUtils::CheckCallerIsSystemApp()) {
            SCAN_HILOGE("not system app");
            context->SetErrorIndex(E_SCAN_ERROR_NOT_SYSTEM_APPLICATION);
            return;
        }
        int32_t ret = ScanManagerClient::GetInstance()->AddScanner(context->uniqueId, context->discoverMode);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to add the scanner");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::DeleteScanner(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("start to DeleteScanner");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_TWO, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype = napi_undefined;

        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ZERO], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "scanner uniqueId is not a string", napi_string_expected);
        std::string uniqueId = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ZERO]);
        SCAN_HILOGD("uniqueId : %{public}s", uniqueId.c_str());
        std::string ip;
        if (ScanUtil::ExtractIpAddresses(uniqueId, ip)) {
            context->uniqueId = ip;
        } else {
            context->uniqueId = uniqueId;
        }

        SCAN_CALL_BASE(env, napi_typeof(env, argv[NapiScanUtils::INDEX_ONE], &valuetype), napi_invalid_arg);
        SCAN_ASSERT_BASE(env, valuetype == napi_string, "discoverMode is not a string", napi_string_expected);
        std::string discoverMode = NapiScanUtils::GetStringFromValueUtf8(env, argv[NapiScanUtils::INDEX_ONE]);
        SCAN_HILOGD("discoverMode : %{public}s", discoverMode.c_str());
        context->discoverMode = discoverMode;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_undefined(env, result);
        return status;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        if (!NapiScanUtils::CheckCallerIsSystemApp()) {
            SCAN_HILOGE("not system app");
            context->SetErrorIndex(E_SCAN_ERROR_NOT_SYSTEM_APPLICATION);
            return;
        }
        int32_t ret = ScanManagerClient::GetInstance()->DeleteScanner(context->uniqueId, context->discoverMode);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to delete the scanner");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerScan::GetAddedScanner(napi_env env, napi_callback_info info)
{
    SCAN_HILOGD("Enter GetAddedScanner---->");
    auto context = std::make_shared<NapiScanContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        SCAN_ASSERT_BASE(env, argc == NapiScanUtils::ARGC_ZERO, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_array(env, result);
        uint32_t index = 0;
        for (auto scanDeviceInfo : context->allAddedScanner) {
            status = napi_set_element(env, *result, index++, ScannerInfoHelper::MakeJsObject(env, scanDeviceInfo));
        }
        return napi_ok;
    };
    auto exec = [context](ScanAsyncCall::Context *ctx) {
        if (!NapiScanUtils::CheckCallerIsSystemApp()) {
            SCAN_HILOGE("not system app");
            context->SetErrorIndex(E_SCAN_ERROR_NOT_SYSTEM_APPLICATION);
            return;
        }
        int32_t ret = ScanManagerClient::GetInstance()->GetAddedScanner(context->allAddedScanner);
        context->result = ret == E_SCAN_NONE;
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("Failed to get added scanner");
            context->SetErrorIndex(ret);
        }
    };
    context->SetAction(std::move(input), std::move(output));
    ScanAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<ScanAsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

uint32_t NapiInnerScan::IsSupportType(const std::string& type)
{
    if (type == SCAN_DEVICE_FOUND || type == SCAN_DEVICE_SYNC) {
        return E_SCAN_NONE;
    }
    if (type == SCAN_DEVICE_ADD || type == SCAN_DEVICE_DEL) {
        if (!NapiScanUtils::CheckCallerIsSystemApp()) {
            SCAN_HILOGE("not system app");
            return E_SCAN_ERROR_NOT_SYSTEM_APPLICATION;
        } else {
            return E_SCAN_NONE;
        }
    }
    SCAN_HILOGE("type : %{public}s is invalid", type.c_str());
    return E_SCAN_INVALID_PARAMETER;
}
} // namespace OHOS::Scan
