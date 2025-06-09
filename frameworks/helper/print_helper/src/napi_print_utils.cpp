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

#include "napi_print_utils.h"

#include "ability.h"
#include "accesstoken_kit.h"
#include "napi_base_context.h"
#include "print_constant.h"
#include "print_log.h"
#include "securec.h"
#include "tokenid_kit.h"

namespace OHOS::Print {
static constexpr const int MAX_STRING_LENGTH = 65536;
const std::map<int32_t, std::string> ERROR_CODE_CONVERT_MESSAGE_MAP = {
    {E_PRINT_NO_PERMISSION, "the application does not have permission to call this function."},
    {E_PRINT_ILLEGAL_USE_OF_SYSTEM_API, "not system application."},
    {E_PRINT_INVALID_PARAMETER,
        "Parameter error. Possible causes: 1.Mandatory parameters are left unspecified; 2.Incorrect parameter types."},
    {E_PRINT_GENERIC_FAILURE, "Generic failure of print."},
    {E_PRINT_RPC_FAILURE, "RPC failure."},
    {E_PRINT_SERVER_FAILURE, "Failure of print service."},
    {E_PRINT_INVALID_EXTENSION, "Invalid print extension."},
    {E_PRINT_INVALID_PRINTER, "Invalid printer."},
    {E_PRINT_INVALID_PRINTJOB, "Invalid print job."},
    {E_PRINT_FILE_IO, "File i/o error."},
    {E_PRINT_INVALID_TOKEN, "Invalid token."},
    {E_PRINT_INVALID_USERID, "Invalid user id."},
    {E_PRINT_TOO_MANY_FILES, "Number of files exceeding the upper limit."},
};
static const std::string ERROR_MESSAGE_OUT_OF_DEFINITION = "error is out of definition.";

napi_valuetype NapiPrintUtils::GetValueType(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return napi_undefined;
    }

    napi_valuetype valueType = napi_undefined;
    PRINT_CALL_BASE(env, napi_typeof(env, value, &valueType), napi_undefined);
    return valueType;
}

/* named property */
bool NapiPrintUtils::HasNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return false;
    }
    bool hasProperty = false;
    PRINT_CALL_BASE(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty), false);
    return hasProperty;
}

napi_value NapiPrintUtils::GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return nullptr;
    }
    napi_value value = nullptr;
    bool hasProperty = false;
    PRINT_CALL(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty));
    if (!hasProperty) {
        return value;
    }
    PRINT_CALL(env, napi_get_named_property(env, object, propertyName.c_str(), &value));
    return value;
}

void NapiPrintUtils::SetNamedProperty(napi_env env, napi_value object, const std::string &name, napi_value value)
{
    if (object == nullptr) {
        return;
    }
    (void)napi_set_named_property(env, object, name.c_str(), value);
}

std::vector<std::string> NapiPrintUtils::GetPropertyNames(napi_env env, napi_value object)
{
    std::vector<std::string> ret;
    if (object == nullptr) {
        return ret;
    }
    napi_value names = nullptr;
    PRINT_CALL_BASE(env, napi_get_property_names(env, object, &names), ret);
    uint32_t length = 0;
    PRINT_CALL_BASE(env, napi_get_array_length(env, names, &length), ret);
    for (uint32_t index = 0; index < length; ++index) {
        napi_value name = nullptr;
        if (napi_get_element(env, names, index, &name) != napi_ok) {
            continue;
        }
        if (GetValueType(env, name) != napi_string) {
            continue;
        }
        ret.emplace_back(GetStringFromValueUtf8(env, name));
    }
    return ret;
}

/* UINT32 */
napi_value NapiPrintUtils::CreateUint32(napi_env env, uint32_t code)
{
    napi_value value = nullptr;
    if (napi_create_uint32(env, code, &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

uint32_t NapiPrintUtils::GetUint32FromValue(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return 0;
    }
    uint32_t ret = 0;
    PRINT_CALL_BASE(env, napi_get_value_uint32(env, value, &ret), 0);
    return ret;
}

uint32_t NapiPrintUtils::GetUint32Property(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return 0;
    }
    if (!HasNamedProperty(env, object, propertyName)) {
        return 0;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetUint32FromValue(env, value);
}

void NapiPrintUtils::SetUint32Property(napi_env env, napi_value object, const std::string &name, uint32_t value)
{
    if (object == nullptr) {
        return;
    }
    napi_value jsValue = CreateUint32(env, value);
    if (GetValueType(env, jsValue) != napi_number) {
        return;
    }

    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* INT32 */
napi_value NapiPrintUtils::CreateInt32(napi_env env, int32_t code)
{
    napi_value value = nullptr;
    if (napi_create_int32(env, code, &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

int32_t NapiPrintUtils::GetInt32FromValue(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return 0;
    }
    int32_t ret = 0;
    PRINT_CALL_BASE(env, napi_get_value_int32(env, value, &ret), 0);
    return ret;
}

int32_t NapiPrintUtils::GetInt32Property(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return 0;
    }
    if (!HasNamedProperty(env, object, propertyName)) {
        return 0;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetInt32FromValue(env, value);
}

void NapiPrintUtils::SetInt32Property(napi_env env, napi_value object, const std::string &name, int32_t value)
{
    if (object == nullptr) {
        return;
    }
    napi_value jsValue = CreateInt32(env, value);
    if (GetValueType(env, jsValue) != napi_number) {
        return;
    }

    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* String UTF8 */
napi_value NapiPrintUtils::CreateStringUtf8(napi_env env, const std::string &str)
{
    napi_value value = nullptr;
    if (napi_create_string_utf8(env, str.c_str(), strlen(str.c_str()), &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

std::string NapiPrintUtils::GetStringFromValueUtf8(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return "";
    }
    std::string result;
    std::vector<char> str(MAX_STRING_LENGTH + 1, '\0');
    size_t length = 0;
    PRINT_CALL_BASE(env, napi_get_value_string_utf8(env, value, &str[0], MAX_STRING_LENGTH, &length), result);
    if (length > 0) {
        return result.append(&str[0], length);
    }
    return result;
}

std::string NapiPrintUtils::GetStringPropertyUtf8(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return "";
    }
    if (!HasNamedProperty(env, object, propertyName)) {
        return "";
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetStringFromValueUtf8(env, value);
}

void NapiPrintUtils::SetStringPropertyUtf8(
    napi_env env, napi_value object, const std::string &name, const std::string &value)
{
    if (object == nullptr) {
        return;
    }
    napi_value jsValue = CreateStringUtf8(env, value);
    if (GetValueType(env, jsValue) != napi_string) {
        return;
    }
    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* array buffer */

napi_value NapiPrintUtils::CreateArrayBuffer(napi_env env, size_t length, void **data)
{
    napi_value object = nullptr;
    PRINT_CALL(env, napi_create_arraybuffer(env, length, data, &object));
    return object;
}

bool NapiPrintUtils::ValueIsArrayBuffer(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    bool isArrayBuffer = false;
    PRINT_CALL_BASE(env, napi_is_arraybuffer(env, value, &isArrayBuffer), false);
    return isArrayBuffer;
}

void *NapiPrintUtils::GetInfoFromArrayBufferValue(napi_env env, napi_value value, size_t *length)
{
    if (value == nullptr || length == nullptr) {
        return nullptr;
    }

    void *data = nullptr;
    PRINT_CALL(env, napi_get_arraybuffer_info(env, value, &data, length));
    return data;
}

/* object */
napi_value NapiPrintUtils::CreateObject(napi_env env)
{
    napi_value object = nullptr;
    PRINT_CALL(env, napi_create_object(env, &object));
    return object;
}

/* undefined */
napi_value NapiPrintUtils::GetUndefined(napi_env env)
{
    napi_value undefined = nullptr;
    PRINT_CALL(env, napi_get_undefined(env, &undefined));
    return undefined;
}

/* function */
napi_value NapiPrintUtils::CallFunction(
    napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value *argv)
{
    if (func == nullptr) {
        return nullptr;
    }
    napi_value res = nullptr;
    PRINT_CALL(env, napi_call_function(env, recv, func, argc, argv, &res));
    return res;
}

napi_value NapiPrintUtils::CreateFunction
    (napi_env env, const std::string &name, napi_callback func, void *arg)
{
    napi_value res = nullptr;
    PRINT_CALL(env, napi_create_function(env, name.c_str(), NAPI_AUTO_LENGTH, func, arg, &res));
    return res;
}

/* reference */
napi_ref NapiPrintUtils::CreateReference(napi_env env, napi_value callback)
{
    if (callback == nullptr) {
        return nullptr;
    }
    napi_ref callbackRef = nullptr;
    PRINT_CALL(env, napi_create_reference(env, callback, 1, &callbackRef));
    return callbackRef;
}

napi_value NapiPrintUtils::GetReference(napi_env env, napi_ref callbackRef)
{
    if (callbackRef == nullptr) {
        return nullptr;
    }
    napi_value callback = nullptr;
    PRINT_CALL(env, napi_get_reference_value(env, callbackRef, &callback));
    return callback;
}

void NapiPrintUtils::DeleteReference(napi_env env, napi_ref callbackRef)
{
    (void)napi_delete_reference(env, callbackRef);
}

/* boolean */
bool NapiPrintUtils::GetBooleanProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return false;
    }
    if (!HasNamedProperty(env, object, propertyName)) {
        return false;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    bool ret = false;
    PRINT_CALL_BASE(env, napi_get_value_bool(env, value, &ret), false);
    return ret;
}

void NapiPrintUtils::SetBooleanProperty(napi_env env, napi_value object, const std::string &name, bool value)
{
    if (object == nullptr) {
        return;
    }
    napi_value jsValue = nullptr;
    PRINT_CALL_RETURN_VOID(env, napi_get_boolean(env, value, &jsValue));
    if (GetValueType(env, jsValue) != napi_boolean) {
        return;
    }

    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* define properties */
void NapiPrintUtils::DefineProperties(
    napi_env env, napi_value object, const std::initializer_list<napi_property_descriptor> &properties)
{
    std::vector<napi_property_descriptor> descriptors(properties.begin(), properties.end());

    (void)napi_define_properties(env, object, properties.size(), descriptors.data());
}

std::string NapiPrintUtils::GetValueString(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return "";
    }
    std::string resultValue = "";
    char value_string[256] = { 0 };
    size_t value_size = 256;
    size_t result = 0;
    napi_status status = napi_get_value_string_utf8(env, value, value_string, value_size, &result);
    if (status == napi_ok && result > 0) {
        resultValue = value_string;
    }
    return resultValue;
}

size_t NapiPrintUtils::GetJsVal(napi_env env, napi_callback_info info, napi_value argv[], size_t length)
{
    size_t argc = length;
    napi_value thisVal = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVal, &data);
    return argc;
}

bool NapiPrintUtils::VerifyProperty(
    std::vector<std::string> &names, std::map<std::string, PrintParamStatus> &propertyList)
{
    for (const auto& name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = PRINT_PARAM_SET;
    }

    for (const auto& propertyItem : propertyList) {
        if (propertyItem.second == PRINT_PARAM_NOT_SET) {
            PRINT_HILOGE("Missing Property: %{public}s", propertyItem.first.c_str());
            return false;
        }
    }
    return true;
}

std::string NapiPrintUtils::GetPrintErrorMsg(int32_t errorCode)
{
    auto msg = PRINT_ERROR_MSG_MAP.find(static_cast<PrintErrorCode>(errorCode));
    if (msg != PRINT_ERROR_MSG_MAP.end()) {
        return msg->second;
    }
    return "";
}

bool NapiPrintUtils::CheckCallerIsSystemApp()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        PRINT_HILOGD("tokenType check passed.");
        return true;
    }
    auto accessTokenId = IPCSkeleton::GetCallingFullTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenId);
}

const std::string NapiPrintUtils::GetErrorMsgByErrorCode(int32_t code)
{
    PRINT_HILOGD("GetErrorMsgByErrorCode start");
    auto iter = ERROR_CODE_CONVERT_MESSAGE_MAP.find(code);
    if (iter == ERROR_CODE_CONVERT_MESSAGE_MAP.end()) {
        PRINT_HILOGE("error is out of definition.");
        return ERROR_MESSAGE_OUT_OF_DEFINITION;
    }
    PRINT_HILOGD("ErrorMessage: %{public}s", (iter->second).c_str());
    return iter->second;
}

napi_value NapiPrintUtils::CreateJsError(napi_env env, int32_t errCode)
{
    std::string errMsg = GetErrorMsgByErrorCode(errCode);
    PRINT_HILOGD("CreateJsError errCode: %{public}d, errMsg: %{public}s", errCode, errMsg.c_str());

    napi_value code = nullptr;
    napi_status status = napi_create_int32(env, errCode, &code);
    if (status != napi_ok) {
        PRINT_HILOGE("napi create error code failed");
        return nullptr;
    }

    napi_value message = nullptr;
    status = napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);
    if (status != napi_ok) {
        PRINT_HILOGE("napi create error message failed");
        return nullptr;
    }

    napi_value errorObj = nullptr;
    status = napi_create_error(env, code, message, &errorObj);
    if (status != napi_ok) {
        PRINT_HILOGE("napi create js error failed");
        return nullptr;
    }

    return errorObj;
}
}  // namespace OHOS::Print
