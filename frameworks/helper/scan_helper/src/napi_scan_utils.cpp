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

#include "napi_scan_utils.h"

#include <fcntl.h>
#include "ability.h"
#include "napi_base_context.h"
#include "scan_log.h"
#include "scan_util.h"
#include "accesstoken_kit.h"
#include "tokenid_kit.h"

namespace OHOS::Scan {
static constexpr const int MAX_STRING_LENGTH = 65536;
const std::string GLOBAL_ID_DELIMITER = ":";
const std::string EXTENSION_CID_DELIMITER = ":";
const std::string TASK_EVENT_DELIMITER = "-";
std::unordered_map<uint32_t, std::string> NapiScanUtils::scanErrorCodeMap_ = {
    {E_SCAN_NO_PERMISSION, "SCAN_ERROR_NO_PERMISSION", },
    {E_SCAN_ERROR_NOT_SYSTEM_APPLICATION, "SCAN_ERROR_NOT_SYSTEM_APPLICATION", },
    {E_SCAN_INVALID_PARAMETER, "SCAN_ERROR_INVALID_PARAMETER"},
    {E_SCAN_GENERIC_FAILURE, "SCAN_ERROR_GENERIC_FAILURE"},
    {E_SCAN_RPC_FAILURE, "SCAN_ERROR_RPC_FAILURE"},
    {E_SCAN_SERVER_FAILURE, "SCAN_ERROR_SERVER_FAILURE"},
    {E_SCAN_UNSUPPORTED, "SCAN_ERROR_UNSUPPORTED"},
    {E_SCAN_CANCELLED, "SCAN_ERROR_CANCELED"},
    {E_SCAN_DEVICE_BUSY, "SCAN_ERROR_DEVICE_BUSY"},
    {E_SCAN_INVAL, "SCAN_ERROR_INVALID"},
    {E_SCAN_JAMMED, "SCAN_ERROR_JAMMED"},
    {E_SCAN_NO_DOCS, "SCAN_ERROR_NO_DOCS"},
    {E_SCAN_COVER_OPEN, "SCAN_ERROR_COVER_OPEN"},
    {E_SCAN_IO_ERROR, "SCAN_ERROR_IO_ERROR"},
    {E_SCAN_NO_MEM, "SCAN_ERROR_NO_MEMORY"},
};
napi_valuetype NapiScanUtils::GetValueType(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return napi_undefined;
    }

    napi_valuetype valueType = napi_undefined;
    SCAN_CALL_BASE(env, napi_typeof(env, value, &valueType), napi_undefined);
    return valueType;
}

/* named property */
bool NapiScanUtils::HasNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return false;
    }
    bool hasProperty = false;
    SCAN_CALL_BASE(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty), false);
    return hasProperty;
}

napi_value NapiScanUtils::GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return nullptr;
    }
    napi_value value = nullptr;
    bool hasProperty = false;
    SCAN_CALL(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty));
    if (!hasProperty) {
        return value;
    }
    SCAN_CALL(env, napi_get_named_property(env, object, propertyName.c_str(), &value));
    return value;
}

void NapiScanUtils::SetNamedProperty(napi_env env, napi_value object, const std::string &name, napi_value value)
{
    if (object == nullptr) {
        return;
    }
    (void)napi_set_named_property(env, object, name.c_str(), value);
}

std::vector<std::string> NapiScanUtils::GetPropertyNames(napi_env env, napi_value object)
{
    std::vector<std::string> ret;
    if (object == nullptr) {
        return ret;
    }
    napi_value names = nullptr;
    SCAN_CALL_BASE(env, napi_get_property_names(env, object, &names), ret);
    uint32_t length = 0;
    SCAN_CALL_BASE(env, napi_get_array_length(env, names, &length), ret);
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
napi_value NapiScanUtils::CreateUint32(napi_env env, uint32_t code)
{
    napi_value value = nullptr;
    if (napi_create_uint32(env, code, &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

uint32_t NapiScanUtils::GetUint32FromValue(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return 0;
    }
    uint32_t ret = 0;
    SCAN_CALL_BASE(env, napi_get_value_uint32(env, value, &ret), 0);
    return ret;
}

uint32_t NapiScanUtils::GetUint32Property(napi_env env, napi_value object, const std::string &propertyName)
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

void NapiScanUtils::SetUint32Property(napi_env env, napi_value object, const std::string &name, uint32_t value)
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
napi_value NapiScanUtils::CreateInt32(napi_env env, int32_t code)
{
    napi_value value = nullptr;
    if (napi_create_int32(env, code, &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

int32_t NapiScanUtils::GetInt32FromValue(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return 0;
    }
    int32_t ret = 0;
    SCAN_CALL_BASE(env, napi_get_value_int32(env, value, &ret), 0);
    return ret;
}

int32_t NapiScanUtils::GetInt32Property(napi_env env, napi_value object, const std::string &propertyName)
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

void NapiScanUtils::SetInt32Property(napi_env env, napi_value object, const std::string &name, int32_t value)
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
napi_value NapiScanUtils::CreateStringUtf8(napi_env env, const std::string &str)
{
    napi_value value = nullptr;
    if (napi_create_string_utf8(env, str.c_str(), strlen(str.c_str()), &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

std::string NapiScanUtils::GetStringFromValueUtf8(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return "";
    }
    std::string result;
    std::vector<char> str(MAX_STRING_LENGTH + 1, '\0');
    size_t length = 0;
    SCAN_CALL_BASE(env, napi_get_value_string_utf8(env, value, &str[0], MAX_STRING_LENGTH, &length), result);
    if (length > 0) {
        return result.append(&str[0], length);
    }
    return result;
}

std::string NapiScanUtils::GetStringPropertyUtf8(napi_env env, napi_value object, const std::string &propertyName)
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

void NapiScanUtils::SetStringPropertyUtf8(
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

napi_value NapiScanUtils::CreateArrayBuffer(napi_env env, size_t length, void **data)
{
    napi_value object = nullptr;
    SCAN_CALL(env, napi_create_arraybuffer(env, length, data, &object));
    return object;
}

bool NapiScanUtils::ValueIsArrayBuffer(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    bool isArrayBuffer = false;
    SCAN_CALL_BASE(env, napi_is_arraybuffer(env, value, &isArrayBuffer), false);
    return isArrayBuffer;
}

void *NapiScanUtils::GetInfoFromArrayBufferValue(napi_env env, napi_value value, size_t *length)
{
    if (value == nullptr || length == nullptr) {
        return nullptr;
    }

    void *data = nullptr;
    SCAN_CALL(env, napi_get_arraybuffer_info(env, value, &data, length));
    return data;
}

/* object */
napi_value NapiScanUtils::CreateObject(napi_env env)
{
    napi_value object = nullptr;
    SCAN_CALL(env, napi_create_object(env, &object));
    return object;
}

/* undefined */
napi_value NapiScanUtils::GetUndefined(napi_env env)
{
    napi_value undefined = nullptr;
    SCAN_CALL(env, napi_get_undefined(env, &undefined));
    return undefined;
}

/* function */
napi_value NapiScanUtils::CallFunction(
    napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value *argv)
{
    if (func == nullptr) {
        return nullptr;
    }
    napi_value res = nullptr;
    SCAN_CALL(env, napi_call_function(env, recv, func, argc, argv, &res));
    return res;
}

/* reference */
napi_ref NapiScanUtils::CreateReference(napi_env env, napi_value callback)
{
    if (callback == nullptr) {
        return nullptr;
    }
    napi_ref callbackRef = nullptr;
    SCAN_CALL(env, napi_create_reference(env, callback, 1, &callbackRef));
    return callbackRef;
}

napi_value NapiScanUtils::GetReference(napi_env env, napi_ref callbackRef)
{
    if (callbackRef == nullptr) {
        return nullptr;
    }
    napi_value callback = nullptr;
    SCAN_CALL(env, napi_get_reference_value(env, callbackRef, &callback));
    return callback;
}

void NapiScanUtils::DeleteReference(napi_env env, napi_ref callbackRef)
{
    if (env != nullptr && callbackRef != nullptr) {
        (void)napi_delete_reference(env, callbackRef);
    }
}

/* boolean */
napi_value NapiScanUtils::CreateBoolean(napi_env env, bool value)
{
    napi_value jsValue = nullptr;
    if (napi_get_boolean(env, value, &jsValue) != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

bool NapiScanUtils::GetBooleanFromValue(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return false;
    }
    bool ret = false;
    SCAN_CALL_BASE(env, napi_get_value_bool(env, value, &ret), 0);
    return ret;
}

bool NapiScanUtils::GetBooleanProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    if (object == nullptr) {
        return false;
    }
    if (!HasNamedProperty(env, object, propertyName)) {
        return false;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    bool ret = false;
    SCAN_CALL_BASE(env, napi_get_value_bool(env, value, &ret), false);
    return ret;
}

void NapiScanUtils::SetBooleanProperty(napi_env env, napi_value object, const std::string &name, bool value)
{
    if (object == nullptr) {
        return;
    }
    napi_value jsValue = nullptr;
    SCAN_CALL_RETURN_VOID(env, napi_get_boolean(env, value, &jsValue));
    if (GetValueType(env, jsValue) != napi_boolean) {
        return;
    }

    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* define properties */
void NapiScanUtils::DefineProperties(
    napi_env env, napi_value object, const std::initializer_list<napi_property_descriptor> &properties)
{
    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    (void)napi_define_properties(env, object, properties.size(), descriptors);
}

std::string NapiScanUtils::ToLower(const std::string &s)
{
    std::string res = s;
    std::transform(res.begin(), res.end(), res.begin(), tolower);
    return res;
}

std::string NapiScanUtils::GetValueString(napi_env env, napi_value value)
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

std::string NapiScanUtils::GetExtensionId(const std::string &globalId)
{
    auto pos = globalId.find(GLOBAL_ID_DELIMITER);
    if (pos == std::string::npos) {
        return "";
    }
    return globalId.substr(0, pos);
}

std::string NapiScanUtils::GetGlobalId(const std::string& extensionId, const std::string& localId)
{
    return extensionId + GLOBAL_ID_DELIMITER + localId;
}

std::string NapiScanUtils::GetLocalId(const std::string& globalId, const std::string& extensionId)
{
    auto pos = globalId.find(GLOBAL_ID_DELIMITER);
    if (pos == std::string::npos) {
        return "";
    }

    if (globalId.substr(0, pos) != extensionId) {
        return "";
    }
    return globalId.substr(pos + 1);
}

std::string NapiScanUtils::EncodeExtensionCid(const std::string &extensionId, uint32_t callbackId)
{
    return extensionId + EXTENSION_CID_DELIMITER + std::to_string(callbackId);
}

bool NapiScanUtils::DecodeExtensionCid(const std::string &cid, std::string &extensionId, uint32_t &callbackId)
{
    auto pos = cid.find(EXTENSION_CID_DELIMITER);
    if (pos == std::string::npos) {
        return false;
    }
    extensionId = cid.substr(0, pos);
    int32_t callbackIdTmp = 0;
    if (!ScanUtil::ConvertToInt(cid.substr(pos + 1), callbackIdTmp)) {
        return false;
    }
    callbackId = static_cast<uint32_t>(callbackIdTmp);
    return true;
}

int32_t NapiScanUtils::OpenFile(const std::string &filePath)
{
    if (!IsPathValid(filePath)) {
        return SCAN_INVALID_ID;
    }
    int32_t fd = open(filePath.c_str(), O_RDONLY);
    SCAN_HILOGD("fd: %{public}d", fd);
    if (fd < 0) {
        SCAN_HILOGE("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        return SCAN_INVALID_ID;
    }
    return fd;
}

bool NapiScanUtils::IsPathValid(const std::string &filePath)
{
    auto path = filePath.substr(0, filePath.rfind('/'));
    char resolvedPath[PATH_MAX + 1] = { 0 };
    if (path.length() > PATH_MAX || realpath(path.c_str(), resolvedPath) == nullptr ||
        strncmp(resolvedPath, path.c_str(), path.length()) != 0) {
        SCAN_HILOGE("invalid file path!");
        return false;
    }
    return true;
}

uint32_t NapiScanUtils::GetIdFromFdPath(const std::string &fdPath)
{
    std::string fd_str = fdPath.substr(fdPath.rfind('/') + 1, fdPath.length());
    std::stringstream getStrStream(fd_str);
    uint32_t fd = 0;
    if (!(getStrStream >> fd)) {
        SCAN_HILOGD("failed to convert to uint32");
    }
    return fd;
}

size_t NapiScanUtils::GetJsVal(napi_env env, napi_callback_info info, napi_value argv[], size_t length)
{
    size_t argc = length;
    napi_value thisVal = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVal, &data);
    return argc;
}

void NapiScanUtils::NapiThrowError(napi_env env, uint32_t errCode)
{
    std::string message;
    SetErrorText(errCode, message);
    napi_value result = nullptr;
    napi_create_error(env, CreateUint32(env, errCode), CreateStringUtf8(env, message), &result);
    napi_throw(env, result);
}

void NapiScanUtils::SetErrorText(uint32_t& code, std::string& message)
{
    auto it = scanErrorCodeMap_.find(code);
    if (it != scanErrorCodeMap_.end()) {
        message = it->second;
    } else {
        SCAN_HILOGD("ErrorText not found");
        code = E_SCAN_GENERIC_FAILURE;
    }
}

bool NapiScanUtils::CheckCallerIsSystemApp()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        SCAN_HILOGD("tokenType check passed.");
        return true;
    }
    auto accessTokenId = IPCSkeleton::GetCallingFullTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenId);
}
} // namespace OHOS::Scan
