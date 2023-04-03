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

#include <fcntl.h>
#include "ability.h"
#include "napi_base_context.h"
#include "print_log.h"
#include "securec.h"

namespace OHOS::Print {
static constexpr const int MAX_STRING_LENGTH = 65536;
const std::string GLOBAL_ID_DELIMITER = ":";
const std::string EXTENSION_CID_DELIMITER = ":";
const std::string TASK_EVENT_DELIMITER = "-";

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
    bool hasProperty = false;
    PRINT_CALL_BASE(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty), false);
    return hasProperty;
}

napi_value NapiPrintUtils::GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
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
    (void)napi_set_named_property(env, object, name.c_str(), value);
}

std::vector<std::string> NapiPrintUtils::GetPropertyNames(napi_env env, napi_value object)
{
    std::vector<std::string> ret;
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
    uint32_t ret = 0;
    PRINT_CALL_BASE(env, napi_get_value_uint32(env, value, &ret), 0);
    return ret;
}

uint32_t NapiPrintUtils::GetUint32Property(napi_env env, napi_value object, const std::string &propertyName)
{
    if (!HasNamedProperty(env, object, propertyName)) {
        return 0;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetUint32FromValue(env, value);
}

void NapiPrintUtils::SetUint32Property(napi_env env, napi_value object, const std::string &name, uint32_t value)
{
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
    int32_t ret = 0;
    PRINT_CALL_BASE(env, napi_get_value_int32(env, value, &ret), 0);
    return ret;
}

int32_t NapiPrintUtils::GetInt32Property(napi_env env, napi_value object, const std::string &propertyName)
{
    if (!HasNamedProperty(env, object, propertyName)) {
        return 0;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetInt32FromValue(env, value);
}

void NapiPrintUtils::SetInt32Property(napi_env env, napi_value object, const std::string &name, int32_t value)
{
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
    if (!HasNamedProperty(env, object, propertyName)) {
        return "";
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetStringFromValueUtf8(env, value);
}

void NapiPrintUtils::SetStringPropertyUtf8(
    napi_env env, napi_value object, const std::string &name, const std::string &value)
{
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
    bool isArrayBuffer = false;
    PRINT_CALL_BASE(env, napi_is_arraybuffer(env, value, &isArrayBuffer), false);
    return isArrayBuffer;
}

void *NapiPrintUtils::GetInfoFromArrayBufferValue(napi_env env, napi_value value, size_t *length)
{
    if (length == nullptr) {
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
    napi_value res = nullptr;
    PRINT_CALL(env, napi_call_function(env, recv, func, argc, argv, &res));
    return res;
}

/* reference */
napi_ref NapiPrintUtils::CreateReference(napi_env env, napi_value callback)
{
    napi_ref callbackRef = nullptr;
    PRINT_CALL(env, napi_create_reference(env, callback, 1, &callbackRef));
    return callbackRef;
}

napi_value NapiPrintUtils::GetReference(napi_env env, napi_ref callbackRef)
{
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
    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    (void)napi_define_properties(env, object, properties.size(), descriptors);
}

std::string NapiPrintUtils::ToLower(const std::string &s)
{
    std::string res = s;
    std::transform(res.begin(), res.end(), res.begin(), tolower);
    return res;
}

std::string NapiPrintUtils::GetValueString(napi_env env, napi_value value)
{
    std::string resultValue = "";
    char value_string[256];
    size_t value_size = 256;
    size_t result;
    napi_get_value_string_utf8(env, value, value_string, value_size, &result);
    resultValue = value_string;
    return resultValue;
}

std::string NapiPrintUtils::GetExtensionId(const std::string &globalId)
{
    auto pos = globalId.find(GLOBAL_ID_DELIMITER);
    if (pos == std::string::npos) {
        return "";
    }
    return globalId.substr(0, pos);
}

std::string NapiPrintUtils::GetGlobalId(const std::string& extensionId, const std::string& localId)
{
    return extensionId + GLOBAL_ID_DELIMITER + localId;
}

std::string NapiPrintUtils::GetLocalId(const std::string& globalId, const std::string& extensionId)
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

std::string NapiPrintUtils::EncodeExtensionCid(const std::string &extensionId, uint32_t callbackId)
{
    return extensionId + EXTENSION_CID_DELIMITER + std::to_string(callbackId);
}

bool NapiPrintUtils::DecodeExtensionCid(const std::string &cid, std::string &extensionId, uint32_t &callbackId)
{
    auto pos = cid.find(EXTENSION_CID_DELIMITER);
    if (pos == std::string::npos) {
        return false;
    }
    extensionId = cid.substr(0, pos);
    callbackId = static_cast<uint32_t>(atoi(cid.substr(pos + 1).c_str()));
    return true;
}

std::string NapiPrintUtils::GetTaskEventId(const std::string &taskId, const std::string &type)
{
    return type + TASK_EVENT_DELIMITER + taskId;
}

int32_t NapiPrintUtils::OpenFile(const std::string &filePath)
{
    if (!IsPathValid(filePath)) {
        return PRINT_INVALID_ID;
    }
    int32_t fd = open(filePath.c_str(), O_RDONLY);
    PRINT_HILOGD("fd: %{public}d", fd);
    if (fd < 0) {
        PRINT_HILOGE("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        return PRINT_INVALID_ID;
    }
    return fd;
}

bool NapiPrintUtils::IsPathValid(const std::string &filePath)
{
    auto path = filePath.substr(0, filePath.rfind('/'));
    char resolvedPath[PATH_MAX + 1] = { 0 };
    if (path.length() > PATH_MAX || realpath(path.c_str(), resolvedPath) == nullptr ||
        strncmp(resolvedPath, path.c_str(), path.length()) != 0) {
        PRINT_HILOGE("invalid file path!");
        return false;
    }
    return true;
}

uint32_t NapiPrintUtils::GetIdFromFdPath(const std::string &fdPath)
{
    std::string fd_str = fdPath.substr(fdPath.rfind('/') + 1, fdPath.length());
    std::stringstream getStrStream(fd_str);
    uint32_t fd;
    if (!(getStrStream >> fd)) {
        PRINT_HILOGD("failed to convert to uint32");
    }
    return fd;
}
} // namespace OHOS::Print
