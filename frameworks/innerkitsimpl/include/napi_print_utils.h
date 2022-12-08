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

#ifndef NAPI_PRINT_UTILS_H
#define NAPI_PRINT_UTILS_H

#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "print_constant.h"
#include "print_job.h"
#include "print_resolution.h"
#include "printer_capability.h"
#include "printer_info.h"

namespace OHOS::Print {
class NapiPrintUtils {
public:
    static constexpr size_t MAX_ARGC = 6;
    static constexpr size_t ARGC_ZERO = 0;
    static constexpr size_t ARGC_ONE = 1;
    static constexpr size_t ARGC_TWO = 2;
    static constexpr size_t ARGC_THREE = 3;
    static constexpr size_t ARGC_FOUR = 4;
    static constexpr size_t ARGC_FIVE = 5;
    static constexpr size_t ARGC_SIX = 6;

    static constexpr int32_t INDEX_ZERO = 0;
    static constexpr int32_t INDEX_ONE = 1;
    static constexpr int32_t INDEX_TWO = 2;
    static constexpr int32_t INDEX_THREE = 3;
    static constexpr int32_t INDEX_FOUR = 4;
    static constexpr int32_t INDEX_FIVE = 5;

    static constexpr int32_t MAX_NUMBER_BYTES = 8;
    static constexpr int32_t MAX_LEN = 4096;
    static constexpr int32_t MAX_JOBSTRING_LENGTH = 10;

    static napi_valuetype GetValueType(napi_env env, napi_value value);
    static bool HasNamedProperty(napi_env env, napi_value object, const std::string &propertyName);
    static napi_value GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName);
    static void SetNamedProperty(napi_env env, napi_value object, const std::string &name, napi_value value);
    static std::vector<std::string> GetPropertyNames(napi_env env, napi_value object);
    static napi_value CreateUint32(napi_env env, uint32_t code);
    static uint32_t GetUint32FromValue(napi_env env, napi_value value);
    static uint32_t GetUint32Property(napi_env env, napi_value object, const std::string &propertyName);
    static void SetUint32Property(napi_env env, napi_value object, const std::string &name, uint32_t value);
    static napi_value CreateInt32(napi_env env, int32_t code);
    static int32_t GetInt32FromValue(napi_env env, napi_value value);
    static int32_t GetInt32Property(napi_env env, napi_value object, const std::string &propertyName);
    static void SetInt32Property(napi_env env, napi_value object, const std::string &name, int32_t value);
    static napi_value CreateStringUtf8(napi_env env, const std::string &str);
    static std::string GetStringFromValueUtf8(napi_env env, napi_value value);
    static std::string GetStringPropertyUtf8(napi_env env, napi_value object, const std::string &propertyName);
    static void SetStringPropertyUtf8(
        napi_env env, napi_value object, const std::string &name, const std::string &value);
    static std::string GetValueString(napi_env env, napi_value value);
    static bool ValueIsArrayBuffer(napi_env env, napi_value value);
    static void *GetInfoFromArrayBufferValue(napi_env env, napi_value value, size_t *length);
    static napi_value CreateArrayBuffer(napi_env env, size_t length, void **data);
    static napi_value CreateObject(napi_env env);
    static napi_value GetUndefined(napi_env env);
    static napi_value CallFunction(napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value *argv);
    static napi_value CreateFunction(napi_env env, const std::string &name, napi_callback func, void *arg);
    static napi_ref CreateReference(napi_env env, napi_value callback);
    static napi_value GetReference(napi_env env, napi_ref callbackRef);
    static void DeleteReference(napi_env env, napi_ref callbackRef);
    static bool GetBooleanProperty(napi_env env, napi_value object, const std::string &propertyName);
    static void SetBooleanProperty(napi_env env, napi_value object, const std::string &name, bool value);
    static void DefineProperties(
        napi_env env, napi_value object, const std::initializer_list<napi_property_descriptor> &properties);
    static std::string ToLower(const std::string &s);
    static std::string GetExtensionId(napi_env env, napi_value *argv);
    static std::string GetExtensionId(const std::string &globalId);    
    static std::string GetGlobalId(const std::string& extensionId, const std::string& localId);
    static std::string GetLocalId(const std::string& globalId, const std::string& extensionId);    
    static std::string EncodeExtensionCid(const std::string &extensionId, uint32_t callbackId);
    static bool DecodeExtensionCid(const std::string &cid, std::string &extensionId, uint32_t &callbackId);
    static std::string GetTaskEventId(const std::string &taskId, const std::string &type);
    static int32_t OpenFile(const std::string &filePath);
    static bool IsPathValid(const std::string &filePath);
};
} // namespace OHOS::Print
#endif // NAPI_PRINT_UTILS_H