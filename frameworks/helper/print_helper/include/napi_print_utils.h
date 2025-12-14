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
#include <map>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "print_constant.h"
#include "ppd_info_helper.h"

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

    static constexpr uint32_t INDEX_ZERO = 0;
    static constexpr uint32_t INDEX_ONE = 1;
    static constexpr uint32_t INDEX_TWO = 2;
    static constexpr uint32_t INDEX_THREE = 3;
    static constexpr uint32_t INDEX_FOUR = 4;
    static constexpr uint32_t INDEX_FIVE = 5;

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
    static napi_value CreateStringVectorUtf8(napi_env env, const std::vector<std::string> &vec);
    static napi_value CreatePpdInfoVectorUtf8(napi_env env, const std::vector<PpdInfo> &vec);
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

    static size_t GetJsVal(napi_env env, napi_callback_info info, napi_value argv[], size_t length);
    static bool VerifyProperty(std::vector<std::string> &names, std::map<std::string, PrintParamStatus> &propertyList);
    static std::string GetPrintErrorMsg(int32_t errorCode);
    static bool CheckCallerIsSystemApp();
    static const std::string GetErrorMsgByErrorCode(int32_t code);
    static napi_value CreateJsError(napi_env env, int32_t errCode);
    static char* GetCharPtrFromValueUtf8(napi_env env, napi_value value);

    template<typename T>
    static bool ProcessJsArrayProperty(napi_env env, napi_value jsValue, const char *propertyName,
                                       std::function<void(const std::vector<T> &)> setFunction,
                                       std::function<std::shared_ptr<T>(napi_env, napi_value)> buildFunction)
    {
        if (!setFunction) {
            PRINT_HILOGE("setFunction is illegal");
            return false;
        }
        if (!buildFunction) {
            PRINT_HILOGE("buildFunction is illegal");
            return false;
        }
        napi_value jsArray;
        bool hasProperty = NapiPrintUtils::HasNamedProperty(env, jsValue, propertyName);
        if (!hasProperty) {
            return true;
        }

        napi_status status = napi_get_named_property(env, jsValue, propertyName, &jsArray);
        if (status != napi_ok) {
            return false;
        }

        bool isArray = false;
        napi_is_array(env, jsArray, &isArray);
        if (!isArray) {
            PRINT_HILOGE("Can not get an array for property %{public}s", propertyName);
            return false;
        }

        uint32_t length = 0;
        napi_get_array_length(env, jsArray, &length);
        if (length > MAX_ARRAY_LENGTH) {
            PRINT_HILOGE("the array length is over %{public}d", MAX_ARRAY_LENGTH);
            return false;
        }
        std::vector<T> items;
        items.reserve(length);

        for (uint32_t i = 0; i < length; ++i) {
            napi_value jsItem;
            napi_get_element(env, jsArray, i, &jsItem);
            auto item = buildFunction(env, jsItem);
            if (!item) {
                PRINT_HILOGE("Failed to build item for property %{public}s", propertyName);
                continue;
            }
            items.push_back(*item);
        }

        setFunction(items);
        return true;
    }
};
} // namespace OHOS::Print
#endif // NAPI_PRINT_UTILS_H