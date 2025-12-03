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
#ifndef PRINTER_CAPABILITY_HELPER_H
#define PRINTER_CAPABILITY_HELPER_H

#define MAX_ARRAY_LENGTH 128

#include <map>
#include "napi/native_api.h"
#include "printer_capability.h"
#include "print_log.h"
#include "napi_print_utils.h"

namespace OHOS::Print {
class PrinterCapabilityHelper {
public:
    static napi_value MakeJsObject(napi_env env, const PrinterCapability &cap);
    static std::shared_ptr<PrinterCapability> BuildFromJs(napi_env env, napi_value jsValue);
    static bool BuildSimplePropertyFromJs(napi_env env, napi_value jsValue,
        std::shared_ptr<PrinterCapability> nativeObj);
    static bool BuildArrayPropertyFromJs(napi_env env, napi_value jsValue,
        std::shared_ptr<PrinterCapability> nativeObj);

private:
    static bool CreatePageSizeList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool CreateResolutionList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool CreateSupportedColorModeList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool CreateSupportedDuplexModeList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool CreateSupportedMediaTypeList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool CreateSupportedQualityList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool CreateSupportedOrientationList(napi_env env, napi_value &jsPrinterCap, const PrinterCapability &cap);
    static bool BuildSupportedPageSizes(napi_env env, napi_value jsValue,
                                        std::shared_ptr<PrinterCapability> nativeObj);
    static bool BuildSupportedResolutions(napi_env env, napi_value jsValue,
                                          std::shared_ptr<PrinterCapability> nativeObj);
    static bool BuildSupportedColorModes(napi_env env, napi_value jsValue,
                                         std::shared_ptr<PrinterCapability> nativeObj);
    static bool BuildSupportedDuplexModes(napi_env env, napi_value jsValue,
                                          std::shared_ptr<PrinterCapability> nativeObj);
    static bool BuildSupportedQualities(napi_env env, napi_value jsValue,
                                        std::shared_ptr<PrinterCapability> nativeObj);
    static bool BuildSupportedMediaTypes(napi_env env, napi_value jsValue,
                                         std::shared_ptr<PrinterCapability> nativeObj);
    static bool BuildSupportedOrientations(napi_env env, napi_value jsValue,
                                           std::shared_ptr<PrinterCapability> nativeObj);
    static bool ValidateProperty(napi_env env, napi_value object);

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
}  // namespace OHOS::Print
#endif  // PRINTER_CAPABILITY_HELPER_H
