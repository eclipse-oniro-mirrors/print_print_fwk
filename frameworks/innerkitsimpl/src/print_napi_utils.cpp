/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "print_napi_utils.h"

#include <cstring>
#include <initializer_list>
#include <memory>

#include "print_log.h"
#include "securec.h"

namespace OHOS::Print {
static constexpr const int MAX_STRING_LENGTH = 65536;

napi_valuetype PrintNapiUtils::GetValueType(napi_env env, napi_value value)
{
    if (value == nullptr) {
        return napi_undefined;
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &valueType), napi_undefined);
    return valueType;
}

/* named property */
bool PrintNapiUtils::HasNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty), false);
    return hasProperty;
}

napi_value PrintNapiUtils::GetNamedProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    napi_value value = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty));
    if (!hasProperty) {
        return value;
    }
    NAPI_CALL(env, napi_get_named_property(env, object, propertyName.c_str(), &value));
    return value;
}

void PrintNapiUtils::SetNamedProperty(napi_env env, napi_value object, const std::string &name, napi_value value)
{
    (void)napi_set_named_property(env, object, name.c_str(), value);
}

std::vector<std::string> PrintNapiUtils::GetPropertyNames(napi_env env, napi_value object)
{
    std::vector<std::string> ret;
    napi_value names = nullptr;
    NAPI_CALL_BASE(env, napi_get_property_names(env, object, &names), ret);
    uint32_t length = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, names, &length), ret);
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
napi_value PrintNapiUtils::CreateUint32(napi_env env, uint32_t code)
{
    napi_value value = nullptr;
    if (napi_create_uint32(env, code, &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

uint32_t PrintNapiUtils::GetUint32FromValue(napi_env env, napi_value value)
{
    uint32_t ret = 0;
    NAPI_CALL_BASE(env, napi_get_value_uint32(env, value, &ret), 0);
    return ret;
}

uint32_t PrintNapiUtils::GetUint32Property(napi_env env, napi_value object, const std::string &propertyName)
{
    if (!HasNamedProperty(env, object, propertyName)) {
        return 0;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetUint32FromValue(env, value);
}

void PrintNapiUtils::SetUint32Property(napi_env env, napi_value object, const std::string &name, uint32_t value)
{
    napi_value jsValue = CreateUint32(env, value);
    if (GetValueType(env, jsValue) != napi_number) {
        return;
    }

    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* INT32 */
napi_value PrintNapiUtils::CreateInt32(napi_env env, int32_t code)
{
    napi_value value = nullptr;
    if (napi_create_int32(env, code, &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

int32_t PrintNapiUtils::GetInt32FromValue(napi_env env, napi_value value)
{
    int32_t ret = 0;
    NAPI_CALL_BASE(env, napi_get_value_int32(env, value, &ret), 0);
    return ret;
}

int32_t PrintNapiUtils::GetInt32Property(napi_env env, napi_value object, const std::string &propertyName)
{
    if (!HasNamedProperty(env, object, propertyName)) {
        return 0;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetInt32FromValue(env, value);
}

void PrintNapiUtils::SetInt32Property(napi_env env, napi_value object, const std::string &name, int32_t value)
{
    napi_value jsValue = CreateInt32(env, value);
    if (GetValueType(env, jsValue) != napi_number) {
        return;
    }

    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* String UTF8 */
napi_value PrintNapiUtils::CreateStringUtf8(napi_env env, const std::string &str)
{
    napi_value value = nullptr;
    if (napi_create_string_utf8(env, str.c_str(), strlen(str.c_str()), &value) != napi_ok) {
        return nullptr;
    }
    return value;
}

std::string PrintNapiUtils::GetStringFromValueUtf8(napi_env env, napi_value value)
{
    std::string result;
    std::vector<char> str(MAX_STRING_LENGTH + 1, '\0');
    size_t length = 0;
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, value, &str[0], MAX_STRING_LENGTH, &length), result);
    if (length > 0) {
        return result.append(&str[0], length);
    }
    return result;
}

std::string PrintNapiUtils::GetStringPropertyUtf8(napi_env env, napi_value object, const std::string &propertyName)
{
    if (!HasNamedProperty(env, object, propertyName)) {
        return "";
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    return GetStringFromValueUtf8(env, value);
}

void PrintNapiUtils::SetStringPropertyUtf8(
    napi_env env, napi_value object, const std::string &name, const std::string &value)
{
    napi_value jsValue = CreateStringUtf8(env, value);
    if (GetValueType(env, jsValue) != napi_string) {
        return;
    }
    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* array buffer */
bool PrintNapiUtils::ValueIsArrayBuffer(napi_env env, napi_value value)
{
    bool isArrayBuffer = false;
    NAPI_CALL_BASE(env, napi_is_arraybuffer(env, value, &isArrayBuffer), false);
    return isArrayBuffer;
}

void *PrintNapiUtils::GetInfoFromArrayBufferValue(napi_env env, napi_value value, size_t *length)
{
    if (length == nullptr) {
        return nullptr;
    }

    void *data = nullptr;
    NAPI_CALL(env, napi_get_arraybuffer_info(env, value, &data, length));
    return data;
}

/* object */
napi_value PrintNapiUtils::CreateObject(napi_env env)
{
    napi_value object = nullptr;
    NAPI_CALL(env, napi_create_object(env, &object));
    return object;
}

/* undefined */
napi_value PrintNapiUtils::GetUndefined(napi_env env)
{
    napi_value undefined = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &undefined));
    return undefined;
}

/* function */
napi_value PrintNapiUtils::CallFunction(
    napi_env env, napi_value recv, napi_value func, size_t argc, const napi_value *argv)
{
    napi_value res = nullptr;
    NAPI_CALL(env, napi_call_function(env, recv, func, argc, argv, &res));
    return res;
}

/* reference */
napi_ref PrintNapiUtils::CreateReference(napi_env env, napi_value callback)
{
    napi_ref callbackRef = nullptr;
    NAPI_CALL(env, napi_create_reference(env, callback, 1, &callbackRef));
    return callbackRef;
}

napi_value PrintNapiUtils::GetReference(napi_env env, napi_ref callbackRef)
{
    napi_value callback = nullptr;
    NAPI_CALL(env, napi_get_reference_value(env, callbackRef, &callback));
    return callback;
}

void PrintNapiUtils::DeleteReference(napi_env env, napi_ref callbackRef)
{
    (void)napi_delete_reference(env, callbackRef);
}

/* boolean */
bool PrintNapiUtils::GetBooleanProperty(napi_env env, napi_value object, const std::string &propertyName)
{
    if (!HasNamedProperty(env, object, propertyName)) {
        return false;
    }
    napi_value value = GetNamedProperty(env, object, propertyName);
    bool ret = false;
    NAPI_CALL_BASE(env, napi_get_value_bool(env, value, &ret), false);
    return ret;
}

void PrintNapiUtils::SetBooleanProperty(napi_env env, napi_value object, const std::string &name, bool value)
{
    napi_value jsValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, value, &jsValue));
    if (GetValueType(env, jsValue) != napi_boolean) {
        return;
    }

    napi_set_named_property(env, object, name.c_str(), jsValue);
}

/* define properties */
void PrintNapiUtils::DefineProperties(
    napi_env env, napi_value object, const std::initializer_list<napi_property_descriptor> &properties)
{
    napi_property_descriptor descriptors[properties.size()];
    std::copy(properties.begin(), properties.end(), descriptors);

    (void)napi_define_properties(env, object, properties.size(), descriptors);
}

std::string PrintNapiUtils::ToLower(const std::string &s)
{
    std::string res = s;
    std::transform(res.begin(), res.end(), res.begin(), tolower);
    return res;
}

std::string PrintNapiUtils::GetValueString(napi_env env, napi_value value)
{
    std::string resultValue = "";
    char value_string[256];
    size_t value_size = 256;
    size_t result;
    napi_get_value_string_utf8(env, value, value_string, value_size, &result);
    resultValue = value_string;
    return resultValue;
}

napi_value PrintNapiUtils::Convert2JsObj(napi_env env, const PrintJob &job)
{
    napi_value result;
    NAPI_CALL(env, napi_create_object(env, &result));

    std::vector<std::string> files;
    job.GetFiles(files);
    uint32_t arrFilesLength = files.size();

    napi_value arrFiles;
    NAPI_CALL(env, napi_create_array(env, &arrFiles));
    for (uint32_t i = 0; i < arrFilesLength; i++) {
        napi_value value;
        NAPI_CALL(env, napi_create_string_utf8(env, files[i].c_str(), NAPI_AUTO_LENGTH, &value));
        NAPI_CALL(env, napi_set_element(env, arrFiles, i, value));
    }
    NAPI_CALL(env, napi_set_named_property(env, result, "files", arrFiles));

    SetUint32Property(env, result, "jobId", job.GetJobId());
    SetUint32Property(env, result, "printerId", job.GetPrinterId());
    SetUint32Property(env, result, "jobState", job.GetJobState());
    SetUint32Property(env, result, "copyNumber", job.GetCopyNumber());

    PrintRange nativeRange;
    job.GetPageRange(nativeRange);
    std::vector<uint32_t> pages;
    nativeRange.GetPages(pages);

    napi_value pageRange;
    NAPI_CALL(env, napi_create_object(env, &pageRange));
    SetUint32Property(env, pageRange, "startPage", nativeRange.GetStartPage());
    SetUint32Property(env, pageRange, "endPage", nativeRange.GetEndPage());
    napi_value arrPages;
    NAPI_CALL(env, napi_create_array(env, &arrPages));

    uint32_t arrPagesLength = pages.size();
    for (uint32_t i = 0; i < arrPagesLength; i++) {
        napi_value value;
        NAPI_CALL(env, napi_create_uint32(env, pages[i], &value));
        NAPI_CALL(env, napi_set_element(env, arrPages, i, value));
    }
    NAPI_CALL(env, napi_set_named_property(env, pageRange, "pages", arrPages));
    NAPI_CALL(env, napi_set_named_property(env, result, "pageRange", pageRange));

    SetUint32Property(env, result, "isSequential", job.GetIsSequential());

    PrintPageSize nativePageSize;
    job.GetPageSize(nativePageSize);

    napi_value pageSize;
    NAPI_CALL(env, napi_create_object(env, &pageSize));
    SetUint32Property(env, pageSize, "id", nativePageSize.GetId());
    SetStringPropertyUtf8(env, pageSize, "name", nativePageSize.GetName().c_str());
    SetUint32Property(env, pageSize, "width", nativePageSize.GetWidth());
    SetUint32Property(env, pageSize, "height", nativePageSize.GetHeight());
    NAPI_CALL(env, napi_set_named_property(env, result, "pageSize", pageSize));

    SetUint32Property(env, result, "isLandscape", job.GetIsLandscape());
    SetUint32Property(env, result, "colorMode", job.GetColorMode());
    SetUint32Property(env, result, "duplexMode", job.GetDuplexMode());

    PrintMargin nativeMargin;
    job.GetMargin(nativeMargin);

    napi_value margin;
    NAPI_CALL(env, napi_create_object(env, &margin));
    SetUint32Property(env, margin, "top", nativeMargin.GetTop());
    SetUint32Property(env, margin, "bottom", nativeMargin.GetBottom());
    SetUint32Property(env, margin, "left", nativeMargin.GetLeft());
    SetUint32Property(env, margin, "right", nativeMargin.GetRight());
    NAPI_CALL(env, napi_set_named_property(env, result, "margin", margin));

    PreviewAttribute previewAttr;
    job.GetPreview(previewAttr);
    previewAttr.GetPreviewRange(nativeRange);
    nativeRange.GetPages(pages);

    napi_value preview;
    NAPI_CALL(env, napi_create_object(env, &preview));
    SetStringPropertyUtf8(env, preview, "result", previewAttr.GetResult().c_str());
    napi_value subPageRange;
    NAPI_CALL(env, napi_create_object(env, &subPageRange));
    SetUint32Property(env, subPageRange, "startPage", nativeRange.GetStartPage());
    SetUint32Property(env, subPageRange, "endPage", nativeRange.GetEndPage());

    napi_value arrPreviewPages;
    NAPI_CALL(env, napi_create_array(env, &arrPreviewPages));
    uint32_t arrPreviewPagesLength = pages.size();

    for (uint32_t i = 0; i < arrPreviewPagesLength; i++) {
        napi_value value;
        NAPI_CALL(env, napi_create_uint32(env, pages[i], &value));
        NAPI_CALL(env, napi_set_element(env, arrPreviewPages, i, value));
    }
    NAPI_CALL(env, napi_set_named_property(env, subPageRange, "pages", arrPreviewPages));
    NAPI_CALL(env, napi_set_named_property(env, preview, "pageRange", subPageRange));
    NAPI_CALL(env, napi_set_named_property(env, result, "preview", preview));
    return result;
}
} // namespace OHOS::Print