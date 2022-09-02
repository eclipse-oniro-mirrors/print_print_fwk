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
#include "print_log.h"
#include "print_manager_client.h"
#include "print_napi_utils.h"

static constexpr const char *PARAM_INFO_PRINTID = "printerId";
static constexpr const char *PARAM_INFO_PRINTERNAME = "printerName";
static constexpr const char *PARAM_INFO_PRINTERICON = "printerIcon";
static constexpr const char *PARAM_INFO_PRINTERSTATE = "printerState";
static constexpr const char *PARAM_INFO_DESCRIPTION = "description";
static constexpr const char *PARAM_INFO_CAPABILITY = "capability";

static constexpr const char *PARAM_CAPABILITY_MINMARGIN = "minMargin";
static constexpr const char *PARAM_CAPABILITY_PAGESIZE = "pageSize";
static constexpr const char *PARAM_CAPABILITY_RESOLUTION = "resolution";
static constexpr const char *PARAM_CAPABILITY_COLORMODE = "colorMode";
static constexpr const char *PARAM_CAPABILITY_DUPLEXMODE = "duplexMode";

static constexpr const char *PARAM_PAGESIZE_ID = "id";
static constexpr const char *PARAM_PAGESIZE_NAME = "name";
static constexpr const char *PARAM_PAGESIZE_WIDTH = "width";
static constexpr const char *PARAM_PAGESIZE_HEIGHT = "height";

static constexpr const char *PARAM_RESOLUTION_ID = "id";
static constexpr const char *PARAM_RESOLUTION_HORIZONTALDPI = "horizontalDpi";
static constexpr const char *PARAM_RESOLUTION_VERTICALDPI = "verticalDpi";

static constexpr const char *PARAM_MARGIN_TOP = "top";
static constexpr const char *PARAM_MARGIN_BOTTOM = "bottom";
static constexpr const char *PARAM_MARGIN_LEFT = "left";
static constexpr const char *PARAM_MARGIN_RIGHT = "right";

namespace OHOS::Print {
napi_value NapiPrintExt::AddPrinters(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == PrintNapiUtils::ONE_ARG, " should 1 parameter!", napi_invalid_arg);
        napi_value array = argv[PrintNapiUtils::FIRST_ARGV];
        bool isArray = false;
        napi_is_array(env, array, &isArray);
        NAPI_ASSERT_BASE(env, isArray, " is not array!", napi_invalid_arg);

        uint32_t result_size;
        napi_get_array_length(env, argv[PrintNapiUtils::FIRST_ARGV], &result_size);

        PrinterInfo info_;
        for (uint32_t i = 0; i < result_size; i++) {
            napi_value value;
            napi_get_element(env, array, i, &value);
            if (!ParseInfo(env, value, info_)) {
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
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == PrintNapiUtils::ONE_ARG, " should 1 parameter!", napi_invalid_arg);
        napi_value array = argv[PrintNapiUtils::FIRST_ARGV];
        bool isArray = false;
        napi_is_array(env, array, &isArray);
        NAPI_ASSERT_BASE(env, isArray, " is not array!", napi_invalid_arg);

        uint32_t result_size;
        napi_get_array_length(env, argv[PrintNapiUtils::FIRST_ARGV], &result_size);

        PrinterInfo info_;
        for (uint32_t i = 0; i < result_size; i++) {
            napi_value value;
            napi_get_element(env, array, i, &value);
            if (!ParseInfo(env, value, info_)) {
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
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == PrintNapiUtils::TWO_ARG, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "valuetype is not a number", napi_invalid_arg);
        uint32_t printerId = 0;
        napi_get_value_uint32(env, argv[PrintNapiUtils::FIRST_ARGV], &printerId);
        PRINT_HILOGD("printerId : %{public}d", printerId);
        context->printerId = printerId;
        napi_valuetype valueSecondtype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::SECOND_ARGV], &valueSecondtype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valueSecondtype == napi_number, "valueSecondtype is not a string", napi_invalid_arg);
        uint32_t printerState = 0;
        napi_get_value_uint32(env, argv[PrintNapiUtils::SECOND_ARGV], &printerState);
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
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == PrintNapiUtils::TWO_ARG, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerJobState is not a number", napi_invalid_arg);
        uint32_t printerJobId = 0;
        napi_get_value_uint32(env, argv[PrintNapiUtils::FIRST_ARGV], &printerJobId);
        PRINT_HILOGD("printerJobId : %{public}d", printerJobId);
        context->printerJobId = printerJobId;
        napi_valuetype valueSecondtype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::SECOND_ARGV], &valueSecondtype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valueSecondtype == napi_number, "valueSecondtype is not a string", napi_invalid_arg);
        uint32_t printerJobState = 0;
        napi_get_value_uint32(env, argv[PrintNapiUtils::SECOND_ARGV], &printerJobState);
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

bool NapiPrintExt::ParseInfo(napi_env env, napi_value InfoValue, PrinterInfo &info)
{
    if (!ParseInfoParam(env, InfoValue, info)) {
        PRINT_HILOGD("ParseInfoParam is error!");
        return false;
    }
    info.SetPrinterName(PrintNapiUtils::GetStringPropertyUtf8(env, InfoValue, PARAM_INFO_PRINTERNAME));
    info.SetPrinterIcon(PrintNapiUtils::GetUint32Property(env, InfoValue, PARAM_INFO_PRINTERICON));
    info.SetPrinterState(PrintNapiUtils::GetUint32Property(env, InfoValue, PARAM_INFO_PRINTERSTATE));
    info.SetDescription(PrintNapiUtils::GetStringPropertyUtf8(env, InfoValue, PARAM_INFO_DESCRIPTION));

    PRINT_HILOGD("info_value printId value is: %{public}d", info.GetPrintId());
    PRINT_HILOGD("info_value printerName value is %{public}s", info.GetPrinterName().c_str());
    PRINT_HILOGD("info_value printerIcon value is %{public}d", info.GetPrinterIcon());
    PRINT_HILOGD("info_value printerState value is  %{public}d", info.GetPrinterState());
    PRINT_HILOGD("info_value description value is  %{public}s", info.GetDescription().c_str());
    return true;
}

bool NapiPrintExt::ParseInfoParam(napi_env env, napi_value InfoValue, PrinterInfo &info)
{
    napi_value param_one = PrintNapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTID);
    if (PrintNapiUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = PrintNapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERNAME);
    if (PrintNapiUtils::GetValueType(env, param_two) != napi_string) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = PrintNapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERICON);
    if (PrintNapiUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = PrintNapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERSTATE);
    if (PrintNapiUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    napi_value param_five = PrintNapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_DESCRIPTION);
    if (PrintNapiUtils::GetValueType(env, param_five) != napi_string) {
        PRINT_HILOGD("error param_five");
        return false;
    }
    napi_value param_six = PrintNapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_CAPABILITY);
    if (PrintNapiUtils::GetValueType(env, param_six) != napi_object) {
        PRINT_HILOGD("error param_six");
        return false;
    } else {
        PrinterCapability capability;
        if (!ParseCapability(env, param_six, capability)) {
            PRINT_HILOGD("ParseCapability type error!");
        }
        info.SetCapability(capability);
    }
    auto names = PrintNapiUtils::GetPropertyNames(env, InfoValue);

    std::vector<std::string>::iterator iter;
    PRINT_HILOGD("current name list size = %{public}zu", names.size());
    for (iter = names.begin(); iter != names.end(); ++iter) {
        uint32_t value = PrintNapiUtils::GetUint32Property(env, param_one, *iter);
        if (value) {
            info.SetPrinterId(value);
        }
    }
    return true;
}
bool NapiPrintExt::ParseCapability(napi_env env, napi_value capValue, PrinterCapability &capability)
{
    if (!ParseCapabilityParam(env, capValue, capability)) {
        PRINT_HILOGD("ParseCapabilityParam is error!");
        return false;
    }
    // capability.SetMinMargin(PrintNapiUtils::GetStringPropertyUtf8(env, capValue, PARAM_CAPABILITY_MINMARGIN));
    capability.SetColorMode(PrintNapiUtils::GetUint32Property(env, capValue, PARAM_CAPABILITY_COLORMODE));
    capability.SetDuplexMode(PrintNapiUtils::GetUint32Property(env, capValue, PARAM_CAPABILITY_DUPLEXMODE));
    PRINT_HILOGD("capability_value colorMode value is  %{public}d", capability.GetColorMode());
    PRINT_HILOGD("capability_value duplexMode value is  %{public}d", capability.GetDuplexMode());
    return true;
}
bool NapiPrintExt::ParseCapabilityParam(napi_env env, napi_value capValue, PrinterCapability &capability)
{
    napi_value param_one = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_MINMARGIN);
    if (PrintNapiUtils::GetValueType(env, param_one) != napi_object) {
        PRINT_HILOGD("error param_one");
        return false;
    } else {
        PrintMargin margin;
        if (!ParseMargin(env, param_one, margin)) {
            PRINT_HILOGD("ParseCapability type error!");
        }
        capability.SetMinMargin(margin);
    }

    napi_value param_two = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_PAGESIZE);
    if (PrintNapiUtils::GetValueType(env, param_two) != napi_object) {
        PRINT_HILOGD("error param_two");
        return false;
    } else {
        bool isArray = false;
        napi_is_array(env, param_two, &isArray);
        if (!isArray) {
            PRINT_HILOGD("ParsePageSize type error!");
            return false;
        }

        std::vector<PrintPageSize> pageSizeList;
        uint32_t arrayLength = 0;
        napi_get_array_length(env, param_two, &arrayLength);
        for (uint32_t i = 0; i < arrayLength; i++) {
            napi_value pageSizeValue;
            PrintPageSize pageSize;
            napi_get_element(env, param_two, i, &pageSizeValue);
            // status = napi_get_property(env, result, param_six, &pageResult);
            if (!ParsePageSize(env, pageSizeValue, pageSize)) {
                PRINT_HILOGD("ParsePageSize type error!");
                return false;
            }
            pageSizeList.push_back(pageSize);
        }
        capability.SetPageSize(pageSizeList);
    }

    napi_value param_three = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_RESOLUTION);
    if (PrintNapiUtils::GetValueType(env, param_three) != napi_object) {
        PRINT_HILOGD("error param_three");
        return false;
    } else {
        bool isReArray = false;
        napi_is_array(env, param_three, &isReArray);
        if (!isReArray) {
            PRINT_HILOGD("PrintResolution type error!");
            return false;
        }
        std::vector<PrintResolution> resolutionList;
        uint32_t arrayReLength = 0;
        napi_get_array_length(env, param_three, &arrayReLength);
        for (uint32_t i = 0; i < arrayReLength; i++) {
            napi_value reValue;
            PrintResolution resolution;
            napi_get_element(env, param_three, i, &reValue);
            if (!ParseResolution(env, reValue, resolution)) {
                PRINT_HILOGD("PrintResolution type error!");
                return false;
            }
            resolutionList.push_back(resolution);
        }
        capability.SetResolution(resolutionList);
    }
    napi_value param_four = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_COLORMODE);
    if (PrintNapiUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    napi_value param_five = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_DUPLEXMODE);
    if (PrintNapiUtils::GetValueType(env, param_five) != napi_number) {
        // ParseCapabilityParam()
        PRINT_HILOGD("error param_five");
        return false;
    }
    auto names = PrintNapiUtils::GetPropertyNames(env, capValue);

    std::vector<std::string>::iterator iter;
    PRINT_HILOGD("current name list size = %{public}zu", names.size());
    for (iter = names.begin(); iter != names.end(); ++iter) {
        uint32_t value = PrintNapiUtils::GetUint32Property(env, param_four, *iter);
        if (value) {
            capability.SetColorMode(value);
        }
    }
    return true;
}

bool NapiPrintExt::ParsePageSize(napi_env env, napi_value capValue, PrintPageSize &pageSize)
{
    if (!ParsePageSizeParam(env, capValue, pageSize)) {
        PRINT_HILOGD("ParsePageSizeParam is error!");
        return false;
    }
    pageSize.SetName(PrintNapiUtils::GetStringPropertyUtf8(env, capValue, PARAM_PAGESIZE_NAME));
    pageSize.SetWidth(PrintNapiUtils::GetUint32Property(env, capValue, PARAM_PAGESIZE_WIDTH));
    pageSize.SetHeight(PrintNapiUtils::GetUint32Property(env, capValue, PARAM_PAGESIZE_HEIGHT));

    PRINT_HILOGD("printerPageSize_value GetId value is %{public}d", pageSize.GetId());
    PRINT_HILOGD("printerPageSize_value GetName value is %{public}s", pageSize.GetName().c_str());
    PRINT_HILOGD("printerPageSize_value GetWidth value is  %{public}d", pageSize.GetWidth());
    PRINT_HILOGD("printerPageSize_value GetHeight value is  %{public}d", pageSize.GetHeight());
    return true;
}

bool NapiPrintExt::ParsePageSizeParam(napi_env env, napi_value capValue, PrintPageSize &pageSize)
{
    napi_value param_one = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_ID);
    if (PrintNapiUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_NAME);
    if (PrintNapiUtils::GetValueType(env, param_two) != napi_string) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_WIDTH);
    if (PrintNapiUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = PrintNapiUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_HEIGHT);
    if (PrintNapiUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    auto names = PrintNapiUtils::GetPropertyNames(env, capValue);

    std::vector<std::string>::iterator iter;
    PRINT_HILOGD("current name list size = %{public}zu", names.size());
    for (iter = names.begin(); iter != names.end(); ++iter) {
        uint32_t value = PrintNapiUtils::GetUint32Property(env, param_four, *iter);
        if (value) {
            pageSize.SetId(value);
        }
    }
    return true;
}
bool NapiPrintExt::ParseResolution(napi_env env, napi_value reValue, PrintResolution &resolution)
{
    if (!ParseResolutionParam(env, reValue, resolution)) {
        PRINT_HILOGD("ParseResolutionParam is error!");
        return false;
    }
    resolution.SetId(PrintNapiUtils::GetUint32Property(env, reValue, PARAM_RESOLUTION_ID));
    resolution.SetHorizontalDpi(PrintNapiUtils::GetUint32Property(env, reValue, PARAM_RESOLUTION_HORIZONTALDPI));
    resolution.SetVerticalDpi(PrintNapiUtils::GetUint32Property(env, reValue, PARAM_RESOLUTION_VERTICALDPI));

    PRINT_HILOGD("printerResolution_value GetId value is %{public}d", resolution.GetId());
    PRINT_HILOGD("printerResolution_value GetHorizontalDpi value is %{public}d", resolution.GetHorizontalDpi());
    PRINT_HILOGD("printerResolution_value GetVerticalDpi value is  %{public}d", resolution.GetVerticalDpi());
    return true;
}

bool NapiPrintExt::ParseResolutionParam(napi_env env, napi_value reValue, PrintResolution &resolution)
{
    napi_value param_one = PrintNapiUtils::GetNamedProperty(env, reValue, PARAM_RESOLUTION_ID);
    if (PrintNapiUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = PrintNapiUtils::GetNamedProperty(env, reValue, PARAM_RESOLUTION_HORIZONTALDPI);
    if (PrintNapiUtils::GetValueType(env, param_two) != napi_number) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = PrintNapiUtils::GetNamedProperty(env, reValue, PARAM_RESOLUTION_VERTICALDPI);
    if (PrintNapiUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    auto names = PrintNapiUtils::GetPropertyNames(env, reValue);
    PRINT_HILOGD("current resolution paramster name list size = %{public}zu", names.size());
    return true;
}

bool NapiPrintExt::ParseMargin(napi_env env, napi_value marginValue, PrintMargin &margin)
{
    if (!ParseMarginParam(env, marginValue, margin)) {
        PRINT_HILOGD("ParseResolutionParam is error!");
        return false;
    }
    margin.SetTop(PrintNapiUtils::GetUint32Property(env, marginValue, PARAM_MARGIN_TOP));
    margin.SetBottom(PrintNapiUtils::GetUint32Property(env, marginValue, PARAM_MARGIN_BOTTOM));
    margin.SetLeft(PrintNapiUtils::GetUint32Property(env, marginValue, PARAM_MARGIN_LEFT));
    margin.SetRight(PrintNapiUtils::GetUint32Property(env, marginValue, PARAM_MARGIN_RIGHT));

    PRINT_HILOGD("printerMargin_value GetTop value is %{public}d", margin.GetTop());
    PRINT_HILOGD("printerMargin_value GetBottom value is %{public}d", margin.GetBottom());
    PRINT_HILOGD("printerMargin_value GetLeft value is  %{public}d", margin.GetLeft());
    PRINT_HILOGD("printerMargin_value GetRight value is  %{public}d", margin.GetRight());

    return true;
}

bool NapiPrintExt::ParseMarginParam(napi_env env, napi_value marginValue, PrintMargin &margin)
{
    //±ØÒªÊôÐÔÐ£Ñé
    napi_value param_one = PrintNapiUtils::GetNamedProperty(env, marginValue, PARAM_MARGIN_TOP);
    if (PrintNapiUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = PrintNapiUtils::GetNamedProperty(env, marginValue, PARAM_MARGIN_BOTTOM);
    if (PrintNapiUtils::GetValueType(env, param_two) != napi_number) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = PrintNapiUtils::GetNamedProperty(env, marginValue, PARAM_MARGIN_LEFT);
    if (PrintNapiUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = PrintNapiUtils::GetNamedProperty(env, marginValue, PARAM_MARGIN_RIGHT);
    if (PrintNapiUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    auto names = PrintNapiUtils::GetPropertyNames(env, marginValue);
    PRINT_HILOGD("current margin paramster name list size = %{public}zu", names.size());
    return true;
}
} // namespace OHOS::Print
