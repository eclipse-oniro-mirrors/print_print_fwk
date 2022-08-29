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
#include "log.h"
#include "napi_utils.h"
#include "print_manager.h"

static constexpr const char *PARAM_INFO_PRINTID = "printerId";
static constexpr const char *PARAM_INFO_PRINTERNAME = "printerName";
static constexpr const char *PARAM_INFO_PRINTERICON = "printerIcon";
static constexpr const char *PARAM_INFO_PRINTERSTATE = "printerState";
static constexpr const char *PARAM_INFO_DESCRIPTION = "description";
static constexpr const char *PARAM_INFO_CAPABILITY = "capability";

namespace OHOS::Print {
napi_value NapiPrintExt::AddPrinters(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == NapiUtils::ONE_ARG, " should 1 parameter!", napi_invalid_arg);
        napi_value array = argv[NapiUtils::FIRST_ARGV];
        bool isArray = false;
        napi_is_array(env, array, &isArray);
        NAPI_ASSERT_BASE(env, isArray, " is not array!", napi_invalid_arg);

        uint32_t result_size;
        napi_get_array_length(env, argv[NapiUtils::FIRST_ARGV], &result_size);

        PrintInfo info_;
        for(uint32_t i = 0; i < result_size; i++)
        {
            napi_value value;
            napi_get_element(env, array, i, &value);
            if(!ParseInfo(env, value, info_))
            {
                PRINT_HILOGD("PrintInfo is format error!");
            } 
            context->printInfoVector.push_back(info_);
        }
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
         for(uint32_t i = 0; i < 3; i++)
        {
            PrintInfo printInfo;
            printInfo.SetPrinterId(1);
            printInfo.SetPrinterName("data.ReadString()");
            printInfo.SetPrinterIcon(1);
            printInfo.SetPrinterState(1);
            printInfo.SetDescription("data.ReadString()");
            printInfo.GetCapability().GetMinMargin().SetTop(1);
            printInfo.GetCapability().GetMinMargin().SetBottom(1);
            printInfo.GetCapability().GetMinMargin().SetLeft(1);
            printInfo.GetCapability().GetMinMargin().SetRight(1); 
            for(uint32_t i = 0; i < 3; i++)
            {   
                PrinterPageSize printerPageSize;
                printerPageSize.SetId(1);
                printerPageSize.SetName("data.ReadString()");
                printerPageSize.SetWidth(1);
                printerPageSize.SetHeight(1);
                printInfo.GetCapability().GetPageSize().push_back(printerPageSize);
            }     
            for(uint32_t i = 0; i < 3; i++)
            {
                PrinterResolution printerResolution;
                printerResolution.SetId(1);
                printerResolution.SetHorizontalDpi(1);
                printerResolution.SetVerticalDpi(1);
                printInfo.GetCapability().GetResolution().push_back(printerResolution);
            }   
            printInfo.GetCapability().SetColorMode(1);
            printInfo.GetCapability().SetDuplexMode(1);
            context->arrayPrintInfo.push_back(printInfo);

            PRINT_HILOGD("AddPrinters = %{public}d", context->arrayPrintInfo[i].GetPrintId());
            PRINT_HILOGD("AddPrinters = %{public}s", context->arrayPrintInfo[i].GetPrinterName().c_str());
            PRINT_HILOGD("AddPrinters = %{public}d", context->arrayPrintInfo[i].GetPrinterIcon());
            PRINT_HILOGD("AddPrinters = %{public}d", context->arrayPrintInfo[i].GetPrinterState());
            PRINT_HILOGD("AddPrinters = %{public}s", context->arrayPrintInfo[i].GetDescription().c_str());
        }
        context->result = PrintManager::GetInstance()->AddPrinters(context->arrayPrintInfo);
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
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        for(uint32_t i = 0; i < 3; i++)
        {
            PrintInfo printInfo;
            printInfo.SetPrinterId(1);
            printInfo.SetPrinterName("data.ReadString()");
            printInfo.SetPrinterIcon(1);
            printInfo.SetPrinterState(1);
            printInfo.SetDescription("data.ReadString()");
            printInfo.GetCapability().GetMinMargin().SetTop(1);
            printInfo.GetCapability().GetMinMargin().SetBottom(1);
            printInfo.GetCapability().GetMinMargin().SetLeft(1);
            printInfo.GetCapability().GetMinMargin().SetRight(1); 

            for(uint32_t i = 0; i < 3; i++)
            {   
                PrinterPageSize printerPageSize;
                printerPageSize.SetId(1);
                printerPageSize.SetName("data.ReadString()");
                printerPageSize.SetWidth(1);
                printerPageSize.SetHeight(1);
                printInfo.GetCapability().GetPageSize().push_back(printerPageSize);
            }

            for(uint32_t i = 0; i < 3; i++)
            {
                PrinterResolution printerResolution;
                printerResolution.SetId(1);
                printerResolution.SetHorizontalDpi(1);
                printerResolution.SetVerticalDpi(1);
                printInfo.GetCapability().GetResolution().push_back(printerResolution);
            }   

            printInfo.GetCapability().SetColorMode(1);
            printInfo.GetCapability().SetDuplexMode(1);
            context->arrayPrintInfo.push_back(printInfo);
            PRINT_HILOGD("AddPrinters = %{public}d", context->arrayPrintInfo[i].GetPrintId());
            PRINT_HILOGD("AddPrinters = %{public}s", context->arrayPrintInfo[i].GetPrinterName().c_str());
            PRINT_HILOGD("AddPrinters = %{public}d", context->arrayPrintInfo[i].GetPrinterIcon());
            PRINT_HILOGD("AddPrinters = %{public}d", context->arrayPrintInfo[i].GetPrinterState());
            PRINT_HILOGD("AddPrinters = %{public}s", context->arrayPrintInfo[i].GetDescription().c_str());
        }
        context->result = PrintManager::GetInstance()->RemovePrinters(context->arrayPrintInfo);
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
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == NapiUtils::TWO_ARG, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "valuetype is not a number", napi_invalid_arg);
        uint32_t printerId = 0;
        napi_get_value_uint32(env, argv[NapiUtils::FIRST_ARGV], &printerId);
        PRINT_HILOGD("printerId : %{public}d", printerId);
        context->printerId = printerId;
        napi_valuetype valueSecondtype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::SECOND_ARGV], &valueSecondtype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valueSecondtype == napi_number, "valueSecondtype is not a string", napi_invalid_arg);
        uint32_t printerState = 0;
        napi_get_value_uint32(env, argv[NapiUtils::SECOND_ARGV], &printerState);
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
        context->result = PrintManager::GetInstance()->UpdatePrinterState(context->printerId,context->printerState);
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
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<NapiPrintExtContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == NapiUtils::TWO_ARG, " should 2 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerJobState is not a number", napi_invalid_arg);
        uint32_t printerJobId = 0;
        napi_get_value_uint32(env, argv[NapiUtils::FIRST_ARGV], &printerJobId);
        PRINT_HILOGD("printerJobId : %{public}d", printerJobId);
        context->printerJobId = printerJobId;
        napi_valuetype valueSecondtype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::SECOND_ARGV], &valueSecondtype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valueSecondtype == napi_number, "valueSecondtype is not a string", napi_invalid_arg);
        uint32_t printerJobState = 0;
        napi_get_value_uint32(env, argv[NapiUtils::SECOND_ARGV], &printerJobState);
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
        context->result = PrintManager::GetInstance()->UpdatePrinterJobState(context->printerJobId,context->printerJobState);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

bool NapiPrintExt::ParseInfo(napi_env env, napi_value InfoValue, PrintInfo &info)
{
    if (!ParseInfoParam(env, InfoValue, info)) {
        PRINT_HILOGD("ParseInfoParam is error!");
        return false;
    }
    info.SetPrinterName(NapiUtils::GetStringPropertyUtf8(env, InfoValue, PARAM_INFO_PRINTERNAME));
    info.SetPrinterIcon(NapiUtils::GetUint32Property(env, InfoValue, PARAM_INFO_PRINTERICON));
    info.SetPrinterState(NapiUtils::GetUint32Property(env, InfoValue, PARAM_INFO_PRINTERSTATE));  
    info.SetDescription(NapiUtils::GetStringPropertyUtf8(env, InfoValue, PARAM_INFO_DESCRIPTION));

    PRINT_HILOGD("info_value printId value is: %{public}d", info.GetPrintId());
    PRINT_HILOGD("info_value printerName value is %{public}s", info.GetPrinterName().c_str());
    PRINT_HILOGD("info_value printerIcon value is %{public}d", info.GetPrinterIcon());
    PRINT_HILOGD("info_value printerState value is  %{public}d", info.GetPrinterState());
    PRINT_HILOGD("info_value description value is  %{public}s", info.GetDescription().c_str());
    return true;
}

bool NapiPrintExt::ParseInfoParam(napi_env env, napi_value InfoValue, PrintInfo &info)
{
    napi_value param_one = NapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTID);
    if (NapiUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = NapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERNAME);
    if (NapiUtils::GetValueType(env, param_two) != napi_string) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = NapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERICON);
    if (NapiUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = NapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERSTATE);
    if (NapiUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    napi_value param_five = NapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_DESCRIPTION);
    if (NapiUtils::GetValueType(env, param_five) != napi_number) {
        PRINT_HILOGD("error param_five");
        return false;
    }
    napi_value param_six = NapiUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_CAPABILITY);
    if (NapiUtils::GetValueType(env, param_six) != napi_object) {
        PRINT_HILOGD("error param_six");
        return false;
    }
    auto names = NapiUtils::GetPropertyNames(env, InfoValue);

    std::vector<std::string>::iterator iter;
    PRINT_HILOGD("current name list size = %{public}zu", names.size());
    for (iter = names.begin(); iter != names.end(); ++iter) {
        uint32_t value = NapiUtils::GetUint32Property(env, param_one, *iter);
        if (value) {
            info.SetPrinterId(value);
        }
    }
    return true;
}

bool NapiPrintExt::ParseCapability(napi_env env, napi_value CapValue, PrinterCapability &capability)
{
    return true;
}
} // namespace OHOS::Print
