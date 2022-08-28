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

#include "napi_inner_print.h"
#include "print_manager.h"
#include "async_call.h"
#include "log.h"
#include "napi_utils.h"
#include "print_task.h"

namespace OHOS::Print {
napi_value NapiInnerPrint::QueryExtensionInfo(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == NapiUtils::NO_ARG, " should 0 parameter!", napi_invalid_arg);
        PRINT_HILOGD("input over---->");
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        napi_status status = napi_create_array(env, result);
        uint32_t PrinterExtensionInfoLength = context->arrayPrinterExtensionInfo.size();
        for(uint32_t i = 0; i < PrinterExtensionInfoLength; i++)
        {
        PRINT_HILOGD("PrintServiceProxy, ExtensionId = %{public}d", context->arrayPrinterExtensionInfo[i].GetExtensionId());
        PRINT_HILOGD("PrintServiceProxy, VendorId = %{public}d", context->arrayPrinterExtensionInfo[i].GetVendorId());
        PRINT_HILOGD("PrintServiceProxy, VendorName = %{public}s", context->arrayPrinterExtensionInfo[i].GetVendorName().c_str());
        PRINT_HILOGD("PrintServiceProxy, VendorIcon = %{public}d", context->arrayPrinterExtensionInfo[i].GetVendorIcon());
        PRINT_HILOGD("PrintServiceProxy, Version = %{public}s", context->arrayPrinterExtensionInfo[i].GetVersion().c_str());
        napi_value PrinterInfo;
        napi_create_object(env, &PrinterInfo);
        NapiUtils::SetUint32Property(env, PrinterInfo, "extensionId", context->arrayPrinterExtensionInfo[i].GetExtensionId());
        NapiUtils::SetUint32Property(env, PrinterInfo, "vendorId", context->arrayPrinterExtensionInfo[i].GetVendorId());
        NapiUtils::SetStringPropertyUtf8(env, PrinterInfo, "vendorName", context->arrayPrinterExtensionInfo[i].GetVendorName().c_str());
        NapiUtils::SetUint32Property(env, PrinterInfo, "vendorIcon", context->arrayPrinterExtensionInfo[i].GetVendorIcon());
        NapiUtils::SetStringPropertyUtf8(env, PrinterInfo, "version", context->arrayPrinterExtensionInfo[i].GetVersion().c_str());
        status = napi_set_element(env, *result, i, PrinterInfo);
        }   
        PRINT_HILOGD("output ---- status[%{public}d]", status);
        PRINT_HILOGD("ouput over---->");
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        PRINT_HILOGD("exec enter---->");
        context->result = PrintManager::GetInstance()->QueryAllExtension(context->arrayPrinterExtensionInfo);
        if (context->result == true) {
            PRINT_HILOGD("exec over---->");
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StartDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StartDiscovery---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        uint32_t result_size = 0;
        napi_get_array_length(env, argv[NapiUtils::FIRST_ARGV], &result_size);
        napi_value array = argv[NapiUtils::FIRST_ARGV];
        bool isArray = false;
        napi_is_array(env, array, &isArray);
        NAPI_ASSERT_BASE(env, isArray, " is not array!", napi_invalid_arg);
        for (uint32_t i = 0; i < result_size; i++)
        {
            napi_value value;
            napi_get_element(env, array, i, &value);
            uint32_t valueNumber;
            napi_get_value_uint32(env, value, &valueNumber);
            PRINT_HILOGD("output for :---- extensionVector value is :[%{public}d]", valueNumber);
            context->extensionVector.push_back((int32_t)valueNumber);
        }   
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->extensionList.push_back(5);
        context->extensionList.push_back(55);
        context->extensionList.push_back(555);
        context->extensionList.push_back(5555);
        context->result = PrintManager::GetInstance()->StartDiscoverPrinter(context->extensionList);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StopDiscovery(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StopDiscovery---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 0, " should 0 parameter!", napi_invalid_arg);
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManager::GetInstance()->StopDiscoverPrinter();
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
    return nullptr;
}

napi_value NapiInnerPrint::ConnectPrint(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ConnectPrint---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, "should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerId number is not a number", napi_invalid_arg);
        uint32_t printId;
        napi_get_value_uint32(env, argv[NapiUtils::FIRST_ARGV], &printId);
        PRINT_HILOGD("printId : %{public}d",printId);
        context->printConnId = printId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManager::GetInstance()->ConnectPrinter(context->printConnId);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::DisconnectPrint(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter DisconnectPrint---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerId number is not a number", napi_invalid_arg);
        uint32_t printId;
        napi_get_value_uint32(env,argv[NapiUtils::FIRST_ARGV],&printId);
        PRINT_HILOGD("printId : %{public}d",printId);
        context->printDisConnId = printId;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManager::GetInstance()->DisconnectPrinter(context->printDisConnId);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
    return nullptr;
}

napi_value NapiInnerPrint::StartPrint(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StartPrint---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_object, "printjob number is not a number", napi_invalid_arg);
        uint32_t printjobObject;
        napi_get_value_uint32(env,argv[NapiUtils::FIRST_ARGV],&printjobObject);
        PRINT_HILOGD("printjob : %{public}d",printjobObject);
        context->printStartJobNumber = printjobObject;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        uint32_t fileLength = 3;
        for(uint32_t i = 0; i < fileLength; i++)
        {
            context->jobinfo.GetFiles().push_back("JobInfo");
        }
        context->jobinfo.SetJobId(9);
        context->jobinfo.SetPrintId(99);
        context->jobinfo.SetJobState(5);
        context->jobinfo.SetCopyNumber(9);
        context->jobinfo.GetPageRange().SetStartPage(6);
        context->jobinfo.GetPageRange().SetEndPage(7);
        context->jobinfo.GetPageRange().SetPages(6);
        context->jobinfo.GetPageRange().SetPages(66);
        context->jobinfo.SetIsSequential(6);
        context->jobinfo.GetPageSize().SetId(6);
        context->jobinfo.GetPageSize().SetName("jobinfo.GetPageSize");
        context->jobinfo.GetPageSize().SetWidth(6);
        context->jobinfo.GetPageSize().SetHeight(6);
        context->jobinfo.SetIsLandscape(6);
        context->jobinfo.SetColorMode(6);
        context->jobinfo.SetDuplexMode(6);
        context->jobinfo.GetMargin().SetTop(6);
        context->jobinfo.GetMargin().SetBottom(6);
        context->jobinfo.GetMargin().SetLeft(6);
        context->jobinfo.GetMargin().SetRight(6);
        context->jobinfo.GetPreview().SetResult("data.ReadString()");
        context->jobinfo.GetPreview().GetPreviewRange().SetStartPage(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetEndPage(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetPages(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetPages(66);
        context->result = PrintManager::GetInstance()->StartPrintJob(context->jobinfo);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::CancelPrint(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_object, "printjob number is not a object", napi_invalid_arg);
        uint32_t printjobObject;
        napi_get_value_uint32(env,argv[NapiUtils::FIRST_ARGV],&printjobObject);
        PRINT_HILOGD("printjob : %{public}d",printjobObject);
        context->printCancelJobNumber = printjobObject;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        uint32_t fileLength = 3;
        for(uint32_t i = 0; i < fileLength; i++)
        {
            context->jobinfo.GetFiles().push_back("JobInfo");
        }
        context->jobinfo.SetJobId(9);
        context->jobinfo.SetPrintId(99);
        context->jobinfo.SetJobState(5);
        context->jobinfo.SetCopyNumber(9);
        context->jobinfo.GetPageRange().SetStartPage(6);
        context->jobinfo.GetPageRange().SetEndPage(7);
        context->jobinfo.GetPageRange().SetPages(6);
        context->jobinfo.GetPageRange().SetPages(66);
        context->jobinfo.SetIsSequential(6);
        context->jobinfo.GetPageSize().SetId(6);
        context->jobinfo.GetPageSize().SetName("jobinfo.GetPageSize");
        context->jobinfo.GetPageSize().SetWidth(6);
        context->jobinfo.GetPageSize().SetHeight(6);
        context->jobinfo.SetIsLandscape(6);
        context->jobinfo.SetColorMode(6);
        context->jobinfo.SetDuplexMode(6);
        context->jobinfo.GetMargin().SetTop(6);
        context->jobinfo.GetMargin().SetBottom(6);
        context->jobinfo.GetMargin().SetLeft(6);
        context->jobinfo.GetMargin().SetRight(6);
        context->jobinfo.GetPreview().SetResult("data.ReadString()");
        context->jobinfo.GetPreview().GetPreviewRange().SetStartPage(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetEndPage(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetPages(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetPages(66);
        context->result = PrintManager::GetInstance()->CancelPrintJob(context->jobinfo);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context), 0);
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::RequestPreview(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_object, "printjob number is not a object", napi_invalid_arg);
        uint32_t printjobObject;
        napi_get_value_uint32(env,argv[NapiUtils::FIRST_ARGV],&printjobObject);
        PRINT_HILOGD("printjob : %{public}d",printjobObject);
        context->printReqPreviewJobNumber = printjobObject;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_string_utf8(env, context->previewResult.c_str(), NAPI_AUTO_LENGTH, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        uint32_t fileLength = 3;
        for(uint32_t i = 0; i < fileLength; i++)
        {
            context->jobinfo.GetFiles().push_back("JobInfo");
        }
        context->jobinfo.SetJobId(9);
        context->jobinfo.SetPrintId(99);
        context->jobinfo.SetJobState(5);
        context->jobinfo.SetCopyNumber(9);
        context->jobinfo.GetPageRange().SetStartPage(6);
        context->jobinfo.GetPageRange().SetEndPage(7);
        context->jobinfo.GetPageRange().SetPages(6);
        context->jobinfo.GetPageRange().SetPages(66);
        context->jobinfo.SetIsSequential(6);
        context->jobinfo.GetPageSize().SetId(6);
        context->jobinfo.GetPageSize().SetName("jobinfo.GetPageSize");
        context->jobinfo.GetPageSize().SetWidth(6);
        context->jobinfo.GetPageSize().SetHeight(6);
        context->jobinfo.SetIsLandscape(6);
        context->jobinfo.SetColorMode(6);
        context->jobinfo.SetDuplexMode(6);
        context->jobinfo.GetMargin().SetTop(6);
        context->jobinfo.GetMargin().SetBottom(6);
        context->jobinfo.GetMargin().SetLeft(6);
        context->jobinfo.GetMargin().SetRight(6);
        context->jobinfo.GetPreview().SetResult("data.ReadString()");
        context->jobinfo.GetPreview().GetPreviewRange().SetStartPage(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetEndPage(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetPages(6);
        context->jobinfo.GetPreview().GetPreviewRange().SetPages(66);
        context->result = PrintManager::GetInstance()->RequestPreview(context->jobinfo, context->previewResult);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::QueryCapability(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter QueryCapability---->");
    if (!PrintManager::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[NapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "number is not a number", napi_invalid_arg);
        uint32_t number;
        napi_get_value_uint32(env,argv[NapiUtils::FIRST_ARGV],&number);
        PRINT_HILOGD("printjob : %{public}d",number);
        context->printCapacityId = number;
        PRINT_HILOGD("input over---->");
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        PRINT_HILOGD("ouput enter---->");
        napi_value resultPrintMargin;
        napi_create_object(env, result);
        napi_create_object(env, &resultPrintMargin);
        napi_value arrPageSize,arrResolution;
        napi_status status = napi_create_array(env, &arrPageSize);
        status = napi_create_array(env, &arrResolution);

        NapiUtils::SetUint32Property(env, *result, "colorMode", context->printerCapability.GetColorMode());
        NapiUtils::SetUint32Property(env, *result, "duplexMode", context->printerCapability.GetDuplexMode());
        
        NapiUtils::SetUint32Property(env, resultPrintMargin, "top", context->printerCapability.GetMinMargin().GetTop());
        NapiUtils::SetUint32Property(env, resultPrintMargin, "bottom", context->printerCapability.GetMinMargin().GetBottom());
        NapiUtils::SetUint32Property(env, resultPrintMargin, "left", context->printerCapability.GetMinMargin().GetLeft());
        NapiUtils::SetUint32Property(env, resultPrintMargin, "right", context->printerCapability.GetMinMargin().GetRight());
        uint32_t printerCapabilityLength = context->printerCapability.GetPageSize().size();

        for(uint32_t i = 0; i < printerCapabilityLength; i++)
        {
            napi_value resultPrinterPageSize;
            napi_create_object(env, &resultPrinterPageSize);
            NapiUtils::SetUint32Property(env, resultPrinterPageSize, "id", context->printerCapability.GetPageSize()[i].GetId());
            NapiUtils::SetStringPropertyUtf8(env, resultPrinterPageSize, "name", context->printerCapability.GetPageSize()[i].GetName().c_str());
            NapiUtils::SetUint32Property(env, resultPrinterPageSize, "width", context->printerCapability.GetPageSize()[i].GetWidth());
            NapiUtils::SetUint32Property(env, resultPrinterPageSize, "height", context->printerCapability.GetPageSize()[i].GetHeight());
            status = napi_set_element(env, arrPageSize, i, resultPrinterPageSize);
        }

        uint32_t printerCapabilityresolutionLength = context->printerCapability.GetResolution().size();

        for(uint32_t i = 0; i < printerCapabilityresolutionLength; i++)
        {
            napi_value resultPrinterResolution;
            napi_create_object(env, &resultPrinterResolution);
            NapiUtils::SetUint32Property(env, resultPrinterResolution, "id", context->printerCapability.GetResolution()[i].GetId());
            NapiUtils::SetUint32Property(env, resultPrinterResolution, "horizontalDpi", context->printerCapability.GetResolution()[i].GetHorizontalDpi());
            NapiUtils::SetUint32Property(env, resultPrinterResolution, "verticalDpi", context->printerCapability.GetResolution()[i].GetVerticalDpi());
            status = napi_set_element(env, arrResolution, i, resultPrinterResolution);
        }  
        
        status = napi_set_named_property(env, *result, "minMargin", resultPrintMargin);     
        PRINT_HILOGD("output ---- status[%{public}d]", status);
        napi_set_named_property(env, *result, "pageSize", arrPageSize);
        napi_set_named_property(env, *result, "resolution", arrResolution);
        PRINT_HILOGD("ouput over---->");
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManager::GetInstance()->QueryPrinterCapability(5, context->printerCapability);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::On(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter On---->");
    return nullptr;
}

napi_value NapiInnerPrint::Off(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter Off---->");
    return nullptr;
}
} // namespace OHOS::Print


