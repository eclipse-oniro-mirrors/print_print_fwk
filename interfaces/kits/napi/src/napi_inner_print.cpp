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
#include "print_manager_client.h"
#include "async_call.h"
#include "print_log.h"
#include "print_napi_utils.h"
#include "print_task.h"

static constexpr const char *PARAM_JOB_FILES = "files";
static constexpr const char *PARAM_JOB_JOBID = "jobId";
static constexpr const char *PARAM_JOB_PRINTERID = "printerId";
static constexpr const char *PARAM_JOB_JOBSTATE = "jobState";
static constexpr const char *PARAM_JOB_COPYNUMBER = "copyNumber";
//static constexpr const char *PARAM_JOB_PAGERANGE = "pageRange";

namespace OHOS::Print {
napi_value NapiInnerPrint::QueryExtensionInfo(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ---->");
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == PrintNapiUtils::NO_ARG, " should 0 parameter!", napi_invalid_arg);
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
        PrintNapiUtils::SetUint32Property(env, PrinterInfo, "extensionId", context->arrayPrinterExtensionInfo[i].GetExtensionId());
        PrintNapiUtils::SetUint32Property(env, PrinterInfo, "vendorId", context->arrayPrinterExtensionInfo[i].GetVendorId());
        PrintNapiUtils::SetStringPropertyUtf8(env, PrinterInfo, "vendorName", context->arrayPrinterExtensionInfo[i].GetVendorName().c_str());
        PrintNapiUtils::SetUint32Property(env, PrinterInfo, "vendorIcon", context->arrayPrinterExtensionInfo[i].GetVendorIcon());
        PrintNapiUtils::SetStringPropertyUtf8(env, PrinterInfo, "version", context->arrayPrinterExtensionInfo[i].GetVersion().c_str());
        status = napi_set_element(env, *result, i, PrinterInfo);
        }   
        PRINT_HILOGD("output ---- status[%{public}d]", status);
        PRINT_HILOGD("ouput over---->");
        return napi_ok;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        PRINT_HILOGD("exec enter---->");
        context->result = PrintManagerClient::GetInstance()->QueryAllExtension(context->arrayPrinterExtensionInfo);
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
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }

    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        uint32_t result_size = 0;
        napi_get_array_length(env, argv[PrintNapiUtils::FIRST_ARGV], &result_size);
        napi_value array = argv[PrintNapiUtils::FIRST_ARGV];
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
        /*context->extensionList.push_back(5);
        context->extensionList.push_back(55);
        context->extensionList.push_back(555);
        context->extensionList.push_back(5555);*/
        context->result = PrintManagerClient::GetInstance()->StartDiscoverPrinter(context->extensionVector);
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
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
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
        context->result = PrintManagerClient::GetInstance()->StopDiscoverPrinter();
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::ConnectPrint(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter ConnectPrint---->");
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, "should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerId number is not a number", napi_invalid_arg);
        uint32_t printId;
        napi_get_value_uint32(env, argv[PrintNapiUtils::FIRST_ARGV], &printId);
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
        context->result = PrintManagerClient::GetInstance()->ConnectPrinter(context->printConnId);
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
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "printerId number is not a number", napi_invalid_arg);
        uint32_t printId;
        napi_get_value_uint32(env,argv[PrintNapiUtils::FIRST_ARGV],&printId);
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
        context->result = PrintManagerClient::GetInstance()->DisconnectPrinter(context->printDisConnId);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

napi_value NapiInnerPrint::StartPrint(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter StartPrint---->");
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_value value = argv[PrintNapiUtils::FIRST_ARGV];
        PrintJob printJob;
        if (!ParseJob(env, value, printJob) ){
            PRINT_HILOGD("PrintResolution type error!");
        } 
        context->printStartJob = printJob;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        PrintRange range;
        range.SetStartPage(1);
        range.SetEndPage(2);
        context->printStartJob.SetPageRange(range);
        context->result = PrintManagerClient::GetInstance()->StartPrintJob(context->printStartJob);
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
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_value value = argv[PrintNapiUtils::FIRST_ARGV];
        PrintJob printJob;
        if (!ParseJob(env, value, printJob) ){
            PRINT_HILOGD("PrintResolution type error!");
        } 
        context->printCancelJob = printJob;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        PrintRange range;
        range.SetStartPage(1);
        range.SetEndPage(2);
        context->printCancelJob.SetPageRange(range);
        context->result = PrintManagerClient::GetInstance()->CancelPrintJob(context->printCancelJob);
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
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_value value = argv[PrintNapiUtils::FIRST_ARGV];
        PrintJob printJob;
        if (!ParseJob(env, value, printJob) ){
            PRINT_HILOGD("PrintResolution type error!");
        } 
        context->printReqPreviewJob = printJob;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_create_string_utf8(env, context->previewResult.c_str(), NAPI_AUTO_LENGTH, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        PrintRange range;
        range.SetStartPage(1);
        range.SetEndPage(2);
        context->printReqPreviewJob.SetPageRange(range);
        context->result = PrintManagerClient::GetInstance()->RequestPreview(context->printReqPreviewJob, context->previewResult);
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
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
        PRINT_HILOGD("no permission to access print service");
        return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == 1, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_number, "number is not a number", napi_invalid_arg);
        uint32_t number;
        napi_get_value_uint32(env,argv[PrintNapiUtils::FIRST_ARGV],&number);
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

        PrintNapiUtils::SetUint32Property(env, *result, "colorMode", context->printerCapability.GetColorMode());
        PrintNapiUtils::SetUint32Property(env, *result, "duplexMode", context->printerCapability.GetDuplexMode());

        PrintMargin margin;
        context->printerCapability.GetMinMargin(margin);
        PrintNapiUtils::SetUint32Property(env, resultPrintMargin, "top", margin.GetTop());
        PrintNapiUtils::SetUint32Property(env, resultPrintMargin, "bottom", margin.GetBottom());
        PrintNapiUtils::SetUint32Property(env, resultPrintMargin, "left", margin.GetLeft());
        PrintNapiUtils::SetUint32Property(env, resultPrintMargin, "right", margin.GetRight());

        std::vector<PrintPageSize> pageSize;
        context->printerCapability.GetPageSize(pageSize);
        uint32_t printerCapabilityLength = pageSize.size();

        for(uint32_t i = 0; i < printerCapabilityLength; i++)
        {
            napi_value resultPrinterPageSize;
            napi_create_object(env, &resultPrinterPageSize);
            PrintNapiUtils::SetUint32Property(env, resultPrinterPageSize, "id", pageSize[i].GetId());
            PrintNapiUtils::SetStringPropertyUtf8(env, resultPrinterPageSize, "name", pageSize[i].GetName().c_str());
            PrintNapiUtils::SetUint32Property(env, resultPrinterPageSize, "width", pageSize[i].GetWidth());
            PrintNapiUtils::SetUint32Property(env, resultPrinterPageSize, "height", pageSize[i].GetHeight());
            status = napi_set_element(env, arrPageSize, i, resultPrinterPageSize);
        }

        std::vector<PrintResolution> resolutionList;
        context->printerCapability.GetResolution(resolutionList);

        uint32_t printerCapabilityresolutionLength = resolutionList.size();

        for(uint32_t i = 0; i < printerCapabilityresolutionLength; i++)
        {
            napi_value resultPrinterResolution;
            napi_create_object(env, &resultPrinterResolution);
            PrintNapiUtils::SetUint32Property(env, resultPrinterResolution, "id", resolutionList[i].GetId());
            PrintNapiUtils::SetUint32Property(env, resultPrinterResolution, "horizontalDpi", resolutionList[i].GetHorizontalDpi());
            PrintNapiUtils::SetUint32Property(env, resultPrinterResolution, "verticalDpi", resolutionList[i].GetVerticalDpi());
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
        context->result = PrintManagerClient::GetInstance()->QueryPrinterCapability(context->printCapacityId, context->printerCapability);//
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
    PRINT_HILOGD("Enter ---->");
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    napi_value result = nullptr;
    size_t argc = PrintNapiUtils::MAX_ARGC;
    napi_value argv[PrintNapiUtils::MAX_ARGC] = {nullptr};
    napi_value thisVal = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVal, &data));
    if (argc != PrintNapiUtils::ONE_ARG) {
        PRINT_HILOGE("Wrong number of arguments, requires 1");
        return result;
    }

    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype));
    NAPI_ASSERT(env, valuetype == napi_string, "type is not a string");
    char event[PrintNapiUtils::MAX_LEN] = {0};
    size_t len = 0;
    napi_get_value_string_utf8(env, argv[PrintNapiUtils::FIRST_ARGV], event, PrintNapiUtils::MAX_LEN, &len);
    std::string type = event;
    PRINT_HILOGD("type : %{public}s", type.c_str());


    PrintTask *task;
    PRINT_HILOGD("napi_unwrap begin.");
    NAPI_CALL(env, napi_unwrap(env, thisVal, reinterpret_cast<void **>(&task)));
    PRINT_HILOGD("state judge begin.");
    if(task->IsSupportPrinterStateType(type)){
        PRINT_HILOGD("State type is Printer State. value is : %{public}s",type.c_str());
    }else if(task->IsSupportJobStateType(type)){
        PRINT_HILOGD("State type is Print Job State. value is : %{public}s",type.c_str());
    }else{
        PRINT_HILOGD("state error!");
        return result;
    }
    PRINT_HILOGD("state judge end.");
    napi_ref callbackRef = nullptr;
    napi_create_reference(env, argv[argc - 1], 1, &callbackRef);
	
    // sptr<PrintNotifyInterface> listener = CreateNotify(env, type, callbackRef);
    // if (listener == nullptr) {
    //     PRINT_HILOGD("PrintPause create callback object fail");
    //     return result;
    // }
    // return result;
    return nullptr;
}

napi_value NapiInnerPrint::Off(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("Enter Off---->");
    if (!PrintManagerClient::GetInstance()->CheckPermission()) {
    PRINT_HILOGD("no permission to access print service");
    return nullptr;
    }
    
    auto context = std::make_shared<OperationContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        NAPI_ASSERT_BASE(env, argc == PrintNapiUtils::ONE_ARG, " should 1 parameter!", napi_invalid_arg);
        napi_valuetype valuetype;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[PrintNapiUtils::FIRST_ARGV], &valuetype), napi_invalid_arg);
        NAPI_ASSERT_BASE(env, valuetype == napi_string, "valuetype is not a number", napi_invalid_arg);
        char buf[PrintNapiUtils::MAX_LEN] = {};
        size_t len = 0;
        napi_get_value_string_utf8(env, argv[PrintNapiUtils::FIRST_ARGV], buf, PrintNapiUtils::MAX_LEN, &len);
        PRINT_HILOGD("printerId :");
        context->type = buf;
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        napi_status status = napi_get_boolean(env, context->result, result);
        PRINT_HILOGD("output ---- [%{public}s], status[%{public}d]", context->result ? "true" : "false", status);
        return status;
    };
    auto exec = [context](AsyncCall::Context *ctx) {
        context->result = PrintManagerClient::GetInstance()->Off(context->type);
        if (context->result == true) {
            context->status = napi_ok;
        }
    };
    context->SetAction(std::move(input), std::move(output));
    AsyncCall asyncCall(env, info, std::dynamic_pointer_cast<AsyncCall::Context>(context));
    return asyncCall.Call(env, exec);
}

int32_t NapiInnerPrint::GetEventType(const std::string &type)
{
    if (type == EVENT_SUCCESS) {
        return TWO_ARG_EVENT;
    } else if (type == EVENT_FAIL) {
        return ONE_ARG_EVENT;
    }
    return NO_ARG_EVENT;
}

sptr<PrintNotifyInterface> NapiInnerPrint::CreateNotify(napi_env env, const std::string &type, napi_ref callbackRef)
{
    sptr<PrintNotifyInterface> listener = nullptr;
    int32_t eventType = GetEventType(type);
    switch (eventType) {
        case NO_ARG_EVENT:
            //listener = new PrintBaseNotify(env, type, callbackRef);
            break;

        case ONE_ARG_EVENT:
            //listener = new PrintPrinterStateNotify(env, type, callbackRef);
            break;

        case TWO_ARG_EVENT:
            //listener = new PrintPrintJobNotify(env, type, callbackRef);
            break;

        default:
            PRINT_HILOGE("not support event type");
            break;
    }
    return listener;
}

bool NapiInnerPrint::ParseJob(napi_env env, napi_value jobValue, PrintJob &printJob)
{
    if (!ParseJobParam(env, jobValue, printJob)) {
        PRINT_HILOGD("ParseJobParam is error!");
        return false;
    }
    printJob.SetJobId(PrintNapiUtils::GetUint32Property(env, jobValue, PARAM_JOB_JOBID));
    printJob.SetPrintId(PrintNapiUtils::GetUint32Property(env, jobValue, PARAM_JOB_PRINTERID));
    printJob.SetJobState(PrintNapiUtils::GetUint32Property(env, jobValue, PARAM_JOB_JOBSTATE));
    printJob.SetCopyNumber(PrintNapiUtils::GetUint32Property(env, jobValue, PARAM_JOB_COPYNUMBER));
    //printJob.SetPageRange(PrintNapiUtils::GetUint32Property(env, jobValue, PARAM_JOB_PAGERANGE));

    PRINT_HILOGD("printJob_value GetJobId value is %{public}d", printJob.GetJobId());
    PRINT_HILOGD("printJob_value GetPrinterId value is %{public}d", printJob.GetPrinterId());
    PRINT_HILOGD("printJob_value GetJobState value is  %{public}d", printJob.GetJobState());
    PRINT_HILOGD("printJob_value GetCopyNumber value is %{public}d", printJob.GetCopyNumber());
    //PRINT_HILOGD("printJob_value GetPageRange value is  %{public}d", printJob.GetPageRange());
    return true;
}

bool NapiInnerPrint::ParseJobParam(napi_env env, napi_value jobValue, PrintJob &printJob)
{
    napi_value param_one = PrintNapiUtils::GetNamedProperty(env, jobValue, PARAM_JOB_FILES);
    bool isFileArray = false;
    napi_is_array(env, param_one, &isFileArray);
    if( !isFileArray ){
        PRINT_HILOGD("PrinterJobFile type error!");
        return false;
    }
    std::vector<std::string> printfiles;
    uint32_t arrayReLength = 0;
    napi_get_array_length(env, param_one, &arrayReLength);
    for(uint32_t i = 0; i < arrayReLength; i++)
    {
        napi_value filesValue;
        napi_get_element(env, param_one, i, &filesValue);
        std::string files = PrintNapiUtils::GetStringFromValueUtf8(env, filesValue);
        PRINT_HILOGD("printJob_value param_one %{public}s", files.c_str());
        printfiles.push_back(files);
    }

    napi_value param_two = PrintNapiUtils::GetNamedProperty(env, jobValue, PARAM_JOB_JOBID);
    if (PrintNapiUtils::GetValueType(env, param_two) != napi_number) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = PrintNapiUtils::GetNamedProperty(env, jobValue, PARAM_JOB_PRINTERID);
    if (PrintNapiUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = PrintNapiUtils::GetNamedProperty(env, jobValue, PARAM_JOB_JOBSTATE);
    if (PrintNapiUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    napi_value param_five = PrintNapiUtils::GetNamedProperty(env, jobValue, PARAM_JOB_COPYNUMBER);
    if (PrintNapiUtils::GetValueType(env, param_five) != napi_number) {
        PRINT_HILOGD("error param_five");
        return false;
    }
    // napi_value param_six = PrintNapiUtils::GetNamedProperty(env, jobValue, PARAM_JOB_PAGERANGE);
    // if (PrintNapiUtils::GetValueType(env, param_six) != napi_number) {
    //     PRINT_HILOGD("error param_six");
    //     return false;
    // }
    return true;
}
} // namespace OHOS::Print


