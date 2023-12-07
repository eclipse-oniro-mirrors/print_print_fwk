/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Import print_pdf_render class object will be called
#include <mutex>
#include "napi_base_context.h"
#include "napi_print_utils.h"
#include "print_async_call.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "print_pdf_render.h"
#include "napi_print_pdf_render.h"

// Set the application layer interface function name
static constexpr const char *FUNCTION_GET_PAGE_COUNT = "getPageCount";
static constexpr const char *FUNCTION_GET_PAGE_SIZE = "getPageSize";
static constexpr const char *FUNCTION_RENDER_PAGE_TO_PNG = "renderPageToPng";
static constexpr const char *FUNCTION_DESTROY = "destroy";

namespace OHOS::Print {
__thread napi_ref NapiPrintPdfRender::globalCtor = nullptr;
std::mutex g_printPdfRenderMutex;

napi_value NapiPrintPdfRender::CreatePdfRender(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("NapiPrintPdfRender::CreatePdfRender Enter------------>");
    if (VerifyParameters(env, info) != napi_ok) {
        PRINT_HILOGE("CreatePdfRender Failed to VerifyParameters");
        return nullptr;
    }
    auto context = std::make_shared<PrintPdfRenderContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> napi_status {
        PRINT_ASSERT_BASE(env, argc == NapiPrintUtils::ARGC_TWO,
            "NapiPrintPdfRender::CreatePdfRender need 2 parameter!", napi_invalid_arg);
        std::string file = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
        std::string sandBoxPath = NapiPrintUtils::GetStringFromValueUtf8(env, argv[1]);
        if (!IsPdfFile(file)) {
            context->SetErrorIndex(E_PRINT_GENERIC_FAILURE);
            return napi_generic_failure;
        }
        napi_value proxy = nullptr;
        napi_status status = napi_new_instance(env, GetCtor(env), argc, argv, &proxy);
        if ((proxy == nullptr) || (status != napi_ok)) {
            PRINT_HILOGE("Failed to create PdfRender");
            context->SetErrorIndex(E_PRINT_GENERIC_FAILURE);
            return napi_generic_failure;
        }
        PrintPdfRender *render = nullptr;
        PRINT_CALL_BASE(env, napi_unwrap(env, proxy, reinterpret_cast<void **>(&render)), napi_invalid_arg);
        int32_t ret = E_PRINT_GENERIC_FAILURE;
        if (render != nullptr) {
            ret = render->Init(sandBoxPath);
        }
        if (ret != E_PRINT_NONE) {
            PRINT_HILOGE("Failed to init PdfRender");
            context->SetErrorIndex(ret);
            return napi_generic_failure;
        }
        napi_create_reference(env, proxy, 1, &(context->ref));
        return napi_ok;
    };
    auto output = [context](napi_env env, napi_value *result) -> napi_status {
        if (context->ref == nullptr) {
            *result = NapiPrintUtils::GetUndefined(env);
            return napi_generic_failure;
        }
        napi_status status = napi_get_reference_value(env, context->ref, result);
        napi_delete_reference(env, context->ref);
        return status;
    };
    context->SetAction(std::move(input), std::move(output));
    PrintAsyncCall asyncCall(env, info, std::dynamic_pointer_cast<PrintAsyncCall::Context>(context));
    return asyncCall.Call(env);
}

napi_status NapiPrintPdfRender::VerifyParameters(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("VerifyParameters start!");
    napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
    size_t paramCount = NapiPrintUtils::GetJsVal(env, info, argv, NapiPrintUtils::MAX_ARGC);
    PRINT_ASSERT_BASE(env, paramCount == NapiPrintUtils::ARGC_TWO, "CreatePdfRender need 2 parameter!",
        napi_invalid_arg);
    napi_valuetype type;
    PRINT_CALL_BASE(env, napi_typeof(env, argv[0], &type), napi_invalid_arg);
    PRINT_ASSERT_BASE(env, type == napi_string, "index not a string", napi_invalid_arg);
    PRINT_CALL_BASE(env, napi_typeof(env, argv[1], &type), napi_invalid_arg);
    PRINT_ASSERT_BASE(env, type == napi_string, "index not a string", napi_invalid_arg);
    PRINT_HILOGD("Succeed to VerifyParameters");
    return napi_ok;
}

napi_value NapiPrintPdfRender::GetCtor(napi_env env)
{
    std::lock_guard<std::mutex> lock(g_printPdfRenderMutex);
    napi_value cons;
    if (globalCtor != nullptr) {
        PRINT_CALL(env, napi_get_reference_value(env, globalCtor, &cons));
        return cons;
    }

    napi_property_descriptor clzDes[] = {
        { FUNCTION_GET_PAGE_COUNT, 0, PrintPdfRender::GetPageCount, 0, 0, 0, napi_default, 0 },
        { FUNCTION_GET_PAGE_SIZE, 0, PrintPdfRender::GetPageSize, 0, 0, 0, napi_default, 0 },
        { FUNCTION_RENDER_PAGE_TO_PNG, 0, PrintPdfRender::RenderPageToPng, 0, 0, 0, napi_default, 0 },
        { FUNCTION_DESTROY, 0, PrintPdfRender::Destroy, 0, 0, 0, napi_default, 0 },
    };
    PRINT_CALL(env, napi_define_class(env, "NapiPrintPdfRender", NAPI_AUTO_LENGTH, Initialize, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    PRINT_CALL(env, napi_create_reference(env, cons, 1, &globalCtor));
    return cons;
}

napi_value NapiPrintPdfRender::Initialize(napi_env env, napi_callback_info info)
{
    PRINT_HILOGD("constructor print pdfRender!");
    napi_value self = nullptr;
    size_t argc = NapiPrintUtils::MAX_ARGC;
    napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
    PRINT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));
    std::string file = NapiPrintUtils::GetStringFromValueUtf8(env, argv[0]);
    auto render = new (std::nothrow) PrintPdfRender(file);
    if (render == nullptr) {
        PRINT_HILOGE("print render fail");
        return nullptr;
    }
    auto finalize = [](napi_env env, void *data, void *hint) {
        PRINT_HILOGD("destructed print render");
        PrintPdfRender *render = reinterpret_cast<PrintPdfRender *>(data);
        delete render;
    };
    if (napi_wrap(env, self, render, finalize, nullptr, nullptr) != napi_ok) {
        finalize(env, render, nullptr);
        return nullptr;
    }
    PRINT_HILOGD("Succeed to allocate print render");
    return self;
}

bool NapiPrintPdfRender::IsPdfFile(const std::string fileName)
{
    PRINT_HILOGD("fileName: %{public}s", fileName.c_str());
    if (fileName == "") {
        PRINT_HILOGE("This file is null");
        return false;
    }
    char realPdfPath[PATH_MAX] = {};
    if (realpath(fileName.c_str(), realPdfPath) == nullptr) {
        PRINT_HILOGE("The realPdfPath is null.");
        return false;
    }
    auto file = fopen(realPdfPath, "rb");
    if (file != nullptr) {
        fclose(file);
        if (fileName.find(".pdf") == fileName.npos) {
            PRINT_HILOGE("This file is exist but isn't pdf");
            return false;
        }
        return true;
    }
    PRINT_HILOGE("This file can't open");
    return false;
}
} // namespace OHOS::Print
