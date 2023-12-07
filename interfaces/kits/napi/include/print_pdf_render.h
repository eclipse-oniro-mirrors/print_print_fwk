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

#ifndef PRINT_PDF_RENDER_H
#define PRINT_PDF_RENDER_H

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "print_async_call.h"
#ifdef PDFIUM_ENABLE
#include "fpdfview.h"
#endif // PDFIUM_ENABLE

namespace OHOS::Print {
class PrintPdfRender {
public:
    explicit PrintPdfRender(const std::string file);
    ~PrintPdfRender();

    int32_t Init(const std::string sandBoxPath);
    static napi_value Destroy(napi_env env, napi_callback_info info);
    static napi_value GetPageCount(napi_env env, napi_callback_info info);
    static napi_value GetPageSize(napi_env env, napi_callback_info info);
    static napi_value RenderPageToPng(napi_env env, napi_callback_info info);

private:
    struct PrintPdfRenderEventContext : public PrintAsyncCall::Context {
        std::string imagePath = "";
        std::string basePngName = "";
        int32_t pageIndex = 0;
#ifdef PDFIUM_ENABLE
        FPDF_DOCUMENT doc_ = nullptr;
#endif // PDFIUM_ENABLE
        PrintPdfRenderEventContext() : Context(nullptr, nullptr) {};
        PrintPdfRenderEventContext(InputAction input, OutputAction output)
            : Context(std::move(input), std::move(output)) {};
        virtual ~PrintPdfRenderEventContext() {};
    };

    std::string file_;
    int32_t pageCount = 0;
    std::string basePngName = "";
#ifdef PDFIUM_ENABLE
    FPDF_DOCUMENT doc_ = nullptr;
#endif // PDFIUM_ENABLE
};
} // namespace OHOS::Print
#endif // _PRINT_PDF_RENDER_H
