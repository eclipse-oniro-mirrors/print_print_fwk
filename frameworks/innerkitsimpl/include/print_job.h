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

#ifndef PRINT_PRINT_JOB_H
#define PRINT_PRINT_JOB_H
#define TDD_ENABLE 1

#include <map>

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "napi/native_api.h"
#include "parcel.h"
#include "print_margin.h"
#include "print_page_size.h"
#include "print_preview_attribute.h"
#include "print_range.h"

namespace OHOS::Print {
class PrintJob final : public Parcelable {
public:
    explicit PrintJob();

    PrintJob(const PrintJob &right);

    PrintJob &operator=(const PrintJob &right);

    virtual ~PrintJob();

    void SetFdList(const std::vector<uint32_t> &files);

    void SetJobId(const std::string &jobId);

    void SetPrinterId(const std::string &printerid);

    void SetJobState(uint32_t jobState);

    void SetSubState(uint32_t jobSubState);

    void SetCopyNumber(uint32_t copyNumber);

    void SetPageRange(const PrintRange &pageRange);

    void SetIsSequential(bool isSequential);

    void SetPageSize(const PrintPageSize &pageSize);

    void SetIsLandscape(bool isLandscape);

    void SetColorMode(uint32_t colorMode);

    void SetDuplexMode(uint32_t duplexmode);

    void SetMargin(const PrintMargin &margin);

    void SetOption(const std::string &option);

    void SetPreview(const PrintPreviewAttribute &preview);

    void UpdateParams(const PrintJob& jobInfo);

    void GetFdList(std::vector<uint32_t> &fdList) const;

    [[nodiscard]] const std::string &GetJobId() const;

    [[nodiscard]] const std::string &GetPrinterId() const;

    [[nodiscard]] uint32_t GetJobState() const;

    [[nodiscard]] uint32_t GetSubState() const;

    [[nodiscard]] uint32_t GetCopyNumber() const;

    void GetPageRange(PrintRange &range) const;

    [[nodiscard]] bool GetIsSequential() const;

    void GetPageSize(PrintPageSize &printPageSize) const;

    [[nodiscard]] bool GetIsLandscape() const;

    [[nodiscard]] uint32_t GetColorMode() const;

    [[nodiscard]] uint32_t GetDuplexMode() const;

    void GetMargin(PrintMargin &printMargin) const;

    void GetPreview(PrintPreviewAttribute &previewAttr) const;

    [[nodiscard]] const std::string &GetOption() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    virtual bool MarshallingParam(Parcel &parcel) const;

    static std::shared_ptr<PrintJob> Unmarshalling(Parcel &parcel);

    napi_value ToJsObject(napi_env env) const;

    static std::shared_ptr<PrintJob> BuildFromJs(napi_env env, napi_value jsValue);

    static std::shared_ptr<PrintJob> BuildJsWorkerIsLegal(napi_env env, napi_value jsValue, std::string jobId,
        uint32_t jobState, uint32_t subState, std::shared_ptr<PrintJob> &nativeObj);

    void Dump();

#ifndef TDD_ENABLE
private:
#endif
    bool ReadFromParcel(Parcel &parcel);
    bool CreateFdList(napi_env env, napi_value &jsPrintJob) const;
    bool CreatePageRange(napi_env env, napi_value &jsPrintJob) const;
    bool CreatePageSize(napi_env env, napi_value &jsPrintJob) const;
    bool CreateMargin(napi_env env, napi_value &jsPrintJob) const;
    bool CreatePreview(napi_env env, napi_value &jsPrintJob) const;

    static bool ValidateProperty(napi_env env, napi_value object);
    void ReadParcelFD(Parcel &parcel);

#ifndef TDD_ENABLE
private:
#endif
    std::vector<uint32_t> fdList_;
    std::string jobId_;
    std::string printerId_;
    uint32_t jobState_;
    uint32_t subState_;
    uint32_t copyNumber_;
    PrintRange pageRange_;
    bool isSequential_;
    PrintPageSize pageSize_;
    bool isLandscape_;
    uint32_t colorMode_;
    uint32_t duplexMode_;
    bool hasMargin_;
    PrintMargin margin_;
    bool hasPreview_;
    PrintPreviewAttribute preview_;
    bool hasOption_;
    std::string option_;
};
} // namespace OHOS::Print
#endif /* PRINT_PRINT_JOB_H */
