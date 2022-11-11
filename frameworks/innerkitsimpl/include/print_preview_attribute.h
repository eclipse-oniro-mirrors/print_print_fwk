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
#ifndef PRINT_PREVIEW_ATTRIBUTE_H
#define PRINT_PREVIEW_ATTRIBUTE_H

#include "napi/native_api.h"
#include "parcel.h"
#include "print_range.h"

namespace OHOS::Print {
class PrintPreviewAttribute final : public Parcelable {
public:
    explicit PrintPreviewAttribute();

    PrintPreviewAttribute(const PrintPreviewAttribute &right);

    PrintPreviewAttribute &operator=(const PrintPreviewAttribute &PrintPreviewAttribute);

    virtual ~PrintPreviewAttribute();

    void Reset();

    [[nodiscard]] const std::string &GetResult() const;

    void GetPreviewRange(PrintRange &previewRange) const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrintPreviewAttribute> Unmarshalling(Parcel &parcel);

    napi_value ToJsObject(napi_env env) const;

    static std::shared_ptr<PrintPreviewAttribute> BuildFromJs(napi_env env, napi_value jsValue);

    void Dump();

private:
    void SetResult(const std::string &result);

    void SetPreviewRange(const PrintRange &previewRange);

    bool ReadFromParcel(Parcel &parcel);

    static bool ValidateProperty(napi_env env, napi_value object);

private:
    std::string result_;
    PrintRange previewRange_;
};
} // namespace OHOS::Print
#endif // PRINT_PREVIEW_ATTRIBUTE_H