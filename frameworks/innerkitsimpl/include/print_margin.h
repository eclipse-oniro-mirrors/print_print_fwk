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

#ifndef PRINT_MARGIN_H
#define PRINT_MARGIN_H
#define TDD_ENABLE 1

#include "napi/native_api.h"
#include "parcel.h"

namespace OHOS::Print {
class PrintMargin final : public Parcelable {
public:
    explicit PrintMargin();

    PrintMargin(const PrintMargin &right);

    PrintMargin &operator=(const PrintMargin &right);

    virtual ~PrintMargin();

    void Reset();

    [[nodiscard]] uint32_t GetTop() const;

    [[nodiscard]] uint32_t GetBottom() const;

    [[nodiscard]] uint32_t GetLeft() const;

    [[nodiscard]] uint32_t GetRight() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrintMargin> Unmarshalling(Parcel &parcel);

    napi_value ToJsObject(napi_env env) const;

    static std::shared_ptr<PrintMargin> BuildFromJs(napi_env env, napi_value jsValue);

    void Dump();

#ifndef TDD_ENABLE
private:
#endif
    void SetTop(uint32_t top);

    void SetBottom(uint32_t bottom);

    void SetLeft(uint32_t left);

    void SetRight(uint32_t right);

    bool ReadFromParcel(Parcel &parcel);

    static bool ValidateProperty(napi_env env, napi_value object);

#ifndef TDD_ENABLE
private:
#endif
    bool hasTop_;
    uint32_t top_;

    bool hasBottom_;
    uint32_t bottom_;

    bool hasLeft_;
    uint32_t left_;

    bool hasRight_;
    uint32_t right_;
};
} // namespace OHOS::Print
#endif // PRINT_MARGIN_H