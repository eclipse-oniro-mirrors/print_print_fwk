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

#include "print_preview_attribute.h"
#include "message_parcel.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
PrintPreviewAttribute::PrintPreviewAttribute() : hasResult_(false), result_(PRINT_INVALID_ID) {
}

PrintPreviewAttribute::PrintPreviewAttribute(const PrintPreviewAttribute &right)
{
    hasResult_ = right.hasResult_;
    result_ = right.result_;
    previewRange_ = right.previewRange_;
}

PrintPreviewAttribute &PrintPreviewAttribute::operator=(const PrintPreviewAttribute &right)
{
    if (this != &right) {
        hasResult_ = right.hasResult_;
        result_ = right.result_;
        previewRange_ = right.previewRange_;
    }
    return *this;
}

PrintPreviewAttribute::~PrintPreviewAttribute()
{
}

void PrintPreviewAttribute::Reset()
{
    hasResult_ = false;
    result_ = PRINT_INVALID_ID;
    previewRange_.Reset();
}

void PrintPreviewAttribute::SetResult(uint32_t result)
{
    hasResult_ = true;
    result_ = result;
}

void PrintPreviewAttribute::SetPreviewRange(const PrintRange &previewRange)
{
    previewRange_ = previewRange;
}

bool PrintPreviewAttribute::HasResult() const
{
    return hasResult_;
}

uint32_t  PrintPreviewAttribute::GetResult() const
{
    return result_;
}

void PrintPreviewAttribute::GetPreviewRange(PrintRange &previewRange) const
{
    previewRange = previewRange_;
}

bool PrintPreviewAttribute::ReadFromParcel(Parcel &parcel)
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(hasResult_), false);
    auto msgParcel = static_cast<MessageParcel*>(&parcel);
    if (hasResult_ && msgParcel != nullptr) {
        SetResult(msgParcel->ReadFileDescriptor());
    }
    auto rangePtr = PrintRange::Unmarshalling(parcel);
    if (rangePtr != nullptr) {
        SetPreviewRange(*rangePtr);
    }
    return true;
}

bool PrintPreviewAttribute::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteBool(hasResult_), false);
    if (hasResult_) {
        auto msgParcel = static_cast<MessageParcel*>(&parcel);
        if (msgParcel == nullptr) {
            return false;
        }
        CHECK_PARCEL_OP_AND_RETURN_VAL(msgParcel->WriteFileDescriptor(GetResult()), false);
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(previewRange_.Marshalling(parcel), false);
    return true;
}

std::shared_ptr<PrintPreviewAttribute> PrintPreviewAttribute::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintPreviewAttribute>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return nativeObj;
}

void PrintPreviewAttribute::Dump()
{
    if (hasResult_) {
        PRINT_HILOGD("result_: %{public}d", result_);
    }
    previewRange_.Dump();
}

Json::Value PrintPreviewAttribute::ConvertToJsonObject() const
{
    Json::Value previewJson;
    previewJson["hasResult_"] = hasResult_;
    if (hasResult_) {
        previewJson["result_"] = result_;
    }
    previewJson["previewRange_"] = previewRange_.ConvertToJsonObject();
    return previewJson;
}
} // namespace OHOS::Print
