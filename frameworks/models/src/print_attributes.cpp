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

#include "print_attributes.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
PrintAttributes::PrintAttributes()
    : copyNumber_(0),
      isSequential_(false), isLandscape_(false), colorMode_(0), duplexMode_(0),
      hasMargin_(false), hasOption_(false), option_("") {
    margin_.Reset();
}

PrintAttributes::PrintAttributes(const PrintAttributes &right)
{
    copyNumber_ = right.copyNumber_;
    pageRange_ = right.pageRange_;
    isSequential_ = right.isSequential_;
    pageSize_ = right.pageSize_;
    isLandscape_ = right.isLandscape_;
    colorMode_ = right.colorMode_;
    duplexMode_ = right.duplexMode_;
    hasMargin_ = right.hasMargin_;
    margin_ = right.margin_;
    hasOption_ = right.hasOption_;
    option_ = right.option_;
}

PrintAttributes &PrintAttributes::operator=(const PrintAttributes &right)
{
    if (this != &right) {
        copyNumber_ = right.copyNumber_;
        pageRange_ = right.pageRange_;
        isSequential_ = right.isSequential_;
        pageSize_ = right.pageSize_;
        isLandscape_ = right.isLandscape_;
        colorMode_ = right.colorMode_;
        duplexMode_ = right.duplexMode_;
        hasMargin_ = right.hasMargin_;
        margin_ = right.margin_;
        hasOption_ = right.hasOption_;
        option_ = right.option_;
    }
    return *this;
}

PrintAttributes::~PrintAttributes()
{
}

void PrintAttributes::SetCopyNumber(uint32_t copyNumber)
{
    copyNumber_ = copyNumber;
}

void PrintAttributes::SetPageRange(const PrintRange &pageRange)
{
    pageRange_ = pageRange;
}

void PrintAttributes::SetIsSequential(bool isSequential)
{
    isSequential_ = isSequential;
}

void PrintAttributes::SetPageSize(const PrintPageSize &pageSize)
{
    pageSize_ = pageSize;
}

void PrintAttributes::SetIsLandscape(bool isLandscape)
{
    isLandscape_ = isLandscape;
}

void PrintAttributes::SetColorMode(uint32_t colorMode)
{
    colorMode_ = colorMode;
}

void PrintAttributes::SetDuplexMode(uint32_t duplexmode)
{
    duplexMode_ = duplexmode;
}

void PrintAttributes::SetMargin(const PrintMargin &margin)
{
    hasMargin_ = true;
    margin_ = margin;
}

void PrintAttributes::SetOption(const std::string &option)
{
    hasOption_ = true;
    option_ = option;
}

void PrintAttributes::UpdateParams(const PrintAttributes &jobInfo)
{
    copyNumber_ = jobInfo.copyNumber_;
    pageRange_ = jobInfo.pageRange_;
    isSequential_ = jobInfo.isSequential_;
    pageSize_ = jobInfo.pageSize_;
    isLandscape_ = jobInfo.isLandscape_;
    colorMode_ = jobInfo.colorMode_;
    duplexMode_ = jobInfo.duplexMode_;
    hasMargin_ = jobInfo.hasMargin_;
    margin_ = jobInfo.margin_;
    hasOption_ = jobInfo.hasOption_;
    option_ = jobInfo.option_;
}

uint32_t PrintAttributes::GetCopyNumber() const
{
    return copyNumber_;
}

void PrintAttributes::GetPageRange(PrintRange &range) const
{
    range = pageRange_;
}

bool PrintAttributes::GetIsSequential() const
{
    return isSequential_;
}
void PrintAttributes::GetPageSize(PrintPageSize &pageSize) const
{
    pageSize = pageSize_;
}

bool PrintAttributes::GetIsLandscape() const
{
    return isLandscape_;
}

uint32_t PrintAttributes::GetColorMode() const
{
    return colorMode_;
}

uint32_t PrintAttributes::GetDuplexMode() const
{
    return duplexMode_;
}

void PrintAttributes::GetMargin(PrintMargin &margin) const
{
    margin = margin_;
}

const std::string &PrintAttributes::GetOption() const
{
    return option_;
}

bool PrintAttributes::HasOption() const
{
    return hasOption_;
}

bool PrintAttributes::ReadFromParcel(Parcel &parcel)
{
    SetCopyNumber(parcel.ReadUint32());
    auto rangePtr = PrintRange::Unmarshalling(parcel);
    if (rangePtr == nullptr) {
        PRINT_HILOGE("Failed to restore page range");
        return false;
    }
    SetPageRange(*rangePtr);
    SetIsSequential(parcel.ReadBool());
    auto pageSizePtr = PrintPageSize::Unmarshalling(parcel);
    if (pageSizePtr == nullptr) {
        PRINT_HILOGE("Failed to restore page size");
        return false;
    }
    SetPageSize(*pageSizePtr);
    SetIsLandscape(parcel.ReadBool());
    SetColorMode(parcel.ReadUint32());
    SetDuplexMode(parcel.ReadUint32());
    hasMargin_ = parcel.ReadBool();
    if (hasMargin_) {
        auto marginPtr = PrintMargin::Unmarshalling(parcel);
        if (marginPtr == nullptr) {
            PRINT_HILOGE("Failed to restore margin");
            return false;
        }
        margin_ = *marginPtr;
    }
    hasOption_ = parcel.ReadBool();
    if (hasOption_) {
        SetOption(parcel.ReadString());
    }
    return true;
}

bool PrintAttributes::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(GetCopyNumber())) {
        PRINT_HILOGE("Failed to save copy number");
        return false;
    }

    if (!pageRange_.Marshalling(parcel)) {
        PRINT_HILOGE("Failed to save page range");
        return false;
    }

    if (!parcel.WriteBool(GetIsSequential())) {
        PRINT_HILOGE("Failed to save sequential mode");
        return false;
    }

    return MarshallingParam(parcel);
}

bool PrintAttributes::MarshallingParam(Parcel &parcel) const
{
    if (!pageSize_.Marshalling(parcel)) {
        PRINT_HILOGE("Failed to save page size");
        return false;
    }

    if (!parcel.WriteBool(GetIsLandscape())) {
        PRINT_HILOGE("Failed to save printer id");
        return false;
    }

    if (!parcel.WriteUint32(GetColorMode())) {
        PRINT_HILOGE("Failed to save color mode");
        return false;
    }

    if (!parcel.WriteUint32(GetDuplexMode())) {
        PRINT_HILOGE("Failed to save duplex mode");
        return false;
    }

    parcel.WriteBool(hasMargin_);
    if (hasMargin_) {
        margin_.Marshalling(parcel);
    }

    parcel.WriteBool(hasOption_);
    if (hasOption_) {
        parcel.WriteString(GetOption());
    }

    return true;
}

std::shared_ptr<PrintAttributes> PrintAttributes::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintAttributes>();
    if (!nativeObj->ReadFromParcel(parcel)) {
        PRINT_HILOGE("Failed to unmarshalling PrintAttributes");
        return nullptr;
    }
    return nativeObj;
}

void PrintAttributes::Dump()
{
    PRINT_HILOGD("copyNumber_ = %{public}d", copyNumber_);
    PRINT_HILOGD("isSequential_ = %{public}d", isSequential_);
    PRINT_HILOGD("isLandscape_ = %{public}d", isLandscape_);
    PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);

    pageRange_.Dump();
    pageSize_.Dump();
    if (hasMargin_) {
        margin_.Dump();
    }
    if (hasOption_) {
        PRINT_HILOGD("option: %{private}s", option_.c_str());
    }
}
} // namespace OHOS::Print
