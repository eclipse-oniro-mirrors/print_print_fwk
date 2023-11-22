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
    : hasCopyNumber_(false), copyNumber_(0), hasPageRange_(false), hasSequential_(false), isSequential_(false),
    hasPageSize_(false), hasLandscape_(false), isLandscape_(false), hasDirectionMode_(false), directionMode_(0),
    hasColorMode_(false), colorMode_(0), hasDuplexMode_(false), duplexMode_(0),
    hasMargin_(false), hasOption_(false), option_("") {
    pageRange_.Reset();
    pageSize_.Reset();
    margin_.Reset();
}

PrintAttributes::PrintAttributes(const PrintAttributes &right)
{
    hasCopyNumber_ = right.hasCopyNumber_;
    copyNumber_ = right.copyNumber_;
    hasPageRange_ = right.hasPageRange_;
    pageRange_ = right.pageRange_;
    hasSequential_ = right.hasSequential_;
    isSequential_ = right.isSequential_;
    hasPageSize_ = right.hasPageSize_;
    pageSize_ = right.pageSize_;
    hasLandscape_ = right.hasLandscape_;
    isLandscape_ = right.isLandscape_;
    hasDirectionMode_ = right.hasDirectionMode_;
    directionMode_ = right.directionMode_;
    hasColorMode_ = right.hasColorMode_;
    colorMode_ = right.colorMode_;
    hasDuplexMode_ = right.hasDuplexMode_;
    duplexMode_ = right.duplexMode_;
    hasMargin_ = right.hasMargin_;
    margin_ = right.margin_;
    hasOption_ = right.hasOption_;
    option_ = right.option_;
}

PrintAttributes &PrintAttributes::operator=(const PrintAttributes &right)
{
    if (this != &right) {
        hasCopyNumber_ = right.hasCopyNumber_;
        copyNumber_ = right.copyNumber_;
        hasPageRange_ = right.hasPageRange_;
        pageRange_ = right.pageRange_;
        hasSequential_ = right.hasSequential_;
        isSequential_ = right.isSequential_;
        hasPageSize_ = right.hasPageSize_;
        pageSize_ = right.pageSize_;
        hasLandscape_ = right.hasLandscape_;
        isLandscape_ = right.isLandscape_;
        hasDirectionMode_ = right.hasDirectionMode_;
        directionMode_ = right.directionMode_;
        hasColorMode_ = right.hasColorMode_;
        colorMode_ = right.colorMode_;
        hasDuplexMode_ = right.hasDuplexMode_;
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
    hasCopyNumber_ = true;
    copyNumber_ = copyNumber;
}

void PrintAttributes::SetPageRange(const PrintRange &pageRange)
{
    hasPageRange_ = true;
    pageRange_ = pageRange;
}

void PrintAttributes::SetIsSequential(bool isSequential)
{
    hasSequential_ = true;
    isSequential_ = isSequential;
}

void PrintAttributes::SetPageSize(const PrintPageSize &pageSize)
{
    hasPageSize_ = true;
    pageSize_ = pageSize;
}

void PrintAttributes::SetIsLandscape(bool isLandscape)
{
    hasLandscape_ = true;
    isLandscape_ = isLandscape;
}

void PrintAttributes::SetDirectionMode(uint32_t directionMode)
{
    hasDirectionMode_ = true;
    directionMode_ = directionMode;
}

void PrintAttributes::SetColorMode(uint32_t colorMode)
{
    hasColorMode_ = true;
    colorMode_ = colorMode;
}

void PrintAttributes::SetDuplexMode(uint32_t duplexmode)
{
    hasDuplexMode_ = true;
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
    hasCopyNumber_ = jobInfo.hasCopyNumber_;
    copyNumber_ = jobInfo.copyNumber_;
    hasPageRange_ = jobInfo.hasPageRange_;
    pageRange_ = jobInfo.pageRange_;
    hasSequential_ = jobInfo.hasSequential_;
    isSequential_ = jobInfo.isSequential_;
    hasPageSize_ = jobInfo.hasPageSize_;
    pageSize_ = jobInfo.pageSize_;
    hasLandscape_ = jobInfo.hasLandscape_;
    isLandscape_ = jobInfo.isLandscape_;
    hasDirectionMode_ = jobInfo.hasDirectionMode_;
    directionMode_ = jobInfo.directionMode_;
    hasColorMode_ = jobInfo.hasColorMode_;
    colorMode_ = jobInfo.colorMode_;
    hasDuplexMode_ = jobInfo.hasDuplexMode_;
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

uint32_t PrintAttributes::GetDirectionMode() const
{
    return directionMode_;
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

bool PrintAttributes::HasCopyNumber() const
{
    return hasCopyNumber_;
}

bool PrintAttributes::HasPageRange() const
{
    return hasPageRange_;
}

bool PrintAttributes::HasSequential() const
{
    return hasSequential_;
}

bool PrintAttributes::HasPageSize() const
{
    return hasPageSize_;
}

bool PrintAttributes::HasLandscape() const
{
    return hasLandscape_;
}

bool PrintAttributes::HasDirectionMode() const
{
    return hasDirectionMode_;
}

bool PrintAttributes::HasColorMode() const
{
    return hasColorMode_;
}

bool PrintAttributes::HasDuplexMode() const
{
    return hasDuplexMode_;
}

bool PrintAttributes::HasMargin() const
{
    return hasMargin_;
}

bool PrintAttributes::HasOption() const
{
    return hasOption_;
}

bool PrintAttributes::ReadFromParcel(Parcel &parcel)
{
    hasCopyNumber_ = parcel.ReadBool();
    if (hasCopyNumber_) {
        SetCopyNumber(parcel.ReadUint32());
    }
    hasPageRange_ = parcel.ReadBool();
    if (hasPageRange_) {
        auto rangePtr = PrintRange::Unmarshalling(parcel);
        if (rangePtr == nullptr) {
            PRINT_HILOGE("Failed to restore page range");
            return false;
        }
        SetPageRange(*rangePtr);
    }
    hasSequential_ = parcel.ReadBool();
    if (hasSequential_) {
        SetIsSequential(parcel.ReadBool());
    }
    hasPageSize_ = parcel.ReadBool();
    if (hasPageSize_) {
        auto pageSizePtr = PrintPageSize::Unmarshalling(parcel);
        if (pageSizePtr == nullptr) {
            PRINT_HILOGE("Failed to restore page size");
            return false;
        }
        SetPageSize(*pageSizePtr);
    }
    hasLandscape_ = parcel.ReadBool();
    if (hasLandscape_) {
        SetIsLandscape(parcel.ReadBool());
    }
    hasDirectionMode_ = parcel.ReadBool();
    if (hasDirectionMode_) {
        SetDirectionMode(parcel.ReadUint32());
    }
    hasColorMode_ = parcel.ReadBool();
    if (hasColorMode_) {
        SetColorMode(parcel.ReadUint32());
    }
    hasDuplexMode_ = parcel.ReadBool();
    if (hasDuplexMode_) {
        SetDuplexMode(parcel.ReadUint32());
    }
    return ReadNextDataFromParcel(parcel);
}

bool PrintAttributes::ReadNextDataFromParcel(Parcel &parcel)
{
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
    parcel.WriteBool(hasCopyNumber_);
    if (hasCopyNumber_) {
        parcel.WriteUint32(GetCopyNumber());
    }

    parcel.WriteBool(hasPageRange_);
    if (hasPageRange_) {
        pageRange_.Marshalling(parcel);
    }

    parcel.WriteBool(hasSequential_);
    if (hasSequential_) {
        parcel.WriteBool(GetIsSequential());
    }

    return MarshallingParam(parcel);
}

bool PrintAttributes::MarshallingParam(Parcel &parcel) const
{
    parcel.WriteBool(hasPageSize_);
    if (hasPageSize_) {
        pageSize_.Marshalling(parcel);
    }

    parcel.WriteBool(hasLandscape_);
    if (hasLandscape_) {
        parcel.WriteBool(GetIsLandscape());
    }

    parcel.WriteBool(hasDirectionMode_);
    if (hasDirectionMode_) {
        parcel.WriteUint32(GetDirectionMode());
    }

    parcel.WriteBool(hasColorMode_);
    if (hasColorMode_) {
        parcel.WriteUint32(GetColorMode());
    }

    parcel.WriteBool(hasDuplexMode_);
    if (hasDuplexMode_) {
        parcel.WriteUint32(GetDuplexMode());
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
    if (hasCopyNumber_) {
        PRINT_HILOGD("copyNumber_ = %{public}d", copyNumber_);
    }
    if (hasSequential_) {
        PRINT_HILOGD("isSequential_ = %{public}d", isSequential_);
    }
    if (hasLandscape_) {
        PRINT_HILOGD("isLandscape_ = %{public}d", isLandscape_);
    }
    if (hasDirectionMode_) {
        PRINT_HILOGD("directionMode_ = %{public}d", directionMode_);
    }
    if (hasColorMode_) {
        PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    }
    if (hasDuplexMode_) {
        PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);
    }
    if (hasPageRange_) {
        pageRange_.Dump();
    }
    if (hasPageSize_) {
        pageSize_.Dump();
    }
    if (hasMargin_) {
        margin_.Dump();
    }
    if (hasOption_) {
        PRINT_HILOGD("option: %{private}s", option_.c_str());
    }
}
} // namespace OHOS::Print
