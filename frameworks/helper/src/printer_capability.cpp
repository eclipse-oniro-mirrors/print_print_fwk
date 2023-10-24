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

#include "printer_capability.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
PrinterCapability::PrinterCapability() : colorMode_(0), duplexMode_(0),
    hasResolution_(false), hasMargin_(false), hasOption_(false), option_("")
{
    pageSizeList_.clear();
    resolutionList_.clear();
    minMargin_.Reset();
}

PrinterCapability::PrinterCapability(const PrinterCapability &right)
{
    colorMode_ = right.colorMode_;
    duplexMode_ = right.duplexMode_;
    pageSizeList_.assign(right.pageSizeList_.begin(), right.pageSizeList_.end());
    hasResolution_ = right.hasResolution_;
    resolutionList_.assign(right.resolutionList_.begin(), right.resolutionList_.end());
    hasMargin_ = right.hasMargin_;
    minMargin_ = right.minMargin_;
    hasOption_ = right.hasOption_;
    option_= right.option_;
}

PrinterCapability &PrinterCapability::operator=(const PrinterCapability &right)
{
    if (this != &right) {
        colorMode_ = right.colorMode_;
        duplexMode_ = right.duplexMode_;
        pageSizeList_.assign(right.pageSizeList_.begin(), right.pageSizeList_.end());
        hasResolution_ = right.hasResolution_;
        resolutionList_.assign(right.resolutionList_.begin(), right.resolutionList_.end());
        hasMargin_ = right.hasMargin_;
        minMargin_ = right.minMargin_;
        hasOption_ = right.hasOption_;
        option_ = right.option_;
    }
    return *this;
}

PrinterCapability::~PrinterCapability()
{
}

void PrinterCapability::Reset()
{
    SetColorMode(0);
    SetDuplexMode(0);
    pageSizeList_.clear();
    hasResolution_ = false;
    resolutionList_.clear();
    hasMargin_ = false;
    minMargin_.Reset();
}

void PrinterCapability::SetMinMargin(const PrintMargin &minMargin)
{
    hasMargin_ = true;
    minMargin_ = minMargin;
}

void PrinterCapability::SetPageSize(const std::vector<PrintPageSize> &pageSizeList)
{
    pageSizeList_.assign(pageSizeList.begin(), pageSizeList.end());
}

void PrinterCapability::SetResolution(const std::vector<PrintResolution> &resolutionList)
{
    hasResolution_ = true;
    resolutionList_.assign(resolutionList.begin(), resolutionList.end());
}

void PrinterCapability::SetColorMode(uint32_t colorMode)
{
    colorMode_ = colorMode;
}

void PrinterCapability::SetDuplexMode(uint32_t duplexMode)
{
    duplexMode_ = duplexMode;
}

void PrinterCapability::SetOption(const std::string &option)
{
    hasOption_ = true;
    option_ = option;
}

bool PrinterCapability::HasMargin() const
{
    return hasMargin_;
}

void PrinterCapability::GetMinMargin(PrintMargin &margin) const
{
    margin = minMargin_;
}

void PrinterCapability::GetPageSize(std::vector<PrintPageSize> &pageSizeList) const
{
    pageSizeList.assign(pageSizeList_.begin(), pageSizeList_.end());
}

bool PrinterCapability::HasResolution() const
{
    return hasResolution_;
}

void PrinterCapability::GetResolution(std::vector<PrintResolution> &resolutionList) const
{
    resolutionList.assign(resolutionList_.begin(), resolutionList_.end());
}

uint32_t PrinterCapability::GetColorMode() const
{
    return colorMode_;
}

uint32_t PrinterCapability::GetDuplexMode() const
{
    return duplexMode_;
}

bool PrinterCapability::HasOption() const
{
    return hasOption_;
}

std::string PrinterCapability::GetOption() const
{
    return option_;
}

bool PrinterCapability::ReadFromParcel(Parcel &parcel)
{
    SetColorMode(parcel.ReadUint32());
    SetDuplexMode(parcel.ReadUint32());

    uint32_t vecSize = parcel.ReadUint32();

    CHECK_IS_EXCEED_PRINT_RANGE_BOOL(vecSize);
    std::vector<PrintPageSize> pageSizeList;
    for (uint32_t index = 0; index < vecSize; index++) {
        auto pageSizePtr = PrintPageSize::Unmarshalling(parcel);
        if (pageSizePtr != nullptr) {
            pageSizeList.emplace_back(*pageSizePtr);
        }
    }
    SetPageSize(pageSizeList);

    hasResolution_ = parcel.ReadBool();
    if (hasResolution_) {
        std::vector<PrintResolution> resolutionList;
        vecSize = parcel.ReadUint32();
        CHECK_IS_EXCEED_PRINT_RANGE_BOOL(vecSize);
        for (uint32_t index = 0; index < vecSize; index++) {
            auto resolutionPtr = PrintResolution::Unmarshalling(parcel);
            if (resolutionPtr != nullptr) {
                resolutionList.emplace_back(*resolutionPtr);
            }
        }
        SetResolution(resolutionList);
    }

    hasMargin_ = parcel.ReadBool();
    if (hasMargin_) {
        auto marginPtr = PrintMargin::Unmarshalling(parcel);
        if (marginPtr != nullptr) {
            minMargin_ = *marginPtr;
        }
    }
    hasOption_ = parcel.ReadBool();
    if (hasOption_) {
        SetOption(parcel.ReadString());
    }
    return true;
}

bool PrinterCapability::Marshalling(Parcel &parcel) const
{
    parcel.WriteUint32(GetColorMode());
    parcel.WriteUint32(GetDuplexMode());

    uint32_t vecSize = static_cast<uint32_t>(pageSizeList_.size());
    parcel.WriteUint32(vecSize);
    for (uint32_t index = 0; index < vecSize; index++) {
        pageSizeList_[index].Marshalling(parcel);
    }

    parcel.WriteBool(hasResolution_);
    if (hasResolution_) {
        vecSize = static_cast<uint32_t>(resolutionList_.size());
        parcel.WriteUint32(vecSize);
        for (uint32_t index = 0; index < vecSize; index++) {
            resolutionList_[index].Marshalling(parcel);
        }
    }

    parcel.WriteBool(hasMargin_);
    if (hasMargin_) {
        minMargin_.Marshalling(parcel);
    }
    parcel.WriteBool(hasOption_);
    if (hasOption_) {
        parcel.WriteString(GetOption());
    }
    return true;
}

std::shared_ptr<PrinterCapability> PrinterCapability::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrinterCapability>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrinterCapability::Dump()
{
    PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);

    for (auto pageItem : pageSizeList_) {
        pageItem.Dump();
    }

    if (hasResolution_) {
        for (auto resolutionItem : resolutionList_) {
            resolutionItem.Dump();
        }
    }

    if (hasMargin_) {
        minMargin_.Dump();
    }
    if (hasOption_) {
        PRINT_HILOGD("option: %{private}s", option_.c_str());
    }
}
} // namespace OHOS::Print
