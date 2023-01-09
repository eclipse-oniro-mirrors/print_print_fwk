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

#include "print_range.h"
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_RANGE_STARTPAGE = "startPage";
static constexpr const char *PARAM_RANGE_ENDPAGE = "endPage";
static constexpr const char *PARAM_RANGE_PAGES = "pages";

PrintRange::PrintRange() : hasStartPage_(false), startPage_(0), hasEndPage_(false),
    endPage_(0), hasPages_(false)
{
    pages_.clear();
}

PrintRange::PrintRange(const PrintRange &right)
{
    hasStartPage_ = right.hasStartPage_;
    startPage_ = right.startPage_;
    hasEndPage_ = right.hasEndPage_;
    endPage_ = right.endPage_;
    hasPages_ = right.hasPages_;
    pages_.assign(right.pages_.begin(), right.pages_.end());
}

PrintRange &PrintRange::operator=(const PrintRange &right)
{
    if (this != &right) {
        hasStartPage_ = right.hasStartPage_;
        startPage_ = right.startPage_;
        hasEndPage_ = right.hasEndPage_;
        endPage_ = right.endPage_;
        hasPages_ = right.hasPages_;
        pages_.assign(right.pages_.begin(), right.pages_.end());
    }
    return *this;
}

PrintRange::~PrintRange()
{
    pages_.clear();
}

void PrintRange::SetStartPage(uint32_t startpage)
{
    hasStartPage_ = true;
    startPage_ = startpage;
}

void PrintRange::SetEndPage(uint32_t endpage)
{
    hasEndPage_ = true;
    endPage_ = endpage;
}

void PrintRange::SetPages(const std::vector<uint32_t> &pages)
{
    hasPages_ = true;
    pages_.assign(pages.begin(), pages.end());
}

void PrintRange::Reset()
{
    hasStartPage_ = false;
    startPage_ = 0;
    hasEndPage_ = false;
    endPage_ = 0;
    hasPages_ = false;
    pages_.clear();
}

uint32_t PrintRange::GetStartPage() const
{
    return startPage_;
}

uint32_t PrintRange::GetEndPage() const
{
    return endPage_;
}

void PrintRange::GetPages(std::vector<uint32_t> &pages) const
{
    pages.assign(pages_.begin(), pages_.end());
}

bool PrintRange::ReadFromParcel(Parcel &parcel)
{
    hasStartPage_ = parcel.ReadBool();
    if (hasStartPage_) {
        SetStartPage(parcel.ReadUint32());
    }

    hasEndPage_ = parcel.ReadBool();
    if (hasEndPage_) {
        SetEndPage(parcel.ReadUint32());
    }

    hasPages_ = parcel.ReadBool();
    if (hasPages_) {
        std::vector<uint32_t> pages;
        if (!parcel.ReadUInt32Vector(&pages)) {
            PRINT_HILOGE("Failed to read print range object from parcel");
            return false;
        }
        SetPages(pages);
    }
    return true;
}

bool PrintRange::Marshalling(Parcel &parcel) const
{
    parcel.WriteBool(hasStartPage_);
    if (hasStartPage_) {
        parcel.WriteUint32(GetStartPage());
    }

    parcel.WriteBool(hasEndPage_);
    if (hasEndPage_) {
        parcel.WriteUint32(GetEndPage());
    }

    parcel.WriteBool(hasPages_);
    if (hasPages_ && !parcel.WriteUInt32Vector(pages_)) {
        PRINT_HILOGE("Failed to marshalling print range object");
        return false;
    }
    return true;
}

std::shared_ptr<PrintRange> PrintRange::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintRange>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print range object");
        return nullptr;
    }
    if (!nativeObj->ReadFromParcel(parcel)) {
        PRINT_HILOGE("Failed to unmarshalling print rage");
        return nullptr;
    }
    return nativeObj;
}

napi_value PrintRange::ToJsObject(napi_env env) const
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    if (hasStartPage_) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RANGE_STARTPAGE, GetStartPage());
    }
    if (hasEndPage_) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RANGE_ENDPAGE, GetEndPage());
    }

    if (hasPages_) {
        if (GetStartPage() == 0 && GetEndPage() == 0 && pages_.size() > 0) {
            napi_value arrPages = nullptr;
            PRINT_CALL(env, napi_create_array(env, &arrPages));
            uint32_t arrPagesLength = pages_.size();
            for (uint32_t i = 0; i < arrPagesLength; i++) {
                napi_value value;
                PRINT_CALL(env, napi_create_uint32(env, pages_[i], &value));
                PRINT_CALL(env, napi_set_element(env, arrPages, i, value));
            }
            PRINT_CALL(env, napi_set_named_property(env, jsObj, PARAM_RANGE_PAGES, arrPages));
        }
    }
    return jsObj;
}

std::shared_ptr<PrintRange> PrintRange::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintRange>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print range object");
        return nullptr;
    }

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print range");
        return nullptr;
    }

    auto jsStartPage = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_STARTPAGE);
    if (jsStartPage != nullptr) {
        nativeObj->SetStartPage(NapiPrintUtils::GetUint32FromValue(env, jsStartPage));
    }

    auto jsEndPage = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_ENDPAGE);
    if (jsEndPage != nullptr) {
        nativeObj->SetEndPage(NapiPrintUtils::GetUint32FromValue(env, jsEndPage));
    }

    if (nativeObj->GetEndPage() != 0 && nativeObj->GetEndPage() < nativeObj->GetStartPage()) {
        PRINT_HILOGE("Start and end page conflict");
        return nullptr;
    }

    napi_value jsPages = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_PAGES);
    if (jsPages != nullptr) {
        std::vector<uint32_t> pages;
        bool isArray = false;
        PRINT_CALL(env, napi_is_array(env, jsPages, &isArray));
        if (!isArray) {
            PRINT_HILOGE("Invalid pages of page range");
            return nullptr;
        }
        uint32_t arrayLength = 0;
        PRINT_CALL(env, napi_get_array_length(env, jsPages, &arrayLength));
        for (uint32_t index = 0; index < arrayLength; index++) {
            napi_value jsPage;
            uint32_t pageNo;
            PRINT_CALL(env, napi_get_element(env, jsPages, index, &jsPage));
            PRINT_CALL(env, napi_get_value_uint32(env, jsPage, &pageNo));
            pages.emplace_back(pageNo);
        }
        nativeObj->SetPages(pages);
    }

    PRINT_HILOGE("Build Page Range succeed");
    return nativeObj;
}

bool PrintRange::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_RANGE_STARTPAGE, PRINT_PARAM_OPT},
        {PARAM_RANGE_ENDPAGE, PRINT_PARAM_OPT},
        {PARAM_RANGE_PAGES, PRINT_PARAM_OPT},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = PRINT_PARAM_SET;
    }
    bool hasStartPage = propertyList[PARAM_RANGE_STARTPAGE] == PRINT_PARAM_SET;
    bool hasEndPage = propertyList[PARAM_RANGE_ENDPAGE] == PRINT_PARAM_SET;
    bool hasPages = propertyList[PARAM_RANGE_PAGES] == PRINT_PARAM_SET;
    if ((hasStartPage || hasEndPage) && hasPages) {
        return false;
    }
    return true;
}

void PrintRange::Dump()
{
    if (hasStartPage_) {
        PRINT_HILOGD("startPage_ = %{public}d", startPage_);
    }

    if (hasEndPage_) {
        PRINT_HILOGD("endPage_ = %{public}d", endPage_);
    }

    if (hasPages_) {
        uint32_t pageLength = pages_.size();
        for (uint32_t i = 0; i < pageLength; i++) {
            PRINT_HILOGD("pages_ = %{public}d", pages_[i]);
        }
    }
}
} // namespace OHOS::Print
