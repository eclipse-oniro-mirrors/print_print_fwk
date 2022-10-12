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

PrintRange::PrintRange() : startPage_(0), endPage_(0) { pages_.clear(); }

PrintRange::PrintRange(const PrintRange &right) {
  startPage_ = right.startPage_;
  endPage_ = right.endPage_;
  pages_.clear();
  pages_.assign(right.pages_.begin(), right.pages_.end());
}

PrintRange &PrintRange::operator=(const PrintRange &right) {
  if (this != &right) {
    startPage_ = right.startPage_;
    endPage_ = right.endPage_;
    pages_.clear();
    pages_.assign(right.pages_.begin(), right.pages_.end());
  }
  return *this;
}

PrintRange::~PrintRange() { pages_.clear(); }

void PrintRange::SetStartPage(uint32_t startpage) { startPage_ = startpage; }

void PrintRange::SetEndPage(uint32_t endpage) { endPage_ = endpage; }

void PrintRange::SetPages(const std::vector<uint32_t> &pages) {
  pages_.clear();
  pages_.assign(pages.begin(), pages.end());
}

void PrintRange::Reset() {
  startPage_ = 0;
  endPage_ = 0;
  pages_.clear();
}

uint32_t PrintRange::GetStartPage() const { return startPage_; }

uint32_t PrintRange::GetEndPage() const { return endPage_; }

void PrintRange::GetPages(std::vector<uint32_t> &pages) const {
  pages.clear();
  pages.assign(pages_.begin(), pages_.end());
}

bool PrintRange::ReadFromParcel(Parcel &parcel) {
  SetStartPage(parcel.ReadUint32());
  SetEndPage(parcel.ReadUint32());
  std::vector<uint32_t> pages;
  if (!parcel.ReadUInt32Vector(&pages)) {
    PRINT_HILOGE("Failed to read print range object from parcel");
    return false;
  }
  SetPages(pages);
  return true;
}

bool PrintRange::Marshalling(Parcel &parcel) const {
  parcel.WriteUint32(GetStartPage());
  parcel.WriteUint32(GetEndPage());
  if (!parcel.WriteUInt32Vector(pages_)) {
    PRINT_HILOGE("Failed to marshalling print range object");
    return false;
  }
  return true;
}

std::shared_ptr<PrintRange> PrintRange::Unmarshalling(Parcel &parcel) {
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

napi_value PrintRange::ToJsObject(napi_env env) const {
  napi_value jsObj = nullptr;
  NAPI_CALL(env, napi_create_object(env, &jsObj));
  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RANGE_STARTPAGE,
                                    GetStartPage());
  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RANGE_ENDPAGE,
                                    GetEndPage());

  napi_value arrPages = nullptr;
  NAPI_CALL(env, napi_create_array(env, &arrPages));
  uint32_t arrPagesLength = pages_.size();
  for (uint32_t i = 0; i < arrPagesLength; i++) {
    napi_value value;
    NAPI_CALL(env, napi_create_uint32(env, pages_[i], &value));
    NAPI_CALL(env, napi_set_element(env, arrPages, i, value));
  }
  NAPI_CALL(env,
            napi_set_named_property(env, jsObj, PARAM_RANGE_PAGES, arrPages));
  return jsObj;
}

std::shared_ptr<PrintRange> PrintRange::BuildFromJs(napi_env env,
                                                    napi_value jsValue) {
  auto nativeObj = std::make_shared<PrintRange>();
  if (nativeObj == nullptr) {
    PRINT_HILOGE("Failed to create print range object");
    return nullptr;
  }

  auto names = NapiPrintUtils::GetPropertyNames(env, jsValue);
  for (auto name : names) {
    PRINT_HILOGD("Property: %{public}s", name.c_str());
  }

  uint32_t startPage =
      NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_RANGE_STARTPAGE);
  uint32_t endPage =
      NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_RANGE_ENDPAGE);

  nativeObj->SetStartPage(startPage);
  nativeObj->SetEndPage(endPage);

  napi_value jsPages =
      NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_RANGE_PAGES);
  if (jsPages == nullptr) {
    PRINT_HILOGE("invalid pages object");
    return nullptr;
  }
  bool isArray = false;
  NAPI_CALL(env, napi_is_array(env, jsPages, &isArray));

  std::vector<uint32_t> pages;
  if (isArray) {
    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, jsPages, &arrayLength));
    for (uint32_t index = 0; index < arrayLength; index++) {
      napi_value jsPage;
      uint32_t pageNo;
      NAPI_CALL(env, napi_get_element(env, jsPages, index, &jsPage));
      NAPI_CALL(env, napi_get_value_uint32(env, jsPage, &pageNo));
      pages.push_back(pageNo);
    }
    nativeObj->SetPages(pages);
  }
  PRINT_HILOGE("Build Page Range succeed");
  return nativeObj;
}

void PrintRange::Dump() {
  PRINT_HILOGD("startPage_ = %{public}d", startPage_);
  PRINT_HILOGD("endPage_ = %{public}d", endPage_);
  uint32_t pageLength = pages_.size();
  for (uint32_t i = 0; i < pageLength; i++) {
    PRINT_HILOGD("pages_ = %{public}d", pages_[i]);
  }
}
} // namespace OHOS::Print
