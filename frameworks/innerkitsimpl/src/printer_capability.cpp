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
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {

static constexpr const char *PARAM_CAPABILITY_COLORMODE = "colorMode";
static constexpr const char *PARAM_CAPABILITY_DUPLEXMODE = "duplexMode";
static constexpr const char *PARAM_CAPABILITY_PAGESIZE = "pageSize";
static constexpr const char *PARAM_CAPABILITY_RESOLUTION = "resolution";
static constexpr const char *PARAM_CAPABILITY_MINMARGIN = "minMargin";

PrinterCapability::PrinterCapability()
    : colorMode_(0), duplexMode_(0), minMargin_(nullptr) {
  pageSizeList_.clear();
  resolutionList_.clear();
}

PrinterCapability::PrinterCapability(const PrinterCapability &right) {
  colorMode_ = right.colorMode_;
  duplexMode_ = right.duplexMode_;
  SetPageSize(right.pageSizeList_);
  SetResolution(right.resolutionList_);
  minMargin_ = right.minMargin_;
}

PrinterCapability &
PrinterCapability::operator=(const PrinterCapability &right) {
  if (this != &right) {
    colorMode_ = right.colorMode_;
    duplexMode_ = right.duplexMode_;
    SetPageSize(right.pageSizeList_);
    SetResolution(right.resolutionList_);
    minMargin_ = right.minMargin_;
  }
  return *this;
}

PrinterCapability::~PrinterCapability() {}

void PrinterCapability::Reset() {
  SetColorMode(0);
  SetDuplexMode(0);
  pageSizeList_.clear();
  resolutionList_.clear();
  minMargin_ = nullptr;
}

void PrinterCapability::SetMinMargin(const PrintMargin &minMargin) {
  if (minMargin_ != nullptr) {
    *minMargin_ = minMargin;
    return;
  }
  minMargin_ = std::make_shared<PrintMargin>(minMargin);
}

void PrinterCapability::SetPageSize(
    const std::vector<PrintPageSize> &pageSizeList) {
  pageSizeList_.clear();
  pageSizeList_.assign(pageSizeList.begin(), pageSizeList.end());
}

void PrinterCapability::SetResolution(
    const std::vector<PrintResolution> &resolutionList) {
  resolutionList_.clear();
  resolutionList_.assign(resolutionList.begin(), resolutionList.end());
}

void PrinterCapability::SetColorMode(uint32_t colorMode) {
  colorMode_ = colorMode;
}

void PrinterCapability::SetDuplexMode(uint32_t duplexMode) {
  duplexMode_ = duplexMode;
}

void PrinterCapability::GetMinMargin(PrintMargin &margin) const {
  if (minMargin_ != nullptr) {
    margin = *minMargin_;
    return;
  }
  margin.Reset();
}

void PrinterCapability::GetPageSize(
    std::vector<PrintPageSize> &pageSizeList) const {
  pageSizeList.clear();
  pageSizeList.assign(pageSizeList_.begin(), pageSizeList_.end());
}

void PrinterCapability::GetResolution(
    std::vector<PrintResolution> &resolutionList) const {
  resolutionList.clear();
  resolutionList.assign(resolutionList_.begin(), resolutionList_.end());
}

uint32_t PrinterCapability::GetColorMode() const { return colorMode_; }

uint32_t PrinterCapability::GetDuplexMode() const { return duplexMode_; }

bool PrinterCapability::ReadFromParcel(Parcel &parcel) {
  SetColorMode(parcel.ReadUint32());
  SetDuplexMode(parcel.ReadUint32());

  uint32_t vecSize = parcel.ReadUint32();
  std::vector<PrintPageSize> pageSizeList;
  for (uint32_t index = 0; index < vecSize; index++) {
    auto pageSizePtr = PrintPageSize::Unmarshalling(parcel);
    if (pageSizePtr == nullptr) {
      PRINT_HILOGE("Failed to read page size from parcel");
      return false;
    }
    pageSizeList.emplace_back(*pageSizePtr);
  }
  SetPageSize(pageSizeList);

  std::vector<PrintResolution> resolutionList;
  vecSize = parcel.ReadUint32();
  for (uint32_t index = 0; index < vecSize; index++) {
    auto resolutionPtr = PrintResolution::Unmarshalling(parcel);
    if (resolutionPtr == nullptr) {
      PRINT_HILOGE("Failed to read print resolution from parcel");
      return false;
    }
    resolutionList.emplace_back(*resolutionPtr);
  }
  SetResolution(resolutionList);

  minMargin_ = nullptr;
  if (parcel.ReadBool()) {
    minMargin_ = PrintMargin::Unmarshalling(parcel);
    if (minMargin_ == nullptr) {
      return false;
    }
  }
  return true;
}

bool PrinterCapability::Marshalling(Parcel &parcel) const {
  parcel.WriteUint32(GetColorMode());
  parcel.WriteUint32(GetDuplexMode());

  uint32_t vecSize = static_cast<uint32_t>(pageSizeList_.size());
  parcel.WriteUint32(vecSize);
  for (uint32_t index = 0; index < vecSize; index++) {
    pageSizeList_[index].Marshalling(parcel);
  }

  vecSize = static_cast<uint32_t>(resolutionList_.size());
  parcel.WriteUint32(vecSize);
  for (uint32_t index = 0; index < vecSize; index++) {
    resolutionList_[index].Marshalling(parcel);
  }

  if (minMargin_ != nullptr) {
    parcel.WriteBool(true);
    minMargin_->Marshalling(parcel);
  } else {
    parcel.WriteBool(false);
  }
  return true;
}

std::shared_ptr<PrinterCapability>
PrinterCapability::Unmarshalling(Parcel &parcel) {
  auto nativeObj = std::make_shared<PrinterCapability>();
  if (nativeObj == nullptr) {
    PRINT_HILOGE("Failed to create printer capability object");
    return nullptr;
  }
  if (!nativeObj->ReadFromParcel(parcel)) {
    PRINT_HILOGE("Failed to unmarshalling Printer capability");
    return nullptr;
  }
  return nativeObj;
}

bool PrinterCapability::CreatePageSizeList(napi_env env,
                                           napi_value &jsPrinterCap) const {
  napi_value jsPageSizes = nullptr;
  PRINT_CALL_BASE(env, napi_create_array(env, &jsPageSizes), false);
  uint32_t arrLength = pageSizeList_.size();

  for (uint32_t index = 0; index < arrLength; index++) {
    napi_value value = pageSizeList_[index].ToJsObject(env);
    PRINT_CALL_BASE(env, napi_set_element(env, jsPageSizes, index, value),
                    false);
  }
  PRINT_CALL_BASE(env,
                  napi_set_named_property(env, jsPrinterCap,
                                          PARAM_CAPABILITY_PAGESIZE,
                                          jsPageSizes),
                  false);
  return true;
}

bool PrinterCapability::CreateResolutionList(napi_env env,
                                             napi_value &jsPrinterCap) const {
  napi_value jsResolutionList = nullptr;
  PRINT_CALL_BASE(env, napi_create_array(env, &jsResolutionList), false);
  uint32_t arrLength = resolutionList_.size();

  for (uint32_t index = 0; index < arrLength; index++) {
    napi_value value = resolutionList_[index].ToJsObject(env);
    PRINT_CALL_BASE(env, napi_set_element(env, jsResolutionList, index, value),
                    false);
  }
  PRINT_CALL_BASE(env,
                  napi_set_named_property(env, jsPrinterCap,
                                          PARAM_CAPABILITY_RESOLUTION,
                                          jsResolutionList),
                  false);
  return true;
}

napi_value PrinterCapability::ToJsObject(napi_env env) const {
  napi_value jsObj = nullptr;
  PRINT_CALL(env, napi_create_object(env, &jsObj));

  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_CAPABILITY_COLORMODE,
                                    GetColorMode());
  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_CAPABILITY_DUPLEXMODE,
                                    GetDuplexMode());

  if (!CreatePageSizeList(env, jsObj)) {
    PRINT_HILOGE(
        "Failed to create page size list property of printer capability");
    return nullptr;
  }

  if (!CreateResolutionList(env, jsObj)) {
    PRINT_HILOGE(
        "Failed to create resolution list property of printer capability");
    return nullptr;
  }

  if (minMargin_ != nullptr) {
    napi_value jsMargin = minMargin_->ToJsObject(env);
    PRINT_CALL(env, napi_set_named_property(
                        env, jsObj, PARAM_CAPABILITY_MINMARGIN, jsMargin));
  }
  return jsObj;
}

std::shared_ptr<PrinterCapability>
PrinterCapability::BuildFromJs(napi_env env, napi_value jsValue) {
  auto nativeObj = std::make_shared<PrinterCapability>();
  if (nativeObj == nullptr) {
    PRINT_HILOGE("Failed to create printer capability object");
    return nullptr;
  }

  if (!ValidateProperty(env, jsValue)) {
    PRINT_HILOGE("Invalid property of printer capability");
    return nullptr;
  }

  uint32_t colorMode = NapiPrintUtils::GetUint32Property(
      env, jsValue, PARAM_CAPABILITY_COLORMODE);
  uint32_t duplexMode = NapiPrintUtils::GetUint32Property(
      env, jsValue, PARAM_CAPABILITY_DUPLEXMODE);
  nativeObj->SetColorMode(colorMode);
  nativeObj->SetDuplexMode(duplexMode);

  napi_value jsPageSizes =
      NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_CAPABILITY_PAGESIZE);
  bool isArray = false;
  napi_is_array(env, jsPageSizes, &isArray);
  if (!isArray) {
    PRINT_HILOGE("Invalid list of page size");
    return nullptr;
  }

  std::vector<PrintPageSize> pageSizes;
  uint32_t arrayLength = 0;
  napi_get_array_length(env, jsPageSizes, &arrayLength);
  for (uint32_t index = 0; index < arrayLength; index++) {
    napi_value jsPageSize;
    napi_get_element(env, jsPageSizes, index, &jsPageSize);
    auto pageSizePtr = PrintPageSize::BuildFromJs(env, jsPageSize);
    if (pageSizePtr == nullptr) {
      PRINT_HILOGE("Failed to build printer capability object from js");
      return nullptr;
    }
    pageSizes.emplace_back(*pageSizePtr);
  }
  nativeObj->SetPageSize(pageSizes);

  napi_value jsResolutionList = NapiPrintUtils::GetNamedProperty(
      env, jsValue, PARAM_CAPABILITY_RESOLUTION);
  std::vector<PrintResolution> resolutionList;
  if (jsResolutionList != nullptr) {
    isArray = false;
    napi_is_array(env, jsResolutionList, &isArray);
    if (!isArray) {
      PRINT_HILOGE("Invalid list of print resolution");
      return nullptr;
    }
    std::vector<PrintResolution> resolutionList;
    uint32_t arrayLength = 0;
    napi_get_array_length(env, jsPageSizes, &arrayLength);
    for (uint32_t index = 0; index < arrayLength; index++) {
      napi_value jsResolution;
      napi_get_element(env, jsResolutionList, index, &jsResolution);
      auto resolutionPtr = PrintResolution::BuildFromJs(env, jsResolution);
      if (resolutionPtr == nullptr) {
        PRINT_HILOGE("Failed to build printer capability object from js");
        return nullptr;
      }
      resolutionList.emplace_back(*resolutionPtr);
    }
  }
  nativeObj->SetResolution(resolutionList);

  napi_value jsMargin = NapiPrintUtils::GetNamedProperty(
      env, jsValue, PARAM_CAPABILITY_MINMARGIN);
  PrintMargin minMargin;
  if (jsMargin != nullptr) {
    auto marginPtr = PrintMargin::BuildFromJs(env, jsMargin);
    if (marginPtr == nullptr) {
      PRINT_HILOGE("Failed to build printer capability object from js");
      return nullptr;
    }
    minMargin = *marginPtr;
  }
  nativeObj->SetMinMargin(minMargin);

  PRINT_HILOGE("Build Print Capability succeed");
  return nativeObj;
}

bool PrinterCapability::ValidateProperty(napi_env env, napi_value object) {
  std::map<std::string, PrintParamStatus> propertyList = {
      {PARAM_CAPABILITY_COLORMODE, PRINT_PARAM_NOT_SET},
      {PARAM_CAPABILITY_DUPLEXMODE, PRINT_PARAM_NOT_SET},
      {PARAM_CAPABILITY_PAGESIZE, PRINT_PARAM_NOT_SET},
      {PARAM_CAPABILITY_RESOLUTION, PRINT_PARAM_OPT},
      {PARAM_CAPABILITY_MINMARGIN, PRINT_PARAM_OPT},
  };

  auto names = NapiPrintUtils::GetPropertyNames(env, object);
  for (auto name : names) {
    if (propertyList.find(name) == propertyList.end()) {
      PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
      return false;
    }
    propertyList[name] = PRINT_PARAM_SET;
  }

  for (auto propertypItem : propertyList) {
    if (propertypItem.second == PRINT_PARAM_NOT_SET) {
      PRINT_HILOGE("Missing Property: %{public}s", propertypItem.first.c_str());
      return false;
    }
  }
  return true;
}

void PrinterCapability::Dump() {
  PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
  PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);

  for (auto pageItem : pageSizeList_) {
    pageItem.Dump();
  }

  for (auto resolutionItem : resolutionList_) {
    resolutionItem.Dump();
  }
  if (minMargin_ != nullptr) {
    minMargin_->Dump();
  }
}
} // namespace OHOS::Print
