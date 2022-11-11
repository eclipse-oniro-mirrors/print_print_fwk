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

#include "print_job.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {

static constexpr const char *PARAM_JOB_FILES = "files";
static constexpr const char *PARAM_JOB_JOBID = "jobId";
static constexpr const char *PARAM_JOB_PRINTERID = "printerId";
static constexpr const char *PARAM_JOB_JOBSTATE = "jobState";
static constexpr const char *PARAM_JOB_SUBSTATE = "jobSubState";
static constexpr const char *PARAM_JOB_COPYNUMBER = "copyNumber";
static constexpr const char *PARAM_JOB_PAGERANGE = "pageRange";
static constexpr const char *PARAM_JOB_ISSEQUENTIAL = "isSequential";
static constexpr const char *PARAM_JOB_PAGESIZE = "pageSize";
static constexpr const char *PARAM_JOB_ISLANDSCAPE = "isLandscape";
static constexpr const char *PARAM_JOB_COLORMODE = "colorMode";
static constexpr const char *PARAM_JOB_DUPLEXMODE = "duplexMode";
static constexpr const char *PARAM_JOB_MARGIN = "margin";
static constexpr const char *PARAM_JOB_PREVIEW = "preview";
static constexpr const char *PARAM_JOB_OPTION = "option";

PrintJob::PrintJob()
    : jobId_(""), printerId_(""), jobState_(PRINT_JOB_PREPARED),
      subState_(PRINT_JOB_BLOCKED_UNKNOWN), copyNumber_(0),
      isSequential_(false), isLandscape_(false), colorMode_(0), duplexMode_(0),
      margin_(nullptr), preview_(nullptr), option_("") {}

PrintJob::PrintJob(const PrintJob &right) {
  files_.clear();
  files_.assign(right.files_.begin(), right.files_.end());

  printerId_ = right.printerId_;
  jobId_ = right.jobId_;
  jobState_ = right.jobState_;
  subState_ = right.subState_;
  copyNumber_ = right.copyNumber_;
  pageRange_ = right.pageRange_;
  isSequential_ = right.isSequential_;
  pageSize_ = right.pageSize_;
  isLandscape_ = right.isLandscape_;
  colorMode_ = right.colorMode_;
  duplexMode_ = right.duplexMode_;
  margin_ = right.margin_;
  preview_ = right.preview_;
  option_ = right.option_;
}

PrintJob &PrintJob::operator=(const PrintJob &right) {
  if (this != &right) {
    files_.clear();
    files_.assign(right.files_.begin(), right.files_.end());

    printerId_ = right.printerId_;
    jobId_ = right.jobId_;
    jobState_ = right.jobState_;
    subState_ = right.subState_;
    copyNumber_ = right.copyNumber_;
    pageRange_ = right.pageRange_;
    isSequential_ = right.isSequential_;
    pageSize_ = right.pageSize_;
    isLandscape_ = right.isLandscape_;
    colorMode_ = right.colorMode_;
    duplexMode_ = right.duplexMode_;
    margin_ = right.margin_;
    preview_ = right.preview_;
    option_ = right.option_;
  }
  return *this;
}

PrintJob::~PrintJob() {}

void PrintJob::SetFiles(const std::vector<std::string> &files) {
  files_.clear();
  files_.assign(files.begin(), files.end());
}

void PrintJob::SetJobId(const std::string &jobId) { jobId_ = jobId; }

void PrintJob::SetPrinterId(const std::string &printerid) {
  printerId_ = printerid;
}

void PrintJob::SetJobState(uint32_t jobState) {
  if (jobState < PRINT_JOB_UNKNOWN) {
    jobState_ = jobState;
  }
}

void PrintJob::SetSubState(uint32_t subState) {
  if (jobState_ == PRINT_JOB_COMPLETED &&
      subState <= PRINT_JOB_COMPLETED_FILE_CORRUPT) {
    subState_ = subState;
  }
  if (jobState_ == PRINT_JOB_BLOCKED &&
      (subState < PRINT_JOB_BLOCKED_UNKNOWN &&
       subState > PRINT_JOB_COMPLETED_FILE_CORRUPT)) {
    subState_ = subState;
  }
}

void PrintJob::SetCopyNumber(uint32_t copyNumber) { copyNumber_ = copyNumber; }

void PrintJob::SetPageRange(const PrintRange &pageRange) {
  pageRange_ = pageRange;
}

void PrintJob::SetIsSequential(bool isSequential) {
  isSequential_ = isSequential;
}

void PrintJob::SetPageSize(const PrintPageSize &pageSize) {
  pageSize_ = pageSize;
}

void PrintJob::SetIsLandscape(bool isLandscape) { isLandscape_ = isLandscape; }

void PrintJob::SetColorMode(uint32_t colorMode) { colorMode_ = colorMode; }

void PrintJob::SetDuplexMode(uint32_t duplexmode) { duplexMode_ = duplexmode; }

void PrintJob::SetMargin(const PrintMargin &margin) {
  if (margin_ != nullptr) {
    *margin_ = margin;
    return;
  }
  margin_ = std::make_shared<PrintMargin>(margin);
}

void PrintJob::SetOption(const std::string &option) { option_ = option; }

void PrintJob::SetPreview(const PrintPreviewAttribute &preview) {
  if (preview_ != nullptr) {
    *preview_ = preview;
    return;
  }
  preview_ = std::make_shared<PrintPreviewAttribute>(preview);
}

void PrintJob::UpdateParams(const PrintJob &jobInfo) {
  files_.clear();
  files_.assign(jobInfo.files_.begin(), jobInfo.files_.end());

  printerId_ = jobInfo.printerId_;
  copyNumber_ = jobInfo.copyNumber_;
  pageRange_ = jobInfo.pageRange_;
  isSequential_ = jobInfo.isSequential_;
  pageSize_ = jobInfo.pageSize_;
  isLandscape_ = jobInfo.isLandscape_;
  colorMode_ = jobInfo.colorMode_;
  duplexMode_ = jobInfo.duplexMode_;
  margin_ = jobInfo.margin_;
  preview_ = jobInfo.preview_;
  option_ = jobInfo.option_;
}

void PrintJob::GetFiles(std::vector<std::string> &files) const {
  files.clear();
  files.assign(files_.begin(), files_.end());
}

const std::string &PrintJob::GetJobId() const { return jobId_; }

const std::string &PrintJob::GetPrinterId() const { return printerId_; }

uint32_t PrintJob::GetJobState() const { return jobState_; }

uint32_t PrintJob::GetSubState() const { return subState_; }

uint32_t PrintJob::GetCopyNumber() const { return copyNumber_; }

void PrintJob::GetPageRange(PrintRange &range) const { range = pageRange_; }

bool PrintJob::GetIsSequential() const { return isSequential_; }
void PrintJob::GetPageSize(PrintPageSize &pageSize) const {
  pageSize = pageSize_;
}

bool PrintJob::GetIsLandscape() const { return isLandscape_; }

uint32_t PrintJob::GetColorMode() const { return colorMode_; }

uint32_t PrintJob::GetDuplexMode() const { return duplexMode_; }

void PrintJob::GetMargin(PrintMargin &margin) const {
  if (margin_ != nullptr) {
    margin = *margin_;
  }
  margin.Reset();
}

void PrintJob::GetPreview(PrintPreviewAttribute &previewAttr) const {
  if (preview_ != nullptr) {
    previewAttr = *preview_;
  }
  previewAttr.Reset();
}

const std::string &PrintJob::GetOption() const { return option_; }

bool PrintJob::ReadFromParcel(Parcel &parcel) {
  if (!parcel.ReadStringVector(&files_)) {
    PRINT_HILOGE("Failed to restore file list");
    return false;
  }
  SetJobId(parcel.ReadString());
  SetPrinterId(parcel.ReadString());
  SetJobState(parcel.ReadUint32());
  SetSubState(parcel.ReadUint32());
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

  // check capability
  margin_ = nullptr;
  if (parcel.ReadBool()) {
    margin_ = PrintMargin::Unmarshalling(parcel);
    if (margin_ == nullptr) {
      PRINT_HILOGE("Failed to restore margin");
      return false;
    }
  }

  preview_ = nullptr;
  if (parcel.ReadBool()) {
    preview_ = PrintPreviewAttribute::Unmarshalling(parcel);
    if (preview_ == nullptr) {
      PRINT_HILOGE("Failed to restore preview attribute");
      return false;
    }
  }

  SetOption("");
  if (parcel.ReadBool()) {
    SetOption(parcel.ReadString());
  }
  return true;
}

bool PrintJob::Marshalling(Parcel &parcel) const {
  if (!parcel.WriteStringVector(files_)) {
    PRINT_HILOGE("Failed to save file list");
    return false;
  }

  if (!parcel.WriteString(GetJobId())) {
    PRINT_HILOGE("Failed to save job id");
    return false;
  }

  if (!parcel.WriteString(GetPrinterId())) {
    PRINT_HILOGE("Failed to save printer id");
    return false;
  }

  if (!parcel.WriteUint32(GetJobState())) {
    PRINT_HILOGE("Failed to save job state");
    return false;
  }

  if (!parcel.WriteUint32(GetSubState())) {
    PRINT_HILOGE("Failed to save job substate");
    return false;
  }

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

  if (margin_ != nullptr) {
    parcel.WriteBool(true);
    margin_->Marshalling(parcel);
  } else {
    parcel.WriteBool(false);
  }

  if (preview_ != nullptr) {
    parcel.WriteBool(true);
    preview_->Marshalling(parcel);
  } else {
    parcel.WriteBool(false);
  }

  if (GetOption() != "") {
    parcel.WriteBool(true);
    parcel.WriteString(GetOption());
  } else {
    parcel.WriteBool(false);
  }

  return true;
}

std::shared_ptr<PrintJob> PrintJob::Unmarshalling(Parcel &parcel) {
  auto nativeObj = std::make_shared<PrintJob>();
  if (nativeObj == nullptr) {
    PRINT_HILOGE("Failed to create print job object");
    return nullptr;
  }
  if (!nativeObj->ReadFromParcel(parcel)) {
    PRINT_HILOGE("Failed to unmarshalling printjob");
    return nullptr;
  }
  return nativeObj;
}

bool PrintJob::CreateFileList(napi_env env, napi_value &jsPrintJob) const {
  napi_value arrFiles = nullptr;
  PRINT_CALL_BASE(env, napi_create_array(env, &arrFiles), false);
  uint32_t arrFilesLength = files_.size();

  for (uint32_t i = 0; i < arrFilesLength; i++) {
    napi_value value;
    PRINT_CALL_BASE(env,
                    napi_create_string_utf8(env, files_[i].c_str(),
                                            NAPI_AUTO_LENGTH, &value),
                    false);
    PRINT_CALL_BASE(env, napi_set_element(env, arrFiles, i, value), false);
  }
  PRINT_CALL_BASE(
      env, napi_set_named_property(env, jsPrintJob, PARAM_JOB_FILES, arrFiles),
      false);
  return true;
}

bool PrintJob::CreatePageRange(napi_env env, napi_value &jsPrintJob) const {
  napi_value jsPageRange = pageRange_.ToJsObject(env);
  PRINT_CALL_BASE(env,
                  napi_set_named_property(env, jsPrintJob, PARAM_JOB_PAGERANGE,
                                          jsPageRange),
                  false);
  return true;
}

bool PrintJob::CreatePageSize(napi_env env, napi_value &jsPrintJob) const {
  napi_value jsPageSize = pageSize_.ToJsObject(env);
  PRINT_CALL_BASE(
      env,
      napi_set_named_property(env, jsPrintJob, PARAM_JOB_PAGESIZE, jsPageSize),
      false);
  return true;
}

bool PrintJob::CreateMargin(napi_env env, napi_value &jsPrintJob) const {
  if (margin_ != nullptr) {
    napi_value jsMargin = margin_->ToJsObject(env);
    PRINT_CALL_BASE(
        env,
        napi_set_named_property(env, jsPrintJob, PARAM_JOB_MARGIN, jsMargin),
        false);
  }
  return true;
}

bool PrintJob::CreatePreview(napi_env env, napi_value &jsPrintJob) const {
  if (preview_ != nullptr) {
    napi_value jsPreview = preview_->ToJsObject(env);
    PRINT_CALL_BASE(
        env,
        napi_set_named_property(env, jsPrintJob, PARAM_JOB_PREVIEW, jsPreview),
        false);
  }
  return true;
}

napi_value PrintJob::ToJsObject(napi_env env) const {
  napi_value jsObj = nullptr;
  PRINT_CALL(env, napi_create_object(env, &jsObj));
  if (!CreateFileList(env, jsObj)) {
    PRINT_HILOGE("Failed to create files property of print job");
    return nullptr;
  }
  NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_JOBID,
                                        GetJobId());
  NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_PRINTERID,
                                        GetPrinterId());
  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_JOBSTATE,
                                    GetJobState());
  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_SUBSTATE,
                                    GetSubState());
  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_COPYNUMBER,
                                    GetCopyNumber());

  if (!CreatePageRange(env, jsObj)) {
    PRINT_HILOGE("Failed to create page range property of print job");
    return nullptr;
  }

  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_ISSEQUENTIAL,
                                    GetIsSequential());

  if (!CreatePageSize(env, jsObj)) {
    PRINT_HILOGE("Failed to create page size property of print job");
    return nullptr;
  }

  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_ISLANDSCAPE,
                                    GetIsLandscape());
  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_COLORMODE,
                                    GetColorMode());
  NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_JOB_DUPLEXMODE,
                                    GetDuplexMode());

  if (!CreateMargin(env, jsObj)) {
    PRINT_HILOGE("Failed to create margin property of print job");
    return nullptr;
  }

  if (!CreatePreview(env, jsObj)) {
    PRINT_HILOGE("Failed to create preview property of print job");
    return nullptr;
  }

  if (GetOption() != "") {
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_JOB_OPTION,
                                          GetOption());
  }
  return jsObj;
}

std::shared_ptr<PrintJob> PrintJob::BuildFromJs(napi_env env,
                                                napi_value jsValue) {
  auto nativeObj = std::make_shared<PrintJob>();
  if (nativeObj == nullptr) {
    PRINT_HILOGE("Failed to create print job object");
    return nullptr;
  }

  if (!ValidateProperty(env, jsValue)) {
    PRINT_HILOGE("Invalid property of print job");
    return nullptr;
  }

  napi_value jsFiles =
      NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_FILES);
  bool isFileArray = false;
  napi_is_array(env, jsFiles, &isFileArray);
  if (!isFileArray) {
    PRINT_HILOGE("Invalid file list of print job");
    return nullptr;
  }
  std::vector<std::string> printFiles;
  uint32_t arrayReLength = 0;
  napi_get_array_length(env, jsFiles, &arrayReLength);
  for (uint32_t index = 0; index < arrayReLength; index++) {
    napi_value filesValue;
    napi_get_element(env, jsFiles, index, &filesValue);
    std::string files = NapiPrintUtils::GetStringFromValueUtf8(env, filesValue);
    PRINT_HILOGD("printJob_value jsFiles %{public}s", files.c_str());
    printFiles.emplace_back(files);
  }
  nativeObj->SetFiles(printFiles);

  std::string jobId =
      NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_JOBID);
  std::string printerId =
      NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_PRINTERID);
  uint32_t jobState =
      NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_JOBSTATE);
  uint32_t subState =
      NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_SUBSTATE);
  uint32_t copyNumber =
      NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_COPYNUMBER);
  bool isSequential =
      NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISSEQUENTIAL);
  bool isLandscape =
      NapiPrintUtils::GetBooleanProperty(env, jsValue, PARAM_JOB_ISLANDSCAPE);
  uint32_t colorMode =
      NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_COLORMODE);
  uint32_t duplexMode =
      NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_JOB_DUPLEXMODE);
  nativeObj->SetJobId(jobId);
  nativeObj->SetPrinterId(printerId);
  nativeObj->SetJobState(jobState);
  nativeObj->SetSubState(subState);
  nativeObj->SetCopyNumber(copyNumber);
  nativeObj->SetIsSequential(isSequential);
  nativeObj->SetIsLandscape(isLandscape);
  nativeObj->SetColorMode(colorMode);
  nativeObj->SetDuplexMode(duplexMode);

  if (jobId == "") {
    PRINT_HILOGE("Invalid job id");
    return nullptr;
  }

  if (jobState >= PRINT_JOB_UNKNOWN || subState > PRINT_JOB_BLOCKED_UNKNOWN) {
    PRINT_HILOGE("Invalid job state[%{public}d] or sub state [%{public}d]",
                 jobState, subState);
    return nullptr;
  }

  napi_value jsPageRange =
      NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PAGERANGE);
  auto pageRangePtr = PrintRange::BuildFromJs(env, jsPageRange);
  if (pageRangePtr == nullptr) {
    PRINT_HILOGE("Failed to build print job object from js");
    return nullptr;
  }
  nativeObj->SetPageRange(*pageRangePtr);

  napi_value jsPageSize =
      NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PAGESIZE);
  auto pageSizePtr = PrintPageSize::BuildFromJs(env, jsPageSize);
  if (pageSizePtr == nullptr) {
    PRINT_HILOGE("Failed to build print job object from js");
    return nullptr;
  }
  nativeObj->SetPageSize(*pageSizePtr);

  napi_value jsMargin =
      NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_MARGIN);
  if (jsMargin != nullptr) {
    auto marginPtr = PrintMargin::BuildFromJs(env, jsMargin);
    if (marginPtr == nullptr) {
      PRINT_HILOGE("Failed to build print job object from js");
      return nullptr;
    }
    nativeObj->SetMargin(*marginPtr);
  }

  napi_value jsPreview =
      NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_PREVIEW);
  if (jsPreview != nullptr) {
    auto previewPtr = PrintPreviewAttribute::BuildFromJs(env, jsPreview);
    if (previewPtr == nullptr) {
      PRINT_HILOGE("Failed to build print job object from js");
      return nullptr;
    }
    nativeObj->SetPreview(*previewPtr);
  }

  napi_value jsOption =
      NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_JOB_OPTION);
  if (jsOption != nullptr) {
    nativeObj->SetOption(
        NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_JOB_OPTION));
  }
  nativeObj->Dump();
  return nativeObj;
}

bool PrintJob::ValidateProperty(napi_env env, napi_value object) {
  std::map<std::string, PrintParamStatus> propertyList = {
      {PARAM_JOB_FILES, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_JOBID, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_PRINTERID, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_JOBSTATE, PRINT_PARAM_OPT},
      {PARAM_JOB_SUBSTATE, PRINT_PARAM_OPT},
      {PARAM_JOB_COPYNUMBER, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_PAGERANGE, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_ISSEQUENTIAL, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_PAGESIZE, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_ISLANDSCAPE, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_COLORMODE, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_DUPLEXMODE, PRINT_PARAM_NOT_SET},
      {PARAM_JOB_MARGIN, PRINT_PARAM_OPT},
      {PARAM_JOB_PREVIEW, PRINT_PARAM_OPT},
      {PARAM_JOB_OPTION, PRINT_PARAM_OPT},
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

void PrintJob::Dump() {
  uint32_t fileLength = files_.size();
  for (uint32_t i = 0; i < fileLength; i++) {
    PRINT_HILOGD("files_ = %{public}s", files_[i].c_str());
  }

  PRINT_HILOGD("jobId_ = %{public}s", jobId_.c_str());
  PRINT_HILOGD("printerId_ = %{public}s", printerId_.c_str());
  PRINT_HILOGD("jobState_ = %{public}d", jobState_);
  PRINT_HILOGD("subState_ = %{public}d", subState_);
  PRINT_HILOGD("copyNumber_ = %{public}d", copyNumber_);
  PRINT_HILOGD("isSequential_ = %{public}d", isSequential_);
  PRINT_HILOGD("isLandscape_ = %{public}d", isLandscape_);
  PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
  PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);

  pageRange_.Dump();
  pageSize_.Dump();
  if (margin_ != nullptr) {
    margin_->Dump();
  }
  if (preview_ != nullptr) {
    preview_->Dump();
  }
  if (option_ != "") {
    PRINT_HILOGD("option: %{public}s", option_.c_str());
  }
}
} // namespace OHOS::Print
