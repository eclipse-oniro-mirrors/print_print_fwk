#include "print_preview_attribute.h"

#include "print_log.h"
namespace OHOS::Print {
PreviewAttribute::PreviewAttribute() : result_("") {}

PreviewAttribute::PreviewAttribute(const PreviewAttribute &right) {}

PreviewAttribute &PreviewAttribute::operator=(const PreviewAttribute &right) {
  if (this != &right) {
    result_ = right.result_;
    previewRange_ = right.previewRange_;
  }
  return *this;
}

PreviewAttribute::~PreviewAttribute() {}

void PreviewAttribute::SetResult(const std::string &result) {
  result_ = result;
}

void PreviewAttribute::SetPreviewRange(const PrintRange &previewRange) {
  previewRange_ = previewRange;
}

const std::string &PreviewAttribute::GetResult() const { return result_; }

void PreviewAttribute::GetPreviewRange(PrintRange &range) const {
  range = previewRange_;
}

void PreviewAttribute::Dump() {
  PRINT_HILOGD("result_: %{public}s", result_.c_str());
  previewRange_.Dump();
}
} // namespace OHOS::Print
