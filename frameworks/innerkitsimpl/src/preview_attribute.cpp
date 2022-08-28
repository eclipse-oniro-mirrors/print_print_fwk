#include "preview_attribute.h"
#include "log.h"
#include <cstdint>
#include <string>
namespace OHOS::Print{
PreviewAttribute::PreviewAttribute()
{

}

PreviewAttribute::~PreviewAttribute()
{

}

void PreviewAttribute::SetResult(const std::string& result)
{
    result_ = result;
}

void PreviewAttribute::SetPreviewRange(PrinterRange previewRange)
{
    previewRange_ = previewRange;
}

const std::string& PreviewAttribute::GetResult() const
{
    return result_;
}

PrinterRange PreviewAttribute::GetPreviewRange() const
{
    return previewRange_;
}

void PreviewAttribute::Dump()
{
    PRINT_HILOGD("result_: %{public}s", result_.c_str());
}
}

