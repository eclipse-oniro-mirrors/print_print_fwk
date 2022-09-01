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

