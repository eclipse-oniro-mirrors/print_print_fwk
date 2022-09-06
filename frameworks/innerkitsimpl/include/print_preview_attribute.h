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
#ifndef PRINT_PREVIEW_ATTRIBUTE_H
#define PRINT_PREVIEW_ATTRIBUTE_H

#include <cstdint>
#include <string>

#include "print_range.h"
namespace OHOS::Print {
class PreviewAttribute {
public:
    explicit PreviewAttribute();
    PreviewAttribute(const PreviewAttribute &right);
    PreviewAttribute &operator=(const PreviewAttribute &previewAttribute);
    ~PreviewAttribute();

    void SetResult(const std::string &result);

    void SetPreviewRange(const PrintRange &previewRange);

    [[nodiscard]] const std::string &GetResult() const;

    void GetPreviewRange(PrintRange &range) const;

    void Dump();

private:
    std::string result_;
    PrintRange previewRange_;
};
} // namespace OHOS::Print
#endif // PRINT_PREVIEW_ATTRIBUTE_H