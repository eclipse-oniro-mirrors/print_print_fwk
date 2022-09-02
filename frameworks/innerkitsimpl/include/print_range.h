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

#ifndef PRINT_RANGE_H
#define PRINT_RANGE_H

#include <string>
#include <vector>

namespace OHOS::Print {
class PrintRange{
public:
    explicit PrintRange();
    PrintRange(const PrintRange& right);
    PrintRange &operator=(const PrintRange& right);
    ~PrintRange();

    void SetStartPage(uint32_t startPage);

    void SetEndPage(uint32_t endPage);

    void SetPages(const std::vector<uint32_t>& pages);

    void Reset();

    [[nodiscard]]uint32_t GetStartPage() const;

    [[nodiscard]]uint32_t GetEndPage() const;
        
    void GetPages(std::vector<uint32_t>& pages) const;

    void Dump();
private:
    uint32_t startPage_;
    uint32_t endPage_;
    std::vector<uint32_t> pages_;
};
}// namespace OHOS::Print
#endif // PRINT_RANGE_H