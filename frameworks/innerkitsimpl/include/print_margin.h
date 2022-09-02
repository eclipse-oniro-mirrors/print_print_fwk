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

#ifndef PRINT_MARGIN_H
#define PRINT_MARGIN_H

#include <map>
#include <mutex>
#include <string>

namespace OHOS::Print {
class PrintMargin  {
public:
    explicit PrintMargin();
    PrintMargin(const PrintMargin& right);
    PrintMargin &operator=(const PrintMargin& right);
    ~PrintMargin();

    void SetTop(uint32_t top);

    void SetBottom(uint32_t bottom);

    void SetLeft(uint32_t left);

    void SetRight(uint32_t right);

    [[nodiscard]] uint32_t GetTop() const;

    [[nodiscard]] uint32_t GetBottom() const;

    [[nodiscard]] uint32_t GetLeft() const;

    [[nodiscard]] uint32_t GetRight() const;
    
    void Dump();
private:
    uint32_t top_;
    uint32_t bottom_;
    uint32_t left_;
    uint32_t right_;
};
} // namespace OHOS::Print
#endif // PRINT_MARGIN_H
