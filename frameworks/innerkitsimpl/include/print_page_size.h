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

#ifndef PRINT_PAGESIZE_H
#define PRINT_PAGESIZE_H

#include <map>
#include <mutex>
#include <string>

namespace OHOS::Print {
class PrinterPageSize  {
public:
    PrinterPageSize();

    void SetId(uint32_t id);

    void SetName(const std::string &name);

    void SetWidth(uint32_t width);

    void SetHeight(uint32_t height);

    [[nodiscard]] uint32_t GetId() const;

    [[nodiscard]] std::string &GetName();

    [[nodiscard]] uint32_t GetWidth() const;

    [[nodiscard]] uint32_t GetHeight() const;
    
    PrinterPageSize &operator=(const PrinterPageSize &printerPageSize);

    void Dump();

    ~PrinterPageSize ();
    
private:
    uint32_t id_;
    std::string name_;
    uint32_t width_;
    uint32_t height_;
};
} // namespace OHOS::Print
#endif // PRINT_PAGESIZE_H
