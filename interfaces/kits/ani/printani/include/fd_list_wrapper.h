
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef FD_LIST_WRAPPER_H
#define FD_LIST_WRAPPER_H

#include <vector>
#include <stdint.h>

namespace OHOS::Print {
class FdListWrapper {
public:
    FdListWrapper() = default;
    ~FdListWrapper();

    void Add(uint32_t fd);

    const std::vector<uint32_t>& Get() const;

    void ReleaseAll();

private:
    std::vector<uint32_t> fdList_;
    static constexpr uint32_t INVALID_FD = static_cast<uint32_t>(-1);
};

} // namespace OHOS::Print

#endif  // FD_LIST_WRAPPER_H