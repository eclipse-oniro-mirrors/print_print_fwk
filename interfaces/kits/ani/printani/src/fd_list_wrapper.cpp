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
#include "fd_list_wrapper.h"
#include "securec.h"
#include "print_log.h"

namespace OHOS::Print {

FdListWrapper::~FdListWrapper()
{
    ReleaseAll();
}

bool FdListWrapper::Add(uint32_t fd)
{
    if (fd == INVALID_FD || fd <= STD_FD_MAX) {
        PRINT_HILOGE("invalid fd: %{public}u", fd);
        return false;
    }
    fdList_.emplace_back(fd);
    return true;
}

const std::vector<uint32_t>& FdListWrapper::Get() const
{
    return fdList_;
}

void FdListWrapper::ReleaseAll()
{
    for (auto fd : fdList_) {
        if (fd == INVALID_FD || fd <= STD_FD_MAX) {
            PRINT_HILOGW("skip invalid or std fd: %{public}u", fd);
            continue;
        }
        fdsan_close_with_tag(fd, PRINT_LOG_DOMAIN);
    }
    fdList_.clear();
}

} // namespace OHOS::Print