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

#include "print_resolution.h"
#include "print_log.h"

namespace OHOS::Print {
PrintResolution::PrintResolution() : id_(0), horizontalDpi_(0), verticalDpi_(0)
{    
}

PrintResolution::PrintResolution(const PrintResolution& right)
{
    id_ = right.id_;
    horizontalDpi_ = right.horizontalDpi_;
    verticalDpi_ = right.verticalDpi_;
}

PrintResolution& PrintResolution::operator=(const PrintResolution& right)
{
    if(this != &right){
        id_ = right.id_;
        horizontalDpi_ = right.horizontalDpi_;
        verticalDpi_ = right.verticalDpi_;
    }
    return *this;
}

PrintResolution::~PrintResolution()
{
}

void PrintResolution::SetId(uint32_t id)
{
    id_ = id;
}

void PrintResolution::SetHorizontalDpi(uint32_t horizontalDpi)
{
    horizontalDpi_ = horizontalDpi;
}

void PrintResolution::SetVerticalDpi(uint32_t verticalDpi)
{
    verticalDpi_ = verticalDpi;
}

uint32_t PrintResolution::GetId() const
{
    return id_;
}

uint32_t PrintResolution::GetHorizontalDpi() const
{
    return horizontalDpi_;
}

uint32_t PrintResolution::GetVerticalDpi() const
{
    return verticalDpi_;
}

void PrintResolution::Dump()
{
    PRINT_HILOGD("id_ = %{public}d", id_);
    PRINT_HILOGD("horizontalDpi_ = %{public}d", horizontalDpi_);
    PRINT_HILOGD("verticalDpi_ = %{public}d", verticalDpi_);
}
} // namespace OHOS::Print
