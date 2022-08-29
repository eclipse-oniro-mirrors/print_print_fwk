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
#include "log.h"

namespace OHOS::Print {
PrinterResolution::PrinterResolution() 
: id_(0), horizontalDpi_(0), verticalDpi_(0) {
    
}

void PrinterResolution::SetId(uint32_t id)
{
    id_ = id;
}

void PrinterResolution::SetHorizontalDpi(uint32_t horizontalDpi)
{
    horizontalDpi_ = horizontalDpi;
}

void PrinterResolution::SetVerticalDpi(uint32_t verticalDpi)
{
    verticalDpi_ = verticalDpi;
}

uint32_t PrinterResolution::GetId() const
{
    return id_;
}

uint32_t PrinterResolution::GetHorizontalDpi() const
{
    return horizontalDpi_;
}

uint32_t PrinterResolution::GetVerticalDpi() const
{
    return verticalDpi_;
}

PrinterResolution &PrinterResolution::operator=(const PrinterResolution &printerResolution)
{
    if(this != &printerResolution){
        this->id_ = printerResolution.id_;
        this->horizontalDpi_ = printerResolution.horizontalDpi_;
        this->verticalDpi_ = printerResolution.verticalDpi_;
    }
    return *this;
}

void PrinterResolution::Dump()
{
    PRINT_HILOGD("id_ = %{public}d", id_);
    PRINT_HILOGD("horizontalDpi_ = %{public}d", horizontalDpi_);
    PRINT_HILOGD("verticalDpi_ = %{public}d", verticalDpi_);
}

PrinterResolution ::~PrinterResolution ()
{

}
} // namespace OHOS::Print
