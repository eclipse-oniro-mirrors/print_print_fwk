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

#include "print_page_size.h"
#include "log.h"

namespace OHOS::Print {
PrinterPageSize::PrinterPageSize () 
: id_(0), name_("PrinterPageSize"), width_(0), height_(0) {
    
}

void PrinterPageSize::SetId(uint32_t id)
{
    id_ = id;
}

void PrinterPageSize::SetName(const std::string &name)
{
    name_ = name;
}

void PrinterPageSize::SetWidth(uint32_t width)
{
    width_ = width;
}

void PrinterPageSize::SetHeight(uint32_t height)
{
    height_ = height;
}

uint32_t PrinterPageSize::GetId() const
{
    return id_;
}

std::string &PrinterPageSize::GetName()
{
    return name_;
}

uint32_t PrinterPageSize::GetWidth() const
{
    return width_;
}

uint32_t PrinterPageSize::GetHeight() const
{
    return height_;
}

PrinterPageSize &PrinterPageSize::operator=(const PrinterPageSize &printerPageSize)
{
    if(this != &printerPageSize){
        this->id_ = printerPageSize.id_;
        this->name_ = printerPageSize.name_;
        this->width_ = printerPageSize.width_;
        this->height_ = printerPageSize.height_;  
    }
    return *this;
}

void PrinterPageSize::Dump()
{
    PRINT_HILOGD("top_ = %{public}d", id_);
    PRINT_HILOGD("name_ = %{public}s", name_.c_str());
    PRINT_HILOGD("width_ = %{public}d", width_);
    PRINT_HILOGD("height_ = %{public}d", height_);
}

PrinterPageSize ::~PrinterPageSize ()
{

}

} // namespace OHOS::Print
