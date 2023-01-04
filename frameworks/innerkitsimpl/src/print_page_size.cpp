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
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_PAGESIZE_ID = "id";
static constexpr const char *PARAM_PAGESIZE_NAME = "name";
static constexpr const char *PARAM_PAGESIZE_WIDTH = "width";
static constexpr const char *PARAM_PAGESIZE_HEIGHT = "height";

std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>> PrintPageSize::pageSize_;
void PrintPageSize::BuildPageSizeMap()
{
    PRINT_HILOGD("");
}

PrintPageSize::PrintPageSize() : id_(""), name_("PrintPageSize"), width_(0), height_(0) {}

PrintPageSize::PrintPageSize(PAGE_SIZE_ID id, DiscretePageName name, uint32_t width, uint32_t height)
{
    id_ = id;
    name_ = name;
    width_ = width;
    height_ = height;
}

PrintPageSize PrintPageSize::GetPageSize(PageSizeId id)
{
    uint32_t pageSizeId = (uint32_t)id;
    if (pageSizeId < (uint32_t)sizeof(PAGE_SIZE_TABLE)) {
        auto iter = pageSize_.find(PAGE_SIZE_TABLE[pageSizeId]);
        if (iter != pageSize_.end()) {
            return *(iter->second);
        }
    }
    PrintPageSize printPageSize;
    return printPageSize;
}

PrintPageSize::PrintPageSize(const PrintPageSize &right)
{
    id_ = right.id_;
    name_ = right.name_;
    width_ = right.width_;
    height_ = right.height_;
}

PrintPageSize &PrintPageSize::operator=(const PrintPageSize &right)
{
    if (this != &right) {
        id_ = right.id_;
        name_ = right.name_;
        width_ = right.width_;
        height_ = right.height_;
    }
    return *this;
}

PrintPageSize::~PrintPageSize()
{
}

void PrintPageSize::Reset()
{
    SetId("");
    SetName("");
    SetWidth(0);
    SetHeight(0);
}

void PrintPageSize::SetId(const std::string &id)
{
    id_ = id;
}

void PrintPageSize::SetName(const std::string &name)
{
    name_ = name;
}

void PrintPageSize::SetWidth(uint32_t width)
{
    width_ = width;
}

void PrintPageSize::SetHeight(uint32_t height)
{
    height_ = height;
}

const std::string &PrintPageSize::GetId() const
{
    return id_;
}

const std::string &PrintPageSize::GetName() const
{
    return name_;
}

uint32_t PrintPageSize::GetWidth() const
{
    return width_;
}

uint32_t PrintPageSize::GetHeight() const
{
    return height_;
}

bool PrintPageSize::ReadFromParcel(Parcel &parcel)
{
    SetId(parcel.ReadString());
    SetName(parcel.ReadString());
    SetWidth(parcel.ReadUint32());
    SetHeight(parcel.ReadUint32());
    return true;
}

bool PrintPageSize::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetId());
    parcel.WriteString(GetName());
    parcel.WriteUint32(GetWidth());
    parcel.WriteUint32(GetHeight());
    return true;
}

std::shared_ptr<PrintPageSize> PrintPageSize::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintPageSize>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print page size object");
        return nullptr;
    }
    if (!nativeObj->ReadFromParcel(parcel)) {
        PRINT_HILOGE("Failed to unmarshalling print page size");
        return nullptr;
    }
    return nativeObj;
}

napi_value PrintPageSize::ToJsObject(napi_env env) const
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));

    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_PAGESIZE_ID, GetId());
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_PAGESIZE_NAME, GetName());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_PAGESIZE_WIDTH, GetWidth());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_PAGESIZE_HEIGHT, GetHeight());
    return jsObj;
}

std::shared_ptr<PrintPageSize> PrintPageSize::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintPageSize>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print range object");
        return nullptr;
    }

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print page size");
        return nullptr;
    }

    std::string id = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_PAGESIZE_ID);
    std::string name = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_PAGESIZE_NAME);
    uint32_t width = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_PAGESIZE_WIDTH);
    uint32_t height = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_PAGESIZE_HEIGHT);

    if (id == "") {
        PRINT_HILOGE("Invalid resolution id");
        return nullptr;
    }

    nativeObj->SetId(id);
    nativeObj->SetName(name);
    nativeObj->SetWidth(width);
    nativeObj->SetHeight(height);
    PRINT_HILOGE("Build Page Size succeed");
    return nativeObj;
}

bool PrintPageSize::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_PAGESIZE_ID, PRINT_PARAM_NOT_SET},
        {PARAM_PAGESIZE_NAME, PRINT_PARAM_NOT_SET},
        {PARAM_PAGESIZE_WIDTH, PRINT_PARAM_NOT_SET},
        {PARAM_PAGESIZE_HEIGHT, PRINT_PARAM_NOT_SET},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = PRINT_PARAM_SET;
    }

    for (auto propertypItem : propertyList) {
        if (propertypItem.second == PRINT_PARAM_NOT_SET) {
            PRINT_HILOGE("Missing Property: %{public}s", propertypItem.first.c_str());
            return false;
        }
    }

    return true;
}

void PrintPageSize::Dump()
{
    PRINT_HILOGD("id_ = %{public}s", id_.c_str());
    PRINT_HILOGD("name_ = %{public}s", name_.c_str());
    PRINT_HILOGD("width_ = %{public}d", width_);
    PRINT_HILOGD("height_ = %{public}d", height_);
}
} // namespace OHOS::Print
