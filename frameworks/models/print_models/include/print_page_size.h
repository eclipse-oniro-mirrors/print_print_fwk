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
#include "parcel.h"
 #include <json/json.h>

namespace OHOS::Print {
const double HUNDRED_OF_MILLIMETRE_TO_INCH = 39.37;
const uint32_t ONE_THOUSAND_INCH = 1000;
const uint32_t ONE_HUNDRED = 100;
const uint32_t PAGE_SIZE_UNIT_LENGTH = 2;
const std::string CUSTOM_PREFIX = "Custom.";
using DiscreteId = std::string;
using DiscretePageName = std::string;
using PAGE_SIZE_ID = std::string;

class PrintPageSize final : public Parcelable {
public:
    static void BuildPageSizeMap();
    static PAGE_SIZE_ID MatchPageSize(const std::string& pageString);
    static bool FindPageSizeById(const PAGE_SIZE_ID &id, PrintPageSize& pageSize);

    explicit PrintPageSize();

    PrintPageSize(PAGE_SIZE_ID id, DiscretePageName name, uint32_t width, uint32_t height);

    PrintPageSize(const PrintPageSize &right);

    PrintPageSize &operator=(const PrintPageSize &right);

    bool operator==(const PrintPageSize &right);

    virtual ~PrintPageSize();

    void Reset();

    [[nodiscard]] const std::string &GetId() const;

    [[nodiscard]] const std::string &GetName() const;

    [[nodiscard]] uint32_t GetWidth() const;

    [[nodiscard]] uint32_t GetHeight() const;

    void SetId(const std::string &id);

    void SetName(const std::string &name);

    void SetWidth(uint32_t width);

    void SetHeight(uint32_t height);

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrintPageSize> Unmarshalling(Parcel &parcel);

    void Dump();

    Json::Value ConvertToJsonObject() const;

    bool ConvertToPwgStyle();

    bool ConvertToCustomStyle();

private:
    void ReadFromParcel(Parcel &parcel);

private:
    std::string id_;
    std::string name_;
    uint32_t width_;
    uint32_t height_;
    static std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>> pageSize_;
    static std::mutex pageSizeMapMutex;
};
} // namespace OHOS::Print
#endif // PRINT_PAGESIZE_H
