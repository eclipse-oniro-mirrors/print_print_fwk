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

#ifndef PRINT_UTILS_H
#define PRINT_UTILS_H

#include <string>
#include "want.h"
#include "bundle_mgr_client.h"
#include "print_constant.h"
#include "print_log.h"
#include <json/json.h>
#include <mutex>
#include "print_json_util.h"

#include <print_attributes.h>

namespace OHOS::Print {
struct AdapterParam {
    std::string documentName;
    bool isCheckFdList;
    PrintAttributes printAttributes;
    std::string jobId;
};

class PrintUtils {
public:
    static std::string ToLower(const std::string &s);
    static std::string GetExtensionId(const std::string &globalId);
    static std::string GetGlobalId(const std::string &extensionId, const std::string &localId);
    static std::string GetLocalId(const std::string &globalId, const std::string &extensionId);
    static std::string EncodeExtensionCid(const std::string &extensionId, uint32_t callbackId);
    static bool DecodeExtensionCid(const std::string &cid, std::string &extensionId, uint32_t &callbackId);
    static std::string GetTaskEventId(const std::string &taskId, const std::string &type);
    static int32_t OpenFile(const std::string &filePath);
    static bool IsPathValid(const std::string &filePath);
    static uint32_t GetIdFromFdPath(const std::string &fdPath);
    static std::string GetJobStateChar(const uint32_t state);

    static void BuildAdapterParam(const std::shared_ptr<AdapterParam> &adapterParam, AAFwk::Want &want);
    static void BuildPrintAttributesParam(const std::shared_ptr<AdapterParam> &adapterParam, AAFwk::Want &want);
    static void ParseAttributesObjectParamForJson(const PrintAttributes &attrParam, Json::Value &attrJson);
    static std::string GetBundleNameForUid(const int uid);
    static std::string GetPrintJobId();
    static std::string GetEventTypeWithToken(int32_t userId, int64_t pid, const std::string &type);
    static std::string GetEventType(const std::string &type);
    static bool CheckUserIdInEventType(const std::string &type, int32_t callerUserId);
    template <typename T, typename ReadFunc>
    static bool readListFromParcel(Parcel &parcel, std::vector<T> &supportedList, const ReadFunc &readFunc)
    {
        uint32_t vecSize = parcel.ReadUint32();
        CHECK_IS_EXCEED_PRINT_RANGE_BOOL(vecSize);
        supportedList.clear();
        supportedList.reserve(vecSize);  // Allocate the required memory all at once to speed up processing efficiency.
        for (uint32_t index = 0; index < vecSize; index++) {
            auto item = readFunc(parcel);
            if (item.has_value()) {
                supportedList.emplace_back(std::move(*item));
            } else {
                PRINT_HILOGE("Failed on the %{public}d-th read of the list.", index);
                return false;
            }
        }
        return true;
    }
    template <typename T, typename ReadFunc>
    static bool readListFromParcel(Parcel &parcel, std::vector<T> &supportedList, const ReadFunc &readFunc,
                                   bool *hasSupportedPtr)
    {
        if (hasSupportedPtr) {
            *hasSupportedPtr = parcel.ReadBool();
            if (*hasSupportedPtr) {
                return readListFromParcel(parcel, supportedList, readFunc);
            }
        } else {
            PRINT_HILOGE("Func readListFromParcel error! Ptr: hasSupportedPtr is null");
            return false;
        }
        return true;
    }

    template <typename T, typename WriteFunc>
    static void WriteListToParcel(Parcel &parcel, const std::vector<T> &list, WriteFunc writeFunc)
    {
        uint32_t vecSize = static_cast<uint32_t>(list.size());
        parcel.WriteUint32(vecSize);
        for (uint32_t index = 0; index < vecSize; index++) {
            writeFunc(parcel, list[index]);
        }
    }
    template <typename T, typename WriteFunc>
    static void WriteListToParcel(Parcel &parcel, const std::vector<T> &list, WriteFunc writeFunc, bool hasFlag)
    {
        parcel.WriteBool(hasFlag);
        if (hasFlag) {
            WriteListToParcel(parcel, list, writeFunc);
        }
    }

    template<typename T>
    static bool CheckJsonType(const Json::Value &j)
    {
        if constexpr (std::is_same_v<T, int> || std::is_same_v<T, unsigned int> || std::is_same_v<T, uint32_t>) {
            return j.isInt();
        } else if constexpr (std::is_same_v<T, std::string>) {
            return j.isString();
        } else if constexpr (std::is_same_v<T, bool>) {
            return j.isBool();
        } else {
            return true; // For complex types, we'll do the check in the conversion function
        }
    }

private:
    static Json::Value GetPageRangeForJson(const PrintAttributes &attrParam);
    static Json::Value GetPageSizeForJson(const PrintAttributes &attrParam);
    static Json::Value GetMarginForJson(const PrintAttributes &attrParam);

private:
    static std::mutex instanceLock_;
};
}  // namespace OHOS::Print
#endif  // PRINT_UTILS_H
