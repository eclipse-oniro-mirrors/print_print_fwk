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

#include "print_event_container.h"
#include "print_json_util.h"

namespace OHOS::Print {
PrintEventContainer::PrintEventContainer(const std::string &id) : printerId(id) {}

void PrintEventContainer::AddEventCode(const std::string &type, int32_t code)
{
    auto iter = eventTypeMap.find(type);
    if (iter == eventTypeMap.end() || iter->second == nullptr) {
        std::shared_ptr<std::vector<int32_t>> events = std::make_shared<std::vector<int32_t>>();
        events->push_back(code);
        eventTypeMap[type] = events;
    } else {
        iter->second->push_back(code);
    }
}

void PrintEventContainer::ClearEventType(const std::string &type)
{
    auto iter = eventTypeMap.find(type);
    if (iter != eventTypeMap.end() && iter->second != nullptr) {
        iter->second->clear();
    }
}

std::string PrintEventContainer::AnalyzeEventCodes(const std::string &type)
{
    Json::Value json;
    json["printerId"] = printerId;
    json["type"] = type;
    int32_t code = 0;
    auto iter = eventTypeMap.find(type);
    if (iter != eventTypeMap.end()) {
        auto events = iter->second;
        if (events != nullptr && !events->empty()) {
            code = events->front();
        }
    }
    json["code"] = code;
    return PrintJsonUtil::WriteString(json);
}
}
