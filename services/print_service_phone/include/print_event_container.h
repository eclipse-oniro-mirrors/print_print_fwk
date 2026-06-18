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

#ifndef PRINT_EVENT_CONTAINER_H
#define PRINT_EVENT_CONTAINER_H

#include <string>
#include <vector>
#include <map>
#include <mutex.h>

namespace OHOS::Print {
class PrintEventContainer {
public:
    PrintEventContainer(const std::string &id);
    void AddEventCode(const std::string &type, int32_t code);
    void ClearEventType(const std::string &type);
    std::string AnalyzeEventCodes(const std::string &type);
private:
    std::mutex eventTypeMapMutex_;
    std::string printerId_;
    std::map<std::string, std::shared_ptr<std::vector<int32_t>>> eventTypeMap_;
};
} // namespace OHOS::Print
#endif // PRINT_EVENT_CONTAINER_H
