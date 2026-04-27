/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef PRINT_MAP_SAFE_H
#define PRINT_MAP_SAFE_H

#include <map>
#include <mutex>
#include <vector>

namespace OHOS {
namespace Print {
template <typename T>
class PrintMapSafe {
public:
    bool Insert(const std::string &key, const T &value)
    {
        if (key.empty()) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mapMutex);
        printMap.insert(std::make_pair(key, std::make_shared<T>(value)));
        return true;
    }
    bool Insert(const std::string &key, std::shared_ptr<T> value)
    {
        if (key.empty()) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mapMutex);
        printMap.insert(std::make_pair(key, value));
        return true;
    }
    bool Remove(const std::string &key)
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        auto it = printMap.find(key);
        if (it == printMap.end()) {
            return false;
        }
        printMap.erase(it);
        return true;
    }
    void Clear()
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        printMap.clear();
    }
    std::shared_ptr<T> Find(const std::string &key)
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        auto it = printMap.find(key);
        if (it == printMap.end()) {
            return nullptr;
        }
        return it->second;
    }
    std::string FindKey(std::function<bool(const T &)> comp)
    {
        if (comp == nullptr) {
            return "";
        }
        std::lock_guard<std::mutex> lock(mapMutex);
        for (const auto &pair : printMap) {
            if (pair.second == nullptr) {
                continue;
            }
            if (comp(*(pair.second))) {
                return pair.first;
            }
        }
        return "";
    }
    size_t Count()
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        return printMap.size();
    }
    std::vector<std::string> GetKeyList()
    {
        std::vector<std::string> list;
        std::lock_guard<std::mutex> lock(mapMutex);
        for (const auto &pair : printMap) {
            if (pair.second == nullptr) {
                continue;
            }
            list.push_back(pair.first);
        }
        return list;
    }

    std::vector<std::string> GetKeyList(std::function<bool(const T &)> comp)
    {
        std::vector<std::string> list;
        if (comp == nullptr) {
            return list;
        }
        std::lock_guard<std::mutex> lock(mapMutex);
        for (const auto &pair : printMap) {
            if (pair.second == nullptr) {
                continue;
            }
            if (!comp(*(pair.second))) {
                continue;
            }
            list.push_back(pair.first);
        }
        return list;
    }

private:
    std::mutex mapMutex;
    std::map<std::string, std::shared_ptr<T>> printMap;
};
}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_MAP_SAFE_H
