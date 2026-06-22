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

#ifndef THREAD_SYNC_WAIT_H
#define THREAD_SYNC_WAIT_H

#include <mutex>
#include <thread>

namespace OHOS {
namespace Print {
class ThreadSyncWait {
public:
    static const int WAIT_INFINETE = -1;
    static const int WAIT_NONE = 0;
    void Wait(int timeout);
    void Notify();

private:
    std::mutex waitMutex;
    std::condition_variable waitCondition;
};
}  // namespace Print
}  // namespace OHOS
#endif  // THREAD_SYNC_WAIT_H
