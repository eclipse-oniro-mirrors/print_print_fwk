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

#ifndef OPERATION_QUEUE_H
#define OPERATION_QUEUE_H

#include <list>
#include <thread>
#include <atomic>
#include "thread_sync_wait.h"

namespace OHOS {
namespace Print {
class OperationQueue {
public:
    void Run();
    void Stop();
    bool Push(std::function<void()> op);

private:
    std::function<void()> Pop();

private:
    std::thread opThread;
    std::list<std::function<void()>> opList;
    std::mutex listMutex;
    std::atomic<bool> isRunning{ false };
    size_t maxCount = 100;
    ThreadSyncWait syncWait;
};
}  // namespace Print
}  // namespace OHOS
#endif  // OPERATION_QUEUE_H
