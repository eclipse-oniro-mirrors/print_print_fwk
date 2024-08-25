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

#include "operation_queue.h"
#include "print_log.h"

using namespace OHOS::Print;

void OperationQueue::Run()
{
    bool expectRunning = false;
    if (!isRunning.compare_exchange_strong(expectRunning, true)) {
        PRINT_HILOGW("Operation queue is running");
        return;
    }
    opThread = std::thread([this]() {
        while (isRunning) {
            std::function<void()> op = Pop();
            if (op != nullptr) {
                op();
            } else {
                syncWait.Wait(ThreadSyncWait::WAIT_INFINETE);
            }
        }
    });
}
void OperationQueue::Stop()
{
    bool expectRunning = true;
    if (!isRunning.compare_exchange_strong(expectRunning, false)) {
        PRINT_HILOGW("Operation queue is not running");
        return;
    }
    syncWait.Notify();
    if (opThread.joinable()) {
        opThread.join();
    }
    {
        std::lock_guard<std::mutex> lock(listMutex);
        opList.clear();
    }
}

bool OperationQueue::Push(std::function<void()> op)
{
    if (!isRunning.load()) {
        PRINT_HILOGW("Operation queue is not running");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(listMutex);
        if (opList.size() >= maxCount) {
            PRINT_HILOGW("Operation queue full");
            opList.pop_back();
        }
        opList.push_front(op);
    }
    syncWait.Notify();
    return true;
}

std::function<void()> OperationQueue::Pop()
{
    std::lock_guard<std::mutex> lock(listMutex);
    if (opList.empty()) {
        return nullptr;
    }
    std::function<void()> op = opList.back();
    opList.pop_back();
    return op;
}
