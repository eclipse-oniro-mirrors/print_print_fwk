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
#ifndef SAFE_SANE_API_H
#define SAFE_SANE_API_H

#include <mutex>
#include <shared_mutex>
#include "sane/sane.h"

namespace OHOS {
namespace Scan {

class SafeSANEAPI {
public:
    static SafeSANEAPI& GetInstance();
    
    SafeSANEAPI(const SafeSANEAPI&) = delete;
    SafeSANEAPI& operator=(const SafeSANEAPI&) = delete;
    
    SANE_Status SaneInit(SANE_Int* version, SANE_Auth_Callback authorize);
    
    void SaneExit();
    
    SANE_Status SaneGetDevices(const SANE_Device*** deviceList, SANE_Bool localOnly);
    
    SANE_Status SaneOpen(const char* device_name, SANE_Handle* handle);
    
    void SaneClose(SANE_Handle handle);
    
    SANE_Status SaneStart(SANE_Handle handle);
    
    void SaneCancel(SANE_Handle handle);
    
    const SANE_Option_Descriptor* SaneGetOptionDescriptor(SANE_Handle handle, SANE_Int option);
    
    SANE_Status SaneGetParameters(SANE_Handle handle, SANE_Parameters* params);
    
    SANE_Status SaneControlOption(SANE_Handle handle, SANE_Int option,
        SANE_Action action, void* value, SANE_Int* info);
    
    SANE_Status SaneRead(SANE_Handle handle, SANE_Byte* data,
        SANE_Int maxLength, SANE_Int* length);

private:
    SafeSANEAPI() = default;
    ~SafeSANEAPI() = default;
    
    std::mutex initLock_;
    std::shared_mutex handleLock_;
};

} // namespace Scan
} // namespace OHOS

#endif // SAFE_SANE_API_H