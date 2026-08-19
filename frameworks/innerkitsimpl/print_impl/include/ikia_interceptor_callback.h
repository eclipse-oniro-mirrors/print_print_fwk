/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef IKIA_INTERCEPTOR_CALLBACK_H
#define IKIA_INTERCEPTOR_CALLBACK_H

#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS::Print {
class IKiaInterceptorCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Print.IKiaInterceptorCallback");

    virtual bool OnCheckPrintJobNeedReject(const int32_t &pid, const std::string &callerAppId) = 0;
};

enum {
    KIA_INTERCEPTOR_CALLBACK_CHECK_REJECT,
};
} // namespace OHOS::Print
#endif // IKIA_INTERCEPTOR_CALLBACK_H
