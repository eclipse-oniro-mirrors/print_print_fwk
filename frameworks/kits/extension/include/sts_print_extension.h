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

#ifndef OHOS_STS_PRINT_EXTENSION_H
#define OHOS_STS_PRINT_EXTENSION_H

#include <ani.h>
#include "ets_native_reference.h"
#include "ets_runtime.h"
#include "print_extension.h"
#include "print_extension_context.h"
#include "print_job.h"

class STSNativeReference;

namespace OHOS {
namespace AbilityRuntime {

class StsPrintExtension : public PrintExtension {
public:
    explicit StsPrintExtension(ETSRuntime& etsRuntime);
    virtual ~StsPrintExtension() override;

    static StsPrintExtension* Create(const std::unique_ptr<Runtime>& etsRuntime);
    virtual void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;
    void ResetEnv(ani_env* env);
    virtual void OnStart(const AAFwk::Want &want) override;
    virtual void OnStop() override;
    virtual sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;
    virtual void OnDisconnect(const AAFwk::Want &want) override;
    virtual void OnCommand(const AAFwk::Want &want, bool restart, int startId) override;

private:
    virtual void BindContext(ani_env *env, std::shared_ptr<AAFwk::Want> want,
        const std::shared_ptr<OHOSApplication> &application);
    ani_object CreateSTSContext(ani_env *env, std::shared_ptr<PrintExtensionContext> context,
        int32_t screenMode, const std::shared_ptr<OHOSApplication> &application);
    ani_object CreateStsPrintExtensionContext(ani_env *env,
        std::shared_ptr<PrintExtensionContext> context,
        const std::shared_ptr<OHOS::AppExecFwk::OHOSApplication> &application);
    void BindExtensionInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
        std::shared_ptr<OHOS::AbilityRuntime::Context> context,
        std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo);
    bool Callback(const std::string& funcName);
    bool Callback(const std::string& funcName, const std::string &printerId);
    bool Callback(const std::string& funcName, const Print::PrintJob &job);
    bool CallObjectMethod(bool withResult, const char* name, const char* signature, ...);
    void RegisterDiscoveryCb();
    void RegisterConnectionCb();
    void RegisterPrintJobCb();
    void RegisterPreviewCb();
    void RegisterQueryCapCb();
    void RegisterExtensionCb();
    void RegisterCb();

    ETSRuntime& etsRuntime_;
    sptr<IRemoteObject> token_ = nullptr;
    std::shared_ptr<AppExecFwk::ETSNativeReference> etsObj_ = nullptr;
    static StsPrintExtension *stsExtension_;
    std::string extensionId_;
};

}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_STS_PRINT_EXTENSION_H
