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

#ifndef JS_PRINT_EXTENSION_H
#define JS_PRINT_EXTENSION_H

#include <mutex>

#include "napi/native_api.h"
#include "print_extension.h"
#include "print_job.h"

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class PrintExtension;
class JsRuntime;

struct WorkParam {
    napi_env env;
    std::string funcName;
    std::string printerId;
    Print::PrintJob job;
    WorkParam(napi_env env, std::string funcName) : env(env), funcName(funcName)
    {}
};

/**
 * @brief Basic Print components.
 */
class JsPrintExtension : public PrintExtension, public std::enable_shared_from_this<JsPrintExtension> {
public:
    JsPrintExtension(JsRuntime &jsRuntime);
    virtual ~JsPrintExtension() override;

    /**
     * @brief Create JsPrintExtension.
     *
     * @param runtime The runtime.
     * @return The JsPrintExtension instance.
     */
    static JsPrintExtension *Create(const std::unique_ptr<Runtime> &runtime);

    /**
     * @brief Init the extension.
     *
     * @param record the extension record.
     * @param application the application info.
     * @param handler the extension handler.
     * @param token the remote token.
     */
    virtual void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler, const sptr<IRemoteObject> &token) override;

    /**
     * @brief Called when this extension is started. You must override this function if you want to perform some
     *        initialization operations during extension startup.
     *
     * This function can be called only once in the entire lifecycle of an extension.
     * @param Want Indicates the {@link Want} structure containing startup information about the extension.
     */
    virtual void OnStart(const AAFwk::Want &want) override;

    /**
     * @brief Called when this Print extension is connected for the first time.
     *
     * You can override this function to implement your own processing logic.
     *
     * @param want Indicates the {@link Want} structure containing connection information about the Print extension.
     * @return Returns a pointer to the <b>sid</b> of the connected Print extension.
     */
    virtual sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;

    /**
     * @brief Called when all abilities connected to this Print extension are disconnected.
     *
     * You can override this function to implement your own processing logic.
     *
     */
    virtual void OnDisconnect(const AAFwk::Want &want) override;

    /**
     * @brief Called back when Print is started.
     * This method can be called only by Print. You can use the StartAbility(ohos.aafwk.content.Want) method
     * to start Print. Then the system calls back the current method to use the transferred want parameter
     * to execute its own logic.
     *
     * @param want Indicates the want of Print to start.
     * @param restart Indicates the startup mode. The value true indicates that Print is restarted after being
     * destroyed, and the value false indicates a normal startup.
     * @param startId Indicates the number of times the Print extension has been started. The startId is incremented
     * by 1 every time the extension is started. For example, if the extension has been started for six times, the
     * value of startId is 6.
     */
    virtual void OnCommand(const AAFwk::Want &want, bool restart, int startId) override;

    /**
     * @brief Called when this extension enters the <b>STATE_STOP</b> state.
     *
     * The extension in the <b>STATE_STOP</b> is being destroyed.
     * You can override this function to implement your own processing logic.
     */
    virtual void OnStop() override;

private:
    napi_value CallObjectMethod(const char *name, napi_value const *argv = nullptr, size_t argc = 0);
    bool InitExtensionObj(JsRuntime &jsRuntime);
    bool InitContextObj(JsRuntime &jsRuntime, napi_value &extObj, std::string &extensionId);
    bool Callback(const std::string funcName);
    bool Callback(const std::string funcName, const std::string &printerId);
    bool Callback(const std::string funcName, const Print::PrintJob &job);
    void RegisterDiscoveryCb();
    void RegisterConnectionCb();
    void RegisterPrintJobCb();
    void RegisterPreviewCb();
    void RegisterQueryCapCb();
    void RegisterExtensionCb();
    void RegisterCb();

    void GetSrcPath(std::string &srcPath);

    JsRuntime &jsRuntime_;
    std::unique_ptr<NativeReference> jsObj_;
    static JsPrintExtension *jsExtension_;
    static std::mutex mtx;
    std::string extensionId_;
    bool hasDestroyed_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // JS_PRINT_EXTENSION_H