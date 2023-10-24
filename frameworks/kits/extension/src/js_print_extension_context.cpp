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

#include "js_print_extension_context.h"

#include "js_data_struct_converter.h"
#include "js_extension_context.h"
#include "js_print_extension_connection.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_start_options.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_print_utils.h"
#include "napi_remote_object.h"
#include "print_log.h"
#include "start_options.h"
#include <shared_mutex>

using namespace OHOS::Print;
using noneType = void*;

namespace OHOS {
namespace AbilityRuntime {
static constexpr int32_t E_PRINT_INVALID_CONTEXT = 1;
static constexpr int32_t E_PRINT_INVALID_CONNECTION = 2;

class JsPrintExtensionContext final {
public:
    explicit JsPrintExtensionContext(const std::shared_ptr<PrintExtensionContext>& context) : context_(context) {}
    ~JsPrintExtensionContext() = default;

    static void Finalizer(napi_env engine, noneType data, noneType hint)
    {
        PRINT_HILOGD("JsAbilityContext::Finalizer is called");
        std::unique_ptr<JsPrintExtensionContext>(static_cast<JsPrintExtensionContext*>(data));
    }

    static napi_value StartAbility(napi_env engine, napi_callback_info info)
    {
        JsPrintExtensionContext* me = CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
        return (me != nullptr) ? me->OnStartAbility(engine, info) : nullptr;
    }

    static napi_value StartAbilityWithAccount(napi_env engine, napi_callback_info info)
    {
        JsPrintExtensionContext* me = CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
        return (me != nullptr) ? me->OnStartAbilityWithAccount(engine, info) : nullptr;
    }

    static napi_value ConnectAbilityWithAccount(napi_env engine, napi_callback_info info)
    {
        JsPrintExtensionContext* me = CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
        return (me != nullptr) ? me->OnConnectAbilityWithAccount(engine, info) : nullptr;
    }

    static napi_value TerminateAbility(napi_env engine, napi_callback_info info)
    {
        JsPrintExtensionContext* me = CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
        return (me != nullptr) ? me->OnTerminateAbility(engine, info) : nullptr;
    }

    static napi_value ConnectAbility(napi_env engine, napi_callback_info info)
    {
        JsPrintExtensionContext* me = CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
        return (me != nullptr) ? me->OnConnectAbility(engine, info) : nullptr;
    }

    static napi_value DisconnectAbility(napi_env engine, napi_callback_info info)
    {
        JsPrintExtensionContext* me = CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
        return (me != nullptr) ? me->OnDisconnectAbility(engine, info) : nullptr;
    }

private:
    std::weak_ptr<PrintExtensionContext> context_;
    std::shared_timed_mutex managersMutex_;

    napi_value GetUndefinedValue(napi_env &engine)
    {
        PRINT_HILOGE("params count or value is error");
        napi_value undefineResult = nullptr;
        napi_get_undefined(engine, &undefineResult);
        return undefineResult;
    }

    napi_valuetype GetNapiValueType(napi_env &engine, napi_value &argv)
    {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(engine, argv, &valueType);
        return valueType;
    }

    napi_value OnStartAbility(napi_env &engine, napi_callback_info &info)
    {
        PRINT_HILOGD("OnStartAbility is called");
        size_t argc = NapiPrintUtils::MAX_ARGC;
        napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
        napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
        if (argc != NapiPrintUtils::ARGC_ONE && argc != NapiPrintUtils::ARGC_TWO &&
            argc != NapiPrintUtils::ARGC_THREE) {
            return GetUndefinedValue(engine);
        }

        decltype(argc) unwrapArgc = 0;
        AAFwk::Want want;
        OHOS::AppExecFwk::UnwrapWant(engine, argv[NapiPrintUtils::INDEX_ZERO], want);
        PRINT_HILOGD("%{public}s bundlename:%{public}s abilityname:%{public}s", __func__, want.GetBundle().c_str(),
            want.GetElement().GetAbilityName().c_str());
        unwrapArgc++;

        AAFwk::StartOptions startOptions;
        if (argc > NapiPrintUtils::ARGC_ONE && GetNapiValueType(engine, argv[1]) == napi_object) {
            PRINT_HILOGD("OnStartAbility start options is used.");
            AppExecFwk::UnwrapStartOptions(engine, argv[1], startOptions);
            unwrapArgc++;
        }

        NapiAsyncTask::CompleteCallback complete = [weak = context_, want, startOptions, unwrapArgc](
                                                   napi_env engine, NapiAsyncTask &task, int32_t status) {
            PRINT_HILOGD("startAbility begin");
            auto context = weak.lock();
            if (!context) {
                PRINT_HILOGW("context is released");
                    task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT, "Context is released"));
                return;
            }

            ErrCode errcode = ERR_OK;
            (unwrapArgc == 1) ? errcode = context->StartAbility(want)
                              : errcode = context->StartAbility(want, startOptions);
            if (errcode == 0) {
                napi_value undefineResult = nullptr;
                napi_get_undefined(engine, &undefineResult);
                task.Resolve(engine, undefineResult);
            } else {
                task.Reject(engine, CreateJsError(engine, errcode, "Start Ability failed."));
            }
        };

        napi_value lastParam = (argc == unwrapArgc) ? nullptr : argv[unwrapArgc];
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("PrintExtensionContext::OnStartAbility", engine,
            CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnStartAbilityWithAccount(napi_env &engine, napi_callback_info &info)
    {
        size_t argc = NapiPrintUtils::MAX_ARGC;
        napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
        napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
        if (argc != NapiPrintUtils::ARGC_TWO && argc != NapiPrintUtils::ARGC_THREE &&
            argc != NapiPrintUtils::ARGC_FOUR) {
            return GetUndefinedValue(engine);
        }

        decltype(argc) unwrapArgc = 0;
        AAFwk::Want want;
        OHOS::AppExecFwk::UnwrapWant(engine, argv[0], want);
        PRINT_HILOGD("%{public}s bundlename:%{public}s abilityname:%{public}s", __func__, want.GetBundle().c_str(),
            want.GetElement().GetAbilityName().c_str());
        unwrapArgc++;

        int32_t accountId = 0;
        if (!OHOS::AppExecFwk::UnwrapInt32FromJS2(engine, argv[1], accountId)) {
            return GetUndefinedValue(engine);
        }
        PRINT_HILOGD("%{public}d accountId:", accountId);
        unwrapArgc++;

        AAFwk::StartOptions startOptions;
        if (static_cast<uint32_t>(argc) > NapiPrintUtils::INDEX_TWO &&
            GetNapiValueType(engine, argv[NapiPrintUtils::INDEX_TWO]) == napi_object) {
            AppExecFwk::UnwrapStartOptions(engine, argv[NapiPrintUtils::INDEX_TWO], startOptions);
            unwrapArgc++;
        }

        NapiAsyncTask::CompleteCallback complete = [weak = context_, want, accountId, startOptions, unwrapArgc](
                                                   napi_env engine, NapiAsyncTask &task, int32_t status) {
            auto context = weak.lock();
            if (!context) {
                task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT, "Context is released"));
                return;
            }

            ErrCode errcode = ERR_OK;
            (unwrapArgc == NapiPrintUtils::ARGC_TWO) ? errcode = context->StartAbilityWithAccount(want, accountId)
                : errcode = context->StartAbilityWithAccount(want, accountId, startOptions);
            if (errcode == 0) {
                napi_value undefineResult = nullptr;
                napi_get_undefined(engine, &undefineResult);
                task.Resolve(engine, undefineResult);
            } else {
                task.Reject(engine, CreateJsError(engine, errcode, "Start Ability failed."));
            }
        };

        napi_value lastParam = (argc == unwrapArgc) ? nullptr : argv[unwrapArgc];
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("PrintExtensionContext::OnStartAbilityWithAccount", engine,
            CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnTerminateAbility(napi_env &engine, napi_callback_info &info)
    {
        PRINT_HILOGD("OnTerminateAbility is called");
        size_t argc = NapiPrintUtils::MAX_ARGC;
        napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
        napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
        if (argc != NapiPrintUtils::ARGC_ZERO && argc != NapiPrintUtils::ARGC_ONE) {
            return GetUndefinedValue(engine);
        }

        NapiAsyncTask::CompleteCallback complete = [weak = context_](
                                                   napi_env engine, NapiAsyncTask &task, int32_t status) {
            PRINT_HILOGD("TerminateAbility begin");
            auto context = weak.lock();
            if (!context) {
                PRINT_HILOGW("context is released");
                task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT, "Context is released"));
                return;
            }

            auto errcode = context->TerminateAbility();
            if (errcode == 0) {
                napi_value undefineResult = nullptr;
                napi_get_undefined(engine, &undefineResult);
                task.Resolve(engine, undefineResult);
            } else {
                task.Reject(engine, CreateJsError(engine, errcode, "Terminate Ability failed."));
            }
        };

        napi_value lastParam = (argc == NapiPrintUtils::ARGC_ZERO) ? nullptr : argv[0];
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("PrintExtensionContext::OnTerminateAbility", engine,
            CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }

    napi_value OnConnectAbility(napi_env &engine, napi_callback_info &info)
    {
        PRINT_HILOGD("OnConnectAbility is called");
        size_t argc = NapiPrintUtils::MAX_ARGC;
        napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
        napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
        if (argc != NapiPrintUtils::ARGC_TWO) {
            return GetUndefinedValue(engine);
        }

        AAFwk::Want want;
        OHOS::AppExecFwk::UnwrapWant(engine, argv[0], want);
        PRINT_HILOGD("%{public}s bundlename:%{public}s abilityname:%{public}s", __func__, want.GetBundle().c_str(),
            want.GetElement().GetAbilityName().c_str());

        sptr<JSPrintExtensionConnection> connection = new JSPrintExtensionConnection(engine);
        connection->SetJsConnectionObject(argv[1]);
        int64_t connectId = serialNumber_;
        ConnecttionKey key;
        key.id = serialNumber_;
        key.want = want;
        std::unique_lock<std::shared_timed_mutex> lock(managersMutex_);
        connects_.emplace(key, connection);
        (serialNumber_ < INT64_MAX) ? serialNumber_++ : serialNumber_ = 0;
        NapiAsyncTask::CompleteCallback complete = [weak = context_, want, connection, connectId](
                                                   napi_env engine, NapiAsyncTask &task, int32_t status) {
            PRINT_HILOGD("OnConnectAbility begin");
            auto context = weak.lock();
            if (!context) {
                PRINT_HILOGW("context is released");
                    task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT, "Context is released"));
                return;
            }
            PRINT_HILOGD("context->ConnectAbility connection:%{public}d", (int32_t)connectId);
            if (!context->ConnectAbility(want, connection)) {
                    connection->CallJsFailed(E_PRINT_INVALID_CONTEXT);
            }
            napi_value undefineResult = nullptr;
            napi_get_undefined(engine, &undefineResult);
            task.Resolve(engine, undefineResult);
        };
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("PrintExtensionContext::OnConnectAbility", engine,
            CreateAsyncTaskWithLastParam(engine, nullptr, nullptr, std::move(complete), &result));
        napi_value numberResult = nullptr;
        napi_create_double(engine, connectId, &numberResult);
        return numberResult;
    }

    napi_value OnConnectAbilityWithAccount(napi_env &engine, napi_callback_info &info)
    {
        PRINT_HILOGD("OnConnectAbilityWithAccount is called");
        size_t argc = NapiPrintUtils::MAX_ARGC;
        napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
        napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
        if (argc != NapiPrintUtils::ARGC_THREE) {
            return GetUndefinedValue(engine);
        }

        AAFwk::Want want;
        OHOS::AppExecFwk::UnwrapWant(engine, argv[0], want);
        PRINT_HILOGD("%{public}s bundlename:%{public}s abilityname:%{public}s", __func__, want.GetBundle().c_str(),
            want.GetElement().GetAbilityName().c_str());

        int32_t accountId = 0;
        if (!OHOS::AppExecFwk::UnwrapInt32FromJS2(engine, argv[1], accountId)) {
            PRINT_HILOGD("%{public}s called, the second parameter is invalid.", __func__);
            return GetUndefinedValue(engine);
        }

        sptr<JSPrintExtensionConnection> connection = new JSPrintExtensionConnection(engine);
        connection->SetJsConnectionObject(argv[1]);
        int64_t connectId = serialNumber_;
        ConnecttionKey key;
        key.id = serialNumber_;
        key.want = want;
        std::unique_lock<std::shared_timed_mutex> lock(managersMutex_);
        connects_.emplace(key, connection);
        (serialNumber_ < INT64_MAX) ? serialNumber_++ : serialNumber_ = 0;
        NapiAsyncTask::CompleteCallback complete = [weak = context_, want, accountId, connection, connectId](
                                                   napi_env engine, NapiAsyncTask &task, int32_t status) {
            PRINT_HILOGD("OnConnectAbilityWithAccount begin");
            auto context = weak.lock();
            if (!context) {
                PRINT_HILOGW("context is released");
                task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT, "Context is released"));
                return;
            }
            PRINT_HILOGD("context->ConnectAbilityWithAccount connection:%{public}d", (int32_t)connectId);
            if (!context->ConnectAbilityWithAccount(want, accountId, connection)) {
                connection->CallJsFailed(E_PRINT_INVALID_CONTEXT);
            }
            napi_value undefineResult = nullptr;
            napi_get_undefined(engine, &undefineResult);
            task.Resolve(engine, undefineResult);
        };
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("PrintExtensionContext::OnConnectAbilityWithAccount", engine,
            CreateAsyncTaskWithLastParam(engine, nullptr, nullptr, std::move(complete), &result));
        napi_value numberResult = nullptr;
        napi_create_double(engine, connectId, &numberResult);
        return numberResult;
    }

    napi_value OnDisconnectAbility(napi_env &engine, napi_callback_info &info)
    {
        PRINT_HILOGD("OnDisconnectAbility is called");
        size_t argc = NapiPrintUtils::MAX_ARGC;
        napi_value argv[NapiPrintUtils::MAX_ARGC] = { nullptr };
        napi_get_cb_info(engine, info, &argc, argv, nullptr, nullptr);
        if (argc != NapiPrintUtils::ARGC_ONE && argc != NapiPrintUtils::ARGC_TWO) {
            return GetUndefinedValue(engine);
        }

        AAFwk::Want want;
        int64_t connectId = -1;
        sptr<JSPrintExtensionConnection> connection = nullptr;
        napi_get_value_int64(engine, argv[NapiPrintUtils::INDEX_ZERO], &connectId);
        PRINT_HILOGD("OnDisconnectAbility connection:%{public}d", static_cast<int32_t>(connectId));
        auto item = std::find_if(connects_.begin(), connects_.end(),
            [&connectId](const std::map<ConnecttionKey, sptr<JSPrintExtensionConnection>>::value_type &obj) {
                return connectId == obj.first.id;
            });
        if (item != connects_.end()) {
            // match id
            want = item->first.want;
            connection = item->second;
        } else {
            PRINT_HILOGD("%{public}s not find conn exist.", __func__);
        }
        NapiAsyncTask::CompleteCallback complete = [weak = context_, want, connection](
                                                   napi_env engine, NapiAsyncTask &task, int32_t status) {
            PRINT_HILOGD("OnDisconnectAbility begin");
            auto context = weak.lock();
            if (!context) {
                PRINT_HILOGW("context is released");
                task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT, "Context is released"));
                return;
            }
            if (connection == nullptr) {
                PRINT_HILOGW("connection nullptr");
                task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONNECTION, "not found connection"));
                return;
            }
            PRINT_HILOGD("context->DisconnectAbility");
            auto errcode = context->DisconnectAbility(want, connection);
            napi_value undefineResult = nullptr;
            napi_get_undefined(engine, &undefineResult);
            errcode == 0 ? task.Resolve(engine, undefineResult)
                         : task.Reject(engine, CreateJsError(engine, errcode, "Disconnect Ability failed."));
        };

        napi_value lastParam = (argc == NapiPrintUtils::ARGC_ONE) ? nullptr : argv[1];
        napi_value result = nullptr;
        NapiAsyncTask::Schedule("PrintExtensionContext::OnDisconnectAbility", engine,
            CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
        return result;
    }
};

napi_value CreateJsMetadata(napi_env &engine, const AppExecFwk::Metadata &Info)
{
    PRINT_HILOGD("CreateJsMetadata");
    napi_value object = nullptr;
    napi_create_object(engine, &object);

    napi_set_named_property(engine, object, "name", CreateJsValue(engine, Info.name));
    napi_set_named_property(engine, object, "value", CreateJsValue(engine, Info.value));
    napi_set_named_property(engine, object, "resource", CreateJsValue(engine, Info.resource));
    return object;
}

napi_value CreateJsMetadataArray(napi_env &engine, const std::vector<AppExecFwk::Metadata> &info)
{
    PRINT_HILOGD("CreateJsMetadataArray");
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(engine, info.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &item : info) {
        napi_set_element(engine, arrayValue, index++, CreateJsMetadata(engine, item));
    }
    return arrayValue;
}

napi_value CreateJsExtensionAbilityInfoMessage(napi_env &engine, const AppExecFwk::ExtensionAbilityInfo &info)
{
    PRINT_HILOGD("CreateJsExtensionAbilityInfoMessage");
    napi_value object = nullptr;
    napi_create_object(engine, &object);
    napi_set_named_property(engine, object, "bundleName", CreateJsValue(engine, info.bundleName));
    napi_set_named_property(engine, object, "moduleName", CreateJsValue(engine, info.moduleName));
    napi_set_named_property(engine, object, "name", CreateJsValue(engine, info.name));
    napi_set_named_property(engine, object, "labelId", CreateJsValue(engine, info.labelId));
    napi_set_named_property(engine, object, "descriptionId", CreateJsValue(engine, info.descriptionId));
    napi_set_named_property(engine, object, "iconId", CreateJsValue(engine, info.iconId));
    napi_set_named_property(engine, object, "isVisible", CreateJsValue(engine, info.visible));
    napi_set_named_property(engine, object, "extensionAbilityType", CreateJsValue(engine, info.type));

    napi_value permissionArrayValue = nullptr;
    napi_create_array_with_length(engine, info.permissions.size(), &permissionArrayValue);
    if (permissionArrayValue != nullptr) {
        uint32_t index = 0;
        for (auto permission : info.permissions) {
            napi_set_element(engine, permissionArrayValue, index++, CreateJsValue(engine, permission));
        }
    }
    napi_set_named_property(engine, object, "permissions", permissionArrayValue);
    napi_set_named_property(engine, object, "applicationInfo", CreateJsApplicationInfo(engine, info.applicationInfo));
    napi_set_named_property(engine, object, "metadata", CreateJsMetadataArray(engine, info.metadata));
    napi_set_named_property(engine, object, "enabled", CreateJsValue(engine, info.enabled));
    napi_set_named_property(engine, object, "readPermission", CreateJsValue(engine, info.readPermission));
    napi_set_named_property(engine, object, "writePermission", CreateJsValue(engine, info.writePermission));
    return object;
}

napi_value CreateJsPrintExtensionContext(napi_env engine,
    std::shared_ptr<PrintExtensionContext> context, std::string &extensionId)
{
    PRINT_HILOGD("CreateJsPrintExtensionContext begin");
    napi_value objValue = CreateJsExtensionContext(engine, context);
    napi_value object = objValue;

    std::unique_ptr<JsPrintExtensionContext> jsContext = std::make_unique<JsPrintExtensionContext>(context);
    napi_wrap(engine, object, jsContext.release(), JsPrintExtensionContext::Finalizer, nullptr, nullptr);

    // make handler
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    const char *moduleName = "JsPrintExtensionContext";
    BindNativeFunction(engine, object, "startAbility", moduleName, JsPrintExtensionContext::StartAbility);
    BindNativeFunction(engine, object, "terminateSelf", moduleName, JsPrintExtensionContext::TerminateAbility);
    BindNativeFunction(engine, object, "connectAbility", moduleName, JsPrintExtensionContext::ConnectAbility);
    BindNativeFunction(engine, object, "disconnectAbility", moduleName, JsPrintExtensionContext::DisconnectAbility);
    BindNativeFunction(
        engine, object, "startAbilityWithAccount", moduleName, JsPrintExtensionContext::StartAbilityWithAccount);
    BindNativeFunction(
        engine, object, "connectAbilityWithAccount", moduleName, JsPrintExtensionContext::ConnectAbilityWithAccount);
    if (context) {
        PRINT_HILOGD("Set ExtensionAbilityInfo Property");
        auto abilityInfo = context->GetAbilityInfo();
        auto hapModuleInfo = context->GetHapModuleInfo();
        if (abilityInfo && hapModuleInfo) {
            extensionId = abilityInfo->bundleName;
            PRINT_HILOGD("Set ExtensionAbilityInfo Property: extensionId = %{public}s", extensionId.c_str());
            auto isExist = [&abilityInfo](const AppExecFwk::ExtensionAbilityInfo &info) {
                PRINT_HILOGD("%{public}s, %{public}s", info.bundleName.c_str(), info.name.c_str());
                return info.bundleName == abilityInfo->bundleName && info.name == abilityInfo->name;
            };
            auto infoIter =
                std::find_if(hapModuleInfo->extensionInfos.begin(), hapModuleInfo->extensionInfos.end(), isExist);
            if (infoIter == hapModuleInfo->extensionInfos.end()) {
                PRINT_HILOGD("Get target fail.");
                return objValue;
            }
            napi_set_named_property(engine, object,
                "extensionAbilityInfo", CreateJsExtensionAbilityInfoMessage(engine, *infoIter));
        }
    }

    return objValue;
}
} // namespace AbilityRuntime
} // namespace OHOS
