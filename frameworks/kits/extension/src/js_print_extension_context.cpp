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

using namespace OHOS::Print;

namespace OHOS {
namespace AbilityRuntime {
static constexpr int32_t E_PRINT_INVALID_CONTEXT = 1;
static constexpr int32_t E_PRINT_INVALID_CONNECTION = 2;

class JsPrintExtensionContext final {
public:
  explicit JsPrintExtensionContext(
      const std::shared_ptr<PrintExtensionContext> &context)
      : context_(context) {}
  ~JsPrintExtensionContext() = default;

  static void Finalizer(NativeEngine *engine, void *data, void *hint) {
    PRINT_HILOGD("JsAbilityContext::Finalizer is called");
    std::unique_ptr<JsPrintExtensionContext>(
        static_cast<JsPrintExtensionContext *>(data));
  }

  static NativeValue *StartAbility(NativeEngine *engine,
                                   NativeCallbackInfo *info) {
    JsPrintExtensionContext *me =
        CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
    return (me != nullptr) ? me->OnStartAbility(*engine, *info) : nullptr;
  }

  static NativeValue *StartAbilityWithAccount(NativeEngine *engine,
                                              NativeCallbackInfo *info) {
    JsPrintExtensionContext *me =
        CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
    return (me != nullptr) ? me->OnStartAbilityWithAccount(*engine, *info)
                           : nullptr;
  }

  static NativeValue *ConnectAbilityWithAccount(NativeEngine *engine,
                                                NativeCallbackInfo *info) {
    JsPrintExtensionContext *me =
        CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
    return (me != nullptr) ? me->OnConnectAbilityWithAccount(*engine, *info)
                           : nullptr;
  }

  static NativeValue *TerminateAbility(NativeEngine *engine,
                                       NativeCallbackInfo *info) {
    JsPrintExtensionContext *me =
        CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
    return (me != nullptr) ? me->OnTerminateAbility(*engine, *info) : nullptr;
  }

  static NativeValue *ConnectAbility(NativeEngine *engine,
                                     NativeCallbackInfo *info) {
    JsPrintExtensionContext *me =
        CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
    return (me != nullptr) ? me->OnConnectAbility(*engine, *info) : nullptr;
  }

  static NativeValue *DisconnectAbility(NativeEngine *engine,
                                        NativeCallbackInfo *info) {
    JsPrintExtensionContext *me =
        CheckParamsAndGetThis<JsPrintExtensionContext>(engine, info);
    return (me != nullptr) ? me->OnDisconnectAbility(*engine, *info) : nullptr;
  }

private:
  std::weak_ptr<PrintExtensionContext> context_;

  NativeValue *OnStartAbility(NativeEngine &engine, NativeCallbackInfo &info) {
    PRINT_HILOGD("OnStartAbility is called");
    // only support one or two or three params
    if (info.argc != NapiPrintUtils::ARGC_ONE &&
        info.argc != NapiPrintUtils::ARGC_TWO &&
        info.argc != NapiPrintUtils::ARGC_THREE) {
      PRINT_HILOGE("Not enough params");
      return engine.CreateUndefined();
    }

    decltype(info.argc) unwrapArgc = 0;
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(
        reinterpret_cast<napi_env>(&engine),
        reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_ZERO]),
        want);
    PRINT_HILOGD("%{public}s bundlename:%{public}s abilityname:%{public}s",
                 __func__, want.GetBundle().c_str(),
                 want.GetElement().GetAbilityName().c_str());
    unwrapArgc++;

    AAFwk::StartOptions startOptions;
    if (info.argc > NapiPrintUtils::ARGC_ONE &&
        info.argv[NapiPrintUtils::INDEX_ONE]->TypeOf() == NATIVE_OBJECT) {
      PRINT_HILOGD("OnStartAbility start options is used.");
      AppExecFwk::UnwrapStartOptions(
          reinterpret_cast<napi_env>(&engine),
          reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_ONE]),
          startOptions);
      unwrapArgc++;
    }

    AsyncTask::CompleteCallback complete = [weak = context_, want, startOptions,
                                            unwrapArgc](NativeEngine &engine,
                                                        AsyncTask &task,
                                                        int32_t status) {
      PRINT_HILOGD("startAbility begin");
      auto context = weak.lock();
      if (!context) {
        PRINT_HILOGW("context is released");
        task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT,
                                          "Context is released"));
        return;
      }

      ErrCode errcode = ERR_OK;
      (unwrapArgc == 1) ? errcode = context->StartAbility(want)
                        : errcode = context->StartAbility(want, startOptions);
      if (errcode == 0) {
        task.Resolve(engine, engine.CreateUndefined());
      } else {
        task.Reject(engine,
                    CreateJsError(engine, errcode, "Start Ability failed."));
      }
    };

    NativeValue *lastParam =
        (info.argc == unwrapArgc) ? nullptr : info.argv[unwrapArgc];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("PrintExtensionContext::OnStartAbility", engine,
                        CreateAsyncTaskWithLastParam(engine, lastParam, nullptr,
                                                     std::move(complete),
                                                     &result));
    return result;
  }

  NativeValue *CheckInfo(NativeEngine &engine, NativeCallbackInfo &info) {
    PRINT_HILOGD("OnStartAbilityWithAccount is called");
    // only support two or three or four params
    if (info.argc != NapiPrintUtils::ARGC_TWO &&
        info.argc != NapiPrintUtils::ARGC_THREE &&
        info.argc != NapiPrintUtils::ARGC_FOUR) {
      PRINT_HILOGE("Not enough params");
      return engine.CreateUndefined();
    }
    return nullptr;
  }

  NativeValue *OnStartAbilityWithAccount(NativeEngine &engine,
                                         NativeCallbackInfo &info) {
    CheckInfo(engine, info);
    decltype(info.argc) unwrapArgc = 0;
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(
        reinterpret_cast<napi_env>(&engine),
        reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_ZERO]),
        want);
    PRINT_HILOGD("%{public}s bundlename:%{public}s abilityname:%{public}s",
                 __func__, want.GetBundle().c_str(),
                 want.GetElement().GetAbilityName().c_str());
    unwrapArgc++;

    int32_t accountId = 0;
    if (!OHOS::AppExecFwk::UnwrapInt32FromJS2(
            reinterpret_cast<napi_env>(&engine),
            reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_ONE]),
            accountId)) {
      PRINT_HILOGD("%{public}s called, the second parameter is invalid.",
                   __func__);
      return engine.CreateUndefined();
    }
    PRINT_HILOGD("%{public}d accountId:", accountId);
    unwrapArgc++;

    AAFwk::StartOptions startOptions;
    if (info.argc > NapiPrintUtils::ARGC_TWO &&
        info.argv[NapiPrintUtils::INDEX_TWO]->TypeOf() == NATIVE_OBJECT) {
      PRINT_HILOGD("OnStartAbilityWithAccount start options is used.");
      AppExecFwk::UnwrapStartOptions(
          reinterpret_cast<napi_env>(&engine),
          reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_TWO]),
          startOptions);
      unwrapArgc++;
    }

    AsyncTask::CompleteCallback complete =
        [weak = context_, want, accountId, startOptions,
         unwrapArgc](NativeEngine &engine, AsyncTask &task, int32_t status) {
          PRINT_HILOGD("startAbility begin");
          auto context = weak.lock();
          if (!context) {
            PRINT_HILOGW("context is released");
            task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT,
                                              "Context is released"));
            return;
          }

          ErrCode errcode = ERR_OK;
          (unwrapArgc == NapiPrintUtils::ARGC_TWO)
              ? errcode = context->StartAbilityWithAccount(want, accountId)
              : errcode = context->StartAbilityWithAccount(want, accountId,
                                                           startOptions);
          if (errcode == 0) {
            task.Resolve(engine, engine.CreateUndefined());
          } else {
            task.Reject(engine, CreateJsError(engine, errcode,
                                              "Start Ability failed."));
          }
        };

    NativeValue *lastParam =
        (info.argc == unwrapArgc) ? nullptr : info.argv[unwrapArgc];
    NativeValue *result = nullptr;
    AsyncTask::Schedule(
        "PrintExtensionContext::OnStartAbilityWithAccount", engine,
        CreateAsyncTaskWithLastParam(engine, lastParam, nullptr,
                                     std::move(complete), &result));
    return result;
  }

  NativeValue *OnTerminateAbility(NativeEngine &engine,
                                  NativeCallbackInfo &info) {
    PRINT_HILOGD("OnTerminateAbility is called");
    // only support one or zero params
    if (info.argc != NapiPrintUtils::ARGC_ZERO &&
        info.argc != NapiPrintUtils::ARGC_ONE) {
      PRINT_HILOGE("Not enough params");
      return engine.CreateUndefined();
    }

    AsyncTask::CompleteCallback complete =
        [weak = context_](NativeEngine &engine, AsyncTask &task,
                          int32_t status) {
          PRINT_HILOGD("TerminateAbility begin");
          auto context = weak.lock();
          if (!context) {
            PRINT_HILOGW("context is released");
            task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT,
                                              "Context is released"));
            return;
          }

          auto errcode = context->TerminateAbility();
          if (errcode == 0) {
            task.Resolve(engine, engine.CreateUndefined());
          } else {
            task.Reject(engine, CreateJsError(engine, errcode,
                                              "Terminate Ability failed."));
          }
        };

    NativeValue *lastParam = (info.argc == NapiPrintUtils::ARGC_ZERO)
                                 ? nullptr
                                 : info.argv[NapiPrintUtils::INDEX_ZERO];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("PrintExtensionContext::OnTerminateAbility", engine,
                        CreateAsyncTaskWithLastParam(engine, lastParam, nullptr,
                                                     std::move(complete),
                                                     &result));
    return result;
  }

  NativeValue *OnConnectAbility(NativeEngine &engine,
                                NativeCallbackInfo &info) {
    PRINT_HILOGD("OnConnectAbility is called");
    // only support two params
    if (info.argc != NapiPrintUtils::ARGC_TWO) {
      PRINT_HILOGE("Not enough params");
      return engine.CreateUndefined();
    }

    // unwrap want
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(
        reinterpret_cast<napi_env>(&engine),
        reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_ZERO]),
        want);
    PRINT_HILOGD("%{public}s bundlename:%{public}s abilityname:%{public}s",
                 __func__, want.GetBundle().c_str(),
                 want.GetElement().GetAbilityName().c_str());
    // unwarp connection
    sptr<JSPrintExtensionConnection> connection =
        new JSPrintExtensionConnection(engine);
    connection->SetJsConnectionObject(info.argv[1]);
    int64_t connectId = serialNumber_;
    ConnecttionKey key;
    key.id = serialNumber_;
    key.want = want;
    connects_.emplace(key, connection);
    if (serialNumber_ < INT64_MAX) {
      serialNumber_++;
    } else {
      serialNumber_ = 0;
    }
    PRINT_HILOGD("%{public}s not find connection, make new one:%{public}p.",
                 __func__, connection.GetRefPtr());
    AsyncTask::CompleteCallback complete =
        [weak = context_, want, connection,
         connectId](NativeEngine &engine, AsyncTask &task, int32_t status) {
          PRINT_HILOGD("OnConnectAbility begin");
          auto context = weak.lock();
          if (!context) {
            PRINT_HILOGW("context is released");
            task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT,
                                              "Context is released"));
            return;
          }
          PRINT_HILOGD("context->ConnectAbility connection:%{public}d",
                       (int32_t)connectId);
          if (!context->ConnectAbility(want, connection)) {
            connection->CallJsFailed(E_PRINT_INVALID_CONTEXT);
          }
          task.Resolve(engine, engine.CreateUndefined());
        };
    NativeValue *result = nullptr;
    AsyncTask::Schedule("PrintExtensionContext::OnConnectAbility", engine,
                        CreateAsyncTaskWithLastParam(engine, nullptr, nullptr,
                                                     std::move(complete),
                                                     &result));
    return engine.CreateNumber(connectId);
  }

  NativeValue *OnConnectAbilityWithAccount(NativeEngine &engine,
                                           NativeCallbackInfo &info) {
    PRINT_HILOGD("OnConnectAbilityWithAccount is called");
    // only support three params
    if (info.argc != NapiPrintUtils::ARGC_THREE) {
      PRINT_HILOGE("Not enough params");
      return engine.CreateUndefined();
    }

    // unwrap want
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(
        reinterpret_cast<napi_env>(&engine),
        reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_ZERO]),
        want);
    PRINT_HILOGD("%{public}s bundlename:%{public}s abilityname:%{public}s",
                 __func__, want.GetBundle().c_str(),
                 want.GetElement().GetAbilityName().c_str());

    int32_t accountId = 0;
    if (!OHOS::AppExecFwk::UnwrapInt32FromJS2(
            reinterpret_cast<napi_env>(&engine),
            reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_ONE]),
            accountId)) {
      PRINT_HILOGD("%{public}s called, the second parameter is invalid.",
                   __func__);
      return engine.CreateUndefined();
    }

    // unwarp connection
    sptr<JSPrintExtensionConnection> connection =
        new JSPrintExtensionConnection(engine);
    connection->SetJsConnectionObject(info.argv[1]);
    int64_t connectId = serialNumber_;
    ConnecttionKey key;
    key.id = serialNumber_;
    key.want = want;
    connects_.emplace(key, connection);
    if (serialNumber_ < INT64_MAX) {
      serialNumber_++;
    } else {
      serialNumber_ = 0;
    }
    PRINT_HILOGD("%{public}s not find connection, make new one:%{public}p.",
                 __func__, connection.GetRefPtr());
    AsyncTask::CompleteCallback complete = [weak = context_, want, accountId,
                                            connection,
                                            connectId](NativeEngine &engine,
                                                       AsyncTask &task,
                                                       int32_t status) {
      PRINT_HILOGD("OnConnectAbilityWithAccount begin");
      auto context = weak.lock();
      if (!context) {
        PRINT_HILOGW("context is released");
        task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT,
                                          "Context is released"));
        return;
      }
      PRINT_HILOGD("context->ConnectAbilityWithAccount connection:%{public}d",
                   (int32_t)connectId);
      if (!context->ConnectAbilityWithAccount(want, accountId, connection)) {
        connection->CallJsFailed(E_PRINT_INVALID_CONTEXT);
      }
      task.Resolve(engine, engine.CreateUndefined());
    };
    NativeValue *result = nullptr;
    AsyncTask::Schedule(
        "PrintExtensionContext::OnConnectAbilityWithAccount", engine,
        CreateAsyncTaskWithLastParam(engine, nullptr, nullptr,
                                     std::move(complete), &result));
    return engine.CreateNumber(connectId);
  }

  NativeValue *OnDisconnectAbility(NativeEngine &engine,
                                   NativeCallbackInfo &info) {
    PRINT_HILOGD("OnDisconnectAbility is called");
    // only support one or two params
    if (info.argc != NapiPrintUtils::ARGC_ONE &&
        info.argc != NapiPrintUtils::ARGC_TWO) {
      PRINT_HILOGE("Not enough params");
      return engine.CreateUndefined();
    }

    // unwrap want
    AAFwk::Want want;
    // unwrap connectId
    int64_t connectId = -1;
    sptr<JSPrintExtensionConnection> connection = nullptr;
    napi_get_value_int64(
        reinterpret_cast<napi_env>(&engine),
        reinterpret_cast<napi_value>(info.argv[NapiPrintUtils::INDEX_ZERO]),
        &connectId);
    PRINT_HILOGD("OnDisconnectAbility connection:%{public}d",
                 (int32_t)connectId);
    auto item = std::find_if(
        connects_.begin(), connects_.end(),
        [&connectId](
            const std::map<ConnecttionKey,
                           sptr<JSPrintExtensionConnection>>::value_type &obj) {
          return connectId == obj.first.id;
        });
    if (item != connects_.end()) {
      // match id
      want = item->first.want;
      connection = item->second;
      PRINT_HILOGD("%{public}s find conn ability:%{public}p exist", __func__,
                   item->second.GetRefPtr());
    } else {
      PRINT_HILOGD("%{public}s not find conn exist.", __func__);
    }
    // begin disconnect
    AsyncTask::CompleteCallback complete = [weak = context_, want,
                                            connection](NativeEngine &engine,
                                                        AsyncTask &task,
                                                        int32_t status) {
      PRINT_HILOGD("OnDisconnectAbility begin");
      auto context = weak.lock();
      if (!context) {
        PRINT_HILOGW("context is released");
        task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONTEXT,
                                          "Context is released"));
        return;
      }
      if (connection == nullptr) {
        PRINT_HILOGW("connection nullptr");
        task.Reject(engine, CreateJsError(engine, E_PRINT_INVALID_CONNECTION,
                                          "not found connection"));
        return;
      }
      PRINT_HILOGD("context->DisconnectAbility");
      auto errcode = context->DisconnectAbility(want, connection);
      errcode == 0
          ? task.Resolve(engine, engine.CreateUndefined())
          : task.Reject(engine, CreateJsError(engine, errcode,
                                              "Disconnect Ability failed."));
    };

    NativeValue *lastParam = (info.argc == NapiPrintUtils::ARGC_ONE)
                                 ? nullptr
                                 : info.argv[NapiPrintUtils::INDEX_ONE];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("PrintExtensionContext::OnDisconnectAbility", engine,
                        CreateAsyncTaskWithLastParam(engine, lastParam, nullptr,
                                                     std::move(complete),
                                                     &result));
    return result;
  }
};

NativeValue *CreateJsMetadata(NativeEngine &engine,
                              const AppExecFwk::Metadata &Info) {
  PRINT_HILOGD("CreateJsMetadata");
  NativeValue *objValue = engine.CreateObject();
  NativeObject *object = ConvertNativeValueTo<NativeObject>(objValue);

  object->SetProperty("name", CreateJsValue(engine, Info.name));
  object->SetProperty("value", CreateJsValue(engine, Info.value));
  object->SetProperty("resource", CreateJsValue(engine, Info.resource));
  return objValue;
}

NativeValue *
CreateJsMetadataArray(NativeEngine &engine,
                      const std::vector<AppExecFwk::Metadata> &info) {
  PRINT_HILOGD("CreateJsMetadataArray");
  NativeValue *arrayValue = engine.CreateArray(info.size());
  NativeArray *array = ConvertNativeValueTo<NativeArray>(arrayValue);
  uint32_t index = 0;
  for (const auto &item : info) {
    array->SetElement(index++, CreateJsMetadata(engine, item));
  }
  return arrayValue;
}

NativeValue *
CreateJsExtensionAbilityInfo(NativeEngine &engine,
                             const AppExecFwk::ExtensionAbilityInfo &info) {
  PRINT_HILOGD("CreateJsExtensionAbilityInfo");
  NativeValue *objValue = engine.CreateObject();
  NativeObject *object = ConvertNativeValueTo<NativeObject>(objValue);
  object->SetProperty("bundleName", CreateJsValue(engine, info.bundleName));
  object->SetProperty("moduleName", CreateJsValue(engine, info.moduleName));
  object->SetProperty("name", CreateJsValue(engine, info.name));
  object->SetProperty("labelId", CreateJsValue(engine, info.labelId));
  object->SetProperty("descriptionId",
                      CreateJsValue(engine, info.descriptionId));
  object->SetProperty("iconId", CreateJsValue(engine, info.iconId));
  object->SetProperty("isVisible", CreateJsValue(engine, info.visible));
  object->SetProperty("extensionAbilityType", CreateJsValue(engine, info.type));
  NativeValue *permissionArrayValue =
      engine.CreateArray(info.permissions.size());
  NativeArray *permissionArray =
      ConvertNativeValueTo<NativeArray>(permissionArrayValue);
  if (permissionArray != nullptr) {
    int index = 0;
    for (auto permission : info.permissions) {
      permissionArray->SetElement(index++, CreateJsValue(engine, permission));
    }
  }
  object->SetProperty("permissions", permissionArrayValue);
  object->SetProperty("applicationInfo",
                      CreateJsApplicationInfo(engine, info.applicationInfo));
  object->SetProperty("metadata", CreateJsMetadataArray(engine, info.metadata));
  object->SetProperty("enabled", CreateJsValue(engine, info.enabled));
  object->SetProperty("readPermission",
                      CreateJsValue(engine, info.readPermission));
  object->SetProperty("writePermission",
                      CreateJsValue(engine, info.writePermission));
  return objValue;
}

NativeValue *
CreateJsPrintExtensionContext(NativeEngine &engine,
                              std::shared_ptr<PrintExtensionContext> context,
                              std::string &extensionId) {
  PRINT_HILOGD("CreateJsPrintExtensionContext begin");
  NativeValue *objValue = CreateJsExtensionContext(engine, context);
  NativeObject *object = ConvertNativeValueTo<NativeObject>(objValue);

  std::unique_ptr<JsPrintExtensionContext> jsContext =
      std::make_unique<JsPrintExtensionContext>(context);
  object->SetNativePointer(jsContext.release(),
                           JsPrintExtensionContext::Finalizer, nullptr);

  // make handler
  handler_ = std::make_shared<AppExecFwk::EventHandler>(
      AppExecFwk::EventRunner::GetMainEventRunner());
  const char *moduleName = "JsPrintExtensionContext";
  BindNativeFunction(engine, *object, "startAbility", moduleName,
                     JsPrintExtensionContext::StartAbility);
  BindNativeFunction(engine, *object, "terminateSelf", moduleName,
                     JsPrintExtensionContext::TerminateAbility);
  BindNativeFunction(engine, *object, "connectAbility", moduleName,
                     JsPrintExtensionContext::ConnectAbility);
  BindNativeFunction(engine, *object, "disconnectAbility", moduleName,
                     JsPrintExtensionContext::DisconnectAbility);
  BindNativeFunction(engine, *object, "startAbilityWithAccount", moduleName,
                     JsPrintExtensionContext::StartAbilityWithAccount);
  BindNativeFunction(engine, *object, "connectAbilityWithAccount", moduleName,
                     JsPrintExtensionContext::ConnectAbilityWithAccount);
  if (context) {
    PRINT_HILOGD("Set ExtensionAbilityInfo Property");
    auto abilityInfo = context->GetAbilityInfo();
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (abilityInfo && hapModuleInfo) {
      extensionId = abilityInfo->bundleName;
      PRINT_HILOGD(
          "Set ExtensionAbilityInfo Property: extensionId = %{public}s",
          extensionId.c_str());
      auto isExist =
          [&abilityInfo](const AppExecFwk::ExtensionAbilityInfo &info) {
            PRINT_HILOGD("%{public}s, %{public}s", info.bundleName.c_str(),
                         info.name.c_str());
            return info.bundleName == abilityInfo->bundleName &&
                   info.name == abilityInfo->name;
          };
      auto infoIter =
          std::find_if(hapModuleInfo->extensionInfos.begin(),
                       hapModuleInfo->extensionInfos.end(), isExist);
      if (infoIter == hapModuleInfo->extensionInfos.end()) {
        PRINT_HILOGD("Get target fail.");
        return objValue;
      }
      object->SetProperty("extensionAbilityInfo",
                          CreateJsExtensionAbilityInfo(engine, *infoIter));
    }
  }

  return objValue;
}
} // namespace AbilityRuntime
} // namespace OHOS
