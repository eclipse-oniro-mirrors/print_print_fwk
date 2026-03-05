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

#include <map>
#include <sstream>
#include <atomic>
#include "print_notification_builder.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_resource_manager.h"
#include "notification_normal_content.h"
#include "notification_helper.h"
#include "notification_content.h"
#include "pixel_map.h"
#include "image_source.h"
#include "want_agent_helper.h"
#include "want.h"

namespace {
    constexpr uint32_t ENABLE_BANNER_BIT = 1 << 9;
    constexpr int32_t NOTIFICATION_ID_BASE = 1;
    constexpr int32_t UDMF_KEY_BUFFER_SIZE = 1024;
    constexpr int32_t WANT_AGENT_REQUEST_CODE = 0;

    const std::string WANT_PARAM_PRINT_TRIGGER_TYPE = "trigger_type";
    const std::string WANT_PARAM_PRINT_ASK_XIAOYI = "ask_xiaoyi";
    const std::string WANT_PARAM_PRINT_IS_TEXTEDIT = "isTextEdit";
    const std::string WANT_PARAM_SMART_RIGHT_KEY = "smart_right_key";
    const std::string WANT_PARAM_ASK_FOR_XIAO_YI_BUTTON = "ask_for_xiao_yi_button";

    std::atomic<int32_t> g_nextNotificationId{NOTIFICATION_ID_BASE};
}

namespace OHOS::Print {
using namespace OHOS::UDMF;
UdmfDataGuard::UdmfDataGuard() {}

UdmfDataGuard::~UdmfDataGuard()
{
    if (plainText_) {
        OH_UdsPlainText_Destroy(plainText_);
    }
    if (record_) {
        OH_UdmfRecord_Destroy(record_);
    }
    if (udmfUnifiedData_) {
        OH_UdmfData_Destroy(udmfUnifiedData_);
    }
    if (option_) {
        OH_UdmfOptions_Destroy(option_);
    }
}

bool UdmfDataGuard::CreatePlainText(const std::string& content)
{
    udmfUnifiedData_ = OH_UdmfData_Create();
    if (!udmfUnifiedData_) {
        PRINT_HILOGE("OH_UdmfData_Create failed");
        return false;
    }

    record_ = OH_UdmfRecord_Create();
    if (!record_) {
        PRINT_HILOGE("OH_UdmfRecord_Create failed");
        return false;
    }

    plainText_ = OH_UdsPlainText_Create();
    if (!plainText_) {
        PRINT_HILOGE("OH_UdsPlainText_Create failed");
        return false;
    }

    OH_UdsPlainText_SetContent(plainText_, content.c_str());
    OH_UdmfRecord_AddPlainText(record_, plainText_);
    OH_UdmfData_AddRecord(udmfUnifiedData_, record_);

    option_ = OH_UdmfOptions_Create();
    if (!option_) {
        PRINT_HILOGE("OH_UdmfOptions_Create failed");
        return false;
    }

    option_->intention = Udmf_Intention::UDMF_INTENTION_DATA_HUB;
    return true;
}

std::string UdmfDataGuard::Serialize()
{
    if (!option_ || !udmfUnifiedData_) {
        PRINT_HILOGE("UDMF data not initialized");
        return "";
    }

    char key[UDMF_KEY_BUFFER_SIZE] = {0};
    OH_Udmf_SetUnifiedDataByOptions(option_, udmfUnifiedData_, key, UDMF_KEY_BUFFER_SIZE);
    return std::string(key);
}

Notification::NotificationRequest PrintNotificationBuilder::BuildRequest(int32_t notiId,
    std::shared_ptr<Notification::NotificationContent>& content)
{
    Notification::NotificationRequest request;
    uint32_t controlFlags = 0;
    request.SetNotificationId(notiId);
    request.SetContent(content);
    controlFlags |= ENABLE_BANNER_BIT;
    request.SetNotificationControlFlags(controlFlags);
    auto pixelMap = PrintResourceManager::GetInstance().GetPixelMapByName("logo");
    if (pixelMap) {
        request.SetLittleIcon(pixelMap);
        PRINT_HILOGI("SetLittleIcon success");
    } else {
        PRINT_HILOGW("GetPixelMapByName logo failed");
    }
    request.SetSlotType(Notification::NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request.SetRemoveAllowed(false);
    request.SetTapDismissed(false);
    request.SetCreatorUid(getuid());
    return request;
}

std::shared_ptr<Notification::NotificationActionButton> PrintNotificationBuilder::CreateAiButton(int32_t notiId,
    const std::string& askAiKey)
{
    UdmfDataGuard udmfGuard;
    if (!udmfGuard.CreatePlainText(askAiKey)) {
        PRINT_HILOGE("CreatePlainText failed");
        return nullptr;
    }

    std::string wantStr = udmfGuard.Serialize();
    if (wantStr.empty()) {
        PRINT_HILOGE("Serialize failed");
        return nullptr;
    }

    auto want = std::make_shared<AAFwk::Want>();
    want->SetElementName("com.oh.vassistant", "VoicePcServiceExtAbility");
    want->SetParam(WANT_PARAM_PRINT_TRIGGER_TYPE, WANT_PARAM_SMART_RIGHT_KEY);
    want->SetParam(WANT_PARAM_PRINT_IS_TEXTEDIT, false);
    want->SetParam(WANT_PARAM_PRINT_ASK_XIAOYI, wantStr);
    want->SetFlags(AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION | AAFwk::Want::FLAG_AUTH_WRITE_URI_PERMISSION);

    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);

    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);

    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(WANT_AGENT_REQUEST_CODE,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY, flags, wants, nullptr);

    auto wantAgent = AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo);
    if (!wantAgent) {
        PRINT_HILOGE("GetWantAgent failed");
        return nullptr;
    }

    std::string buttonTitle = PrintResourceManager::GetInstance().GetStringByName(WANT_PARAM_ASK_FOR_XIAO_YI_BUTTON);
    std::shared_ptr<Notification::NotificationActionButton> actionButton =
        Notification::NotificationActionButton::Create(nullptr, buttonTitle, wantAgent);
    if (!actionButton) {
        PRINT_HILOGE("Create actionButton failed");
        return nullptr;
    }

    return actionButton;
}

std::string PrintNotificationBuilder::SubStateToResourceKey(uint32_t subState)
{
    static const std::map<uint32_t, std::string> resourceKeyMap = {
        {PrintJobSubState::PRINT_JOB_BLOCKED_DOOR_OPEN, "printer_door_open"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_OUT_OF_PAPER, "printer_out_of_paper"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_OUT_OF_INK, "printer_out_of_ink"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_OUT_OF_TONER, "printer_out_of_toner"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_JAMMED, "printer_jammed"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_OFFLINE, "printer_offline"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_BUSY, "printer_busy"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_LOW_ON_INK, "printer_low_on_ink"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_LOW_ON_TONER, "printer_low_on_toner"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK, "printer_really_low_on_ink"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_BAD_CERTIFICATE, "printer_bad_certificate"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_DRIVER_EXCEPTION, "printer_driver_exception"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_ACCOUNT_ERROR, "printer_account_error"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_PRINT_PERMISSION_ERROR, "printer_permission_error"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_PRINT_COLOR_PERMISSION_ERROR, "printer_color_permission_error"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_NETWORK_ERROR, "printer_network_error"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_SERVER_CONNECTION_ERROR, "printer_server_connection_error"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_LARGE_FILE_ERROR, "printer_large_file_error"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_FILE_PARSING_ERROR, "printer_file_parsing_error"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_SLOW_FILE_CONVERSION, "printer_slow_file_conversion"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_DRIVER_MISSING, "printer_driver_missing"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_INTERRUPT, "printer_interrupt"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_AUTHENTICATION, "printer_authentication"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_BANNED, "printer_banned"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_SMB_PRINTER, "printer_smb_error"},
        {PrintJobSubState::PRINT_JOB_BLOCKED_PRINTER_UNAVAILABLE, "printer_unavailable"}
    };

    auto it = resourceKeyMap.find(subState);
    if (it != resourceKeyMap.end()) {
        return it->second;
    }
    return "printer_check";
}

int32_t PrintNotificationBuilder::CreateNotification(uint32_t subState, const std::string &printerName)
{
    std::shared_ptr<Notification::NotificationNormalContent> normalContent =
        std::make_shared<Notification::NotificationNormalContent>();
    if (!normalContent) {
        PRINT_HILOGE("create NotificationNormalContent failed");
        return E_PRINT_SERVER_FAILURE;
    }

    const std::string resourceKey = SubStateToResourceKey(subState);
    normalContent->SetText(PrintResourceManager::GetInstance().GetStringByName(resourceKey));

    const std::string app_name = "app_name";
    normalContent->SetTitle(PrintResourceManager::GetInstance().GetStringByName(app_name));

    auto content = std::make_shared<Notification::NotificationContent>(normalContent);
    if (!content) {
        PRINT_HILOGE("create NotificationContent failed");
        return E_PRINT_SERVER_FAILURE;
    }

    int32_t notiId = g_nextNotificationId.fetch_add(1);
    Notification::NotificationRequest request = BuildRequest(notiId, content);

    std::ostringstream oss;
    oss << "来自打印机" << printerName << ":" << PrintResourceManager::GetInstance().GetStringByName(resourceKey);
    std::shared_ptr<Notification::NotificationActionButton> actionButton = CreateAiButton(notiId, oss.str());

    if (!actionButton) {
        PRINT_HILOGE("CreateAiButton failed");
        return E_PRINT_SERVER_FAILURE;
    }

    request.AddActionButton(actionButton);

    int32_t result = Notification::NotificationHelper::PublishNotification(request);
    if (result != OHOS::ERR_OK) {
        PRINT_HILOGE("PublishNotification failed, result: %{public}d", result);
        return E_PRINT_SERVER_FAILURE;
    }

    return E_PRINT_NONE;
}

} // namespace OHOS::Print
