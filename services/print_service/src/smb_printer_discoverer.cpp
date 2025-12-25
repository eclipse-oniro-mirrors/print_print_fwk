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
#include <iostream>
#include <vector>
#include <algorithm>
#include <cctype>
#include <thread>
#include <functional>
#include <poll.h>
#include <fcntl.h>
#include <sstream>
#include "print_log.h"
#include "print_util.h"
#include "print_constant.h"
#include "smb_printer_discoverer.h"

namespace OHOS::Print {
static constexpr int32_t SMB_CONNECT_TIMEOUT_S = 2;
static constexpr int32_t SMB_CONNECT_TIMEOUT_MS = 2000;
static constexpr char SEPARATOR = '-';
static constexpr int32_t MAX_URI_LENGTH = 128;
static constexpr int32_t PRINTER_TYPE = 3;
static const char* URL_SPACE_ENCODING  = "%20";

struct SmbPrinterDiscoverer::PrinterShareInfo {
    std::string name;
    std::string remark;
};

SmbPrinterDiscoverer::SmbPrinterDiscoverer(): smbCtx_(nullptr), userPasswd_(nullptr)
{
    smbCtx_ = smb2_init_context();
    if (!smbCtx_) {
        PRINT_HILOGE("smbCtx_ is nullptr");
    }
    userPasswd_ = new (std::nothrow) char[MAX_AUTH_LENGTH_SIZE]{};
    if (!userPasswd_) {
        PRINT_HILOGE("allocate userPasswd_ mem fail");
    }
}

SmbPrinterDiscoverer::~SmbPrinterDiscoverer()
{
    if (smbCtx_) {
        smb2_destroy_context(smbCtx_);
        smbCtx_ = nullptr;
    }
    if (userPasswd_) {
        PrintUtil::SafeDeleteAuthInfo(userPasswd_);
    }
}

int32_t SmbPrinterDiscoverer::SetCredentials(const std::string &userName, char *userPasswd)
{
    if (userName.empty()) {
        PRINT_HILOGI("auth as guest");
        return E_PRINT_NONE;
    }

    if (!userPasswd) {
        PRINT_HILOGE("userPasswd is null");
        return E_PRINT_INVALID_PARAMETER;
    }

    if (!smbCtx_) {
        PRINT_HILOGE("smbCtx_ is null");
        return E_PRINT_SERVER_FAILURE;
    }

    if (!userPasswd_) {
        PRINT_HILOGE("userPasswd_ is null");
        return E_PRINT_SERVER_FAILURE;
    }

    smb2_set_user(smbCtx_, userName.c_str());
    smb2_set_password(smbCtx_, userPasswd);
    smb2_set_security_mode(smbCtx_, SMB2_NEGOTIATE_SIGNING_ENABLED);

    auto memcpyRet = memcpy_s(userPasswd_, MAX_AUTH_LENGTH_SIZE, userPasswd, MAX_AUTH_LENGTH_SIZE);
    if (memcpyRet != E_PRINT_NONE) {
        PRINT_HILOGW("memcpy_s failed, errorCode:[%{public}d]", memcpyRet);
    }
    userName_ = userName;
    return E_PRINT_NONE;
}

int32_t SmbPrinterDiscoverer::QuerySmbPrinters(const PrintSharedHost& sharedHost, const std::string &userName,
    char *userPasswd, std::vector<PrinterInfo> &infos)
{
    int32_t ret = SetCredentials(userName, userPasswd);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("SetCredentials fail");
        return ret;
    }
    if (smbCtx_ == nullptr) {
        PRINT_HILOGE("smbCtx_ is nullptr");
        return E_PRINT_SERVER_FAILURE;
    }
    smb2_set_timeout(smbCtx_, SMB_CONNECT_TIMEOUT_MS);
    const char* share = "print$";
    ret = smb2_connect_share(smbCtx_, sharedHost.GetIp().c_str(), "IPC$", nullptr);
    if (ret != 0) {
        PRINT_HILOGE("smb2_connect_share fail, ret = %{public}d, reason = %{public}s",
            ret, smb2_get_error(smbCtx_));
        return E_PRINT_INVALID_TOKEN;
    }
    if (smb2_share_enum_async(smbCtx_, SHARE_INFO_1,
        [](struct smb2_context* smb2, int32_t status, void* commandData, void* privateData) {
            if (!privateData) {
                PRINT_HILOGE("privateData is null");
                return;
            }
            auto* self = static_cast<SmbPrinterDiscoverer*>(privateData);
            self->ShareEnumCallback(smb2, status, commandData);
        }, this) != 0) {
        PRINT_HILOGE("smb2_share_enum_async fail, ret = %{public}d, reason = %{public}s",
            ret, smb2_get_error(smbCtx_));
        smb2_disconnect_share(smbCtx_);
        return {};
    }
    ret = SmbEventLoop();
    smb2_disconnect_share(smbCtx_);
    if (ret == E_PRINT_NONE) {
        GeneratePrinterInfos(sharedHost.GetIp(), infos);
    }
    return ret;
}

int32_t SmbPrinterDiscoverer::SmbEventLoop()
{
    if (!smbCtx_) {
        PRINT_HILOGE("smbCtx_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    while (!isFinished_.load()) {
        int32_t fd = smb2_get_fd(smbCtx_);
        if (fd < 0) {
            PRINT_HILOGE("Failed to get fd");
            return E_PRINT_SERVER_FAILURE;
        }
        int32_t events = smb2_which_events(smbCtx_);
        struct pollfd pfd = {
            .fd = fd,
            .events = events,
            .revents = 0
        };
        int32_t ret = poll(&pfd, 1, SMB_CONNECT_TIMEOUT_MS);
        if (ret > 0) {
            if (ret = smb2_service(smbCtx_, pfd.revents) < 0) {
                PRINT_HILOGE("smb2_share_enum_async fail, ret = %{public}d, reason = %{public}s",
                    ret, smb2_get_error(smbCtx_));
                return E_PRINT_SERVER_FAILURE;
            }
        } else if (ret == 0) {
            PRINT_HILOGE("poll timeout");
            return E_PRINT_SERVER_FAILURE;
        } else {
            PRINT_HILOGE("poll fail, errno = %{public}d", errno);
            return E_PRINT_SERVER_FAILURE;
        }
    }
    return E_PRINT_NONE;
}

void SmbPrinterDiscoverer::ShareEnumCallback(struct smb2_context* smb2, int32_t status, void* commandData)
{
    isFinished_.store(true);
    if (!smb2) {
        PRINT_HILOGE("smb2 is null");
        return;
    }
    if (status) {
        PRINT_HILOGE("ShareEnumCallback fail, ret = %{public}d", status);
        return;
    }
    if (!commandData) {
        PRINT_HILOGE("commandData is null");
        return;
    }
    auto* rep = static_cast<struct srvsvc_NetrShareEnum_rep*>(commandData);
    if (rep->ses.ShareInfo.Level1.EntriesRead > 0) {
        for (int32_t i = 0; i < rep->ses.ShareInfo.Level1.EntriesRead; i++) {
            const auto& share = rep->ses.ShareInfo.Level1.Buffer->share_info_1[i];
            if ((share.type & PRINTER_TYPE) == SHARE_TYPE_PRINTQ) {
                PrinterShareInfo printer;
                printer.name = share.netname.utf8 ? share.netname.utf8 : "";
                printer.remark = share.remark.utf8 ? share.remark.utf8 : "";
                printers_.push_back(printer);
                PRINT_HILOGI("find smb printer, name = %{public}s", printer.name.c_str());
            }
        }
    }
    smb2_free_data(smb2, rep);
    PRINT_HILOGI("finish ShareEnumCallback");
}

void SmbPrinterDiscoverer::GeneratePrinterInfos(const std::string& ip, std::vector<PrinterInfo> &infos)
{
    if (printers_.empty()) {
        PRINT_HILOGW("not find smb printers");
        return;
    }
    for (auto& printer : printers_) {
        PrinterInfo info;
        info.SetPrinterId(SmbPrinterDiscoverer::CreatePrinterId(ip, printer.name));
        info.SetPrinterName("SMB-" + printer.name);
        info.SetDescription("vendor");
        info.SetPrinterMake(printer.remark);
        char uri[MAX_URI_LENGTH] = {0};
        std::string shareName = printer.name;
        if (sprintf_s(uri, sizeof(uri), "smb://%s/%s",
            ip.c_str(), ReplaceSpacesInPrinterUri(printer.name).c_str()) < 0) {
            PRINT_HILOGW("GeneratePrinterInfos sprintf_s fail");
            continue;
        }
        PRINT_HILOGD("GeneratePrinterInfos, uri = %{private}s", uri);
        info.SetUri(std::string(uri));
        PrinterCapability printerCapability;
        info.SetCapability(printerCapability);
        infos.push_back(info);
    }
}

std::string SmbPrinterDiscoverer::ReplaceSpacesInPrinterUri(const std::string& input)
{
    std::ostringstream oss;
    for (char c : input) {
        if (c == ' ') {
            oss << URL_SPACE_ENCODING;
        } else {
            oss << c;
        }
    }
    return oss.str();
}

std::string SmbPrinterDiscoverer::CreatePrinterId(const std::string& ip, const std::string& name)
{
    return std::string("smb") + SEPARATOR + ip + SEPARATOR + name;
}

std::string SmbPrinterDiscoverer::ParseIpFromSmbPrinterId(const std::string& printerId)
{
    constexpr int32_t firstSepPos = 4;

    if (printerId.substr(0, firstSepPos) != "smb-") {
        PRINT_HILOGE("cannot find smb in printerId");
        return "";
    }
    
    size_t secondSepPos = printerId.find(SEPARATOR, firstSepPos);
    if (secondSepPos == std::string::npos) {
        PRINT_HILOGE("cannot find SEPARATOR in printerId");
        return "";
    }
    
    return printerId.substr(firstSepPos, secondSepPos - firstSepPos);
}

bool SmbPrinterDiscoverer::IsSmbPrinterId(const std::string& printerId)
{
    return printerId.find("smb") != std::string::npos;
}

}  // namespace OHOS::Print