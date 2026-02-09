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
#include <memory>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <cctype>
#include <iconv.h>
#include <sys/time.h>
#include "print_log.h"
#include "smb_host_search_helper.h"

namespace {
    constexpr int32_t NB_DGRAM = 137;
    constexpr uint16_t FL_BROADCAST = 0x0010;
    constexpr int32_t NBSTAT_QUERY_TYPE = 0x21;
    constexpr int32_t QUESTION_CLASS = 0x01;
    constexpr int32_t SOCKET_BUFFER_SIZE = 512;
    constexpr int32_t KILO_FACTOR = 1000;
    constexpr int32_t SECONDS_TO_NANOSECONDS = 1000000000;
    constexpr uint32_t MASK_31 = 0xFFFFFFFE;
    constexpr uint32_t MASK_32 = 0xFFFFFFFF;
    constexpr int32_t DEFAULT_TIMER_INTERVAL = 1000;
    constexpr int32_t INVALID_SOCKET_FD = -1;
    constexpr int32_t NAME_FIELD_SIZE = 16;
    constexpr int32_t INDEX_2 = 2;
    constexpr int32_t ENCODED_NAME_SIZE = 32;
    constexpr char NAME_PREFIX = '*';
    constexpr char ENCODING_BASE = 'A';
    constexpr uint16_t NIBBLE_MASK = 0x000F;
    constexpr int32_t NIBBLE_SHIFT = 4;
    constexpr uint8_t FILE_SHARE_SERVER_TYPE = 0x20;
    constexpr int32_t NAME_ENTRY_SIZE = 18;
    constexpr int32_t HEADER_SKIP_SIZE = 56;
    constexpr size_t GBK_TO_UTF8_MAX_EXPANSION = 3;
}

namespace OHOS::Print {
struct Nbname {
    char name[NAME_FIELD_SIZE];
    unsigned char type;
    unsigned char flags;
};

SmbHostSearchHelper::SmbHostSearchHelper(): sock_(INVALID_SOCKET_FD),
    ipRange_(NetworkIpRange::CreateFromLocalNetwork()),
    timer_(std::make_unique<HighResTimer>(DEFAULT_TIMER_INTERVAL)),
    scannedHosts_(std::make_unique<HostList>()),
    recvBuffer_(SOCKET_BUFFER_SIZE)
{
    InitializeSock();
}

SmbHostSearchHelper::~SmbHostSearchHelper()
{
    if (sock_ >= 0) {
        close(sock_);
        sock_ = INVALID_SOCKET_FD;
    }
}

bool SmbHostSearchHelper::InitializeSock()
{
    sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_ < 0) {
        PRINT_HILOGE("Failed to create socket");
        sock_ = INVALID_SOCKET_FD;
        return false;
    }
    
    int32_t flags = fcntl(sock_, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock_, F_SETFL, static_cast<uint32_t>(flags) | O_NONBLOCK);
    }
    int32_t bufSize = SOCKET_BUFFER_SIZE;
    if (setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &bufSize, sizeof(bufSize)) < 0) {
        PRINT_HILOGE("Failed to set receive buffer size, reason : %{private}s", strerror(errno));
    }
    return true;
}

void SmbHostSearchHelper::SetTimeval(timeval &timeout, const long &tvSec, const long &tvUsec)
{
    timeout.tv_sec = tvSec;
    timeout.tv_usec = tvUsec;
}

std::vector<PrintSharedHost> SmbHostSearchHelper::GetSharedHosts()
{
    fd_set readSet;
    fd_set writeSet;
    bool moreToSend = true;
    
    int32_t result = 0;
    timeval timeout;
    constexpr int32_t timeoutSeconds = 2;
    SetTimeval(timeout, timeoutSeconds, 0);
    
    while (moreToSend || result > 0) {
        FD_ZERO(&readSet);
        FD_SET(sock_, &readSet);
        
        if (moreToSend) {
            FD_ZERO(&writeSet);
            FD_SET(sock_, &writeSet);
        }
        result = select(sock_ + 1, &readSet, moreToSend ? &writeSet : nullptr, nullptr, &timeout);
        if (result < 0) {
            PRINT_HILOGW("select error, reason: %{private}s", strerror(errno));
            break;
        } else if (result == 0) {
            PRINT_HILOGI("select timeout");
            break;
        }
        
        if (FD_ISSET(sock_, &readSet)) {
            HandleReceive();
        }
        
        if (moreToSend && FD_ISSET(sock_, &writeSet) && timer_->CanSend()) {
            if (!HandleSend()) {
                moreToSend = false;
            }
        }
    }
    return scannedHosts_->GetPrintSharedHost();
}

bool SmbHostSearchHelper::SendQuery(const struct in_addr& destAddr)
{
    struct NbnameRequest request;
    struct sockaddr_in destSockaddr;
    
    if (memset_s(&destSockaddr, sizeof(destSockaddr), 0, sizeof(destSockaddr)) != 0) {
        PRINT_HILOGW("SendQuery memset_s failed.");
    }
    destSockaddr.sin_family = AF_INET;
    destSockaddr.sin_port = htons(NB_DGRAM);
    destSockaddr.sin_addr = destAddr;
    request.flags = htons(FL_BROADCAST);
    request.questionCount = htons(1);
    request.answerCount = 0;
    request.nameServiceCount = 0;
    request.additionalRecordCount = 0;
    SetQuestionName(request);
    request.questionType = htons(NBSTAT_QUERY_TYPE);
    request.questionClass = htons(QUESTION_CLASS);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    request.transactionId = htons((tv.tv_sec % KILO_FACTOR) * KILO_FACTOR +
        tv.tv_usec / KILO_FACTOR);
    int32_t status = sendto(sock_, reinterpret_cast<char*>(&request), sizeof(request), 0,
        reinterpret_cast<struct sockaddr*>(&destSockaddr), sizeof(destSockaddr));
    if (status < 0) {
        PRINT_HILOGE("Sendto failed to %s: %s", inet_ntoa(destAddr), strerror(errno));
        return false;
    }
    
    return true;
}

bool SmbHostSearchHelper::HandleSend()
{
    if (!ipRange_) {
        PRINT_HILOGI("ipRange_ is null");
        return false;
    }
    struct in_addr nextAddr;
    if (ipRange_->Next(&nextAddr)) {
        uint32_t ip = nextAddr.s_addr;
        if (!scannedHosts_->Contains(ip)) {
            if (SendQuery(nextAddr)) {
                timer_->UpdateSendTime();
                return true;
            }
            return false;
        }
        return true;
    }
    PRINT_HILOGI("Finished sending queries to all IPs in range");
    return false;
}

bool SmbHostSearchHelper::HandleReceive()
{
    sockaddr_in destAddr{};
    socklen_t addrLen = sizeof(destAddr);
    ssize_t size = recvfrom(sock_, recvBuffer_.data(), recvBuffer_.size(), 0,
        reinterpret_cast<sockaddr*>(&destAddr), &addrLen);
    if (size <= 0) {
        PRINT_HILOGE("recvfrom failed: %{private}s", strerror(errno));
        return false;
    }
    uint32_t ip = destAddr.sin_addr.s_addr;
    std::string hostName = GetFileServerName();
    if (!hostName.empty() && !scannedHosts_->Contains(ip)) {
        scannedHosts_->Add(ip, hostName);
    }
    if (memset_s(recvBuffer_.data(), recvBuffer_.size(), 0, recvBuffer_.size()) != 0) {
        PRINT_HILOGW("clearn recvBuffer_ fail");
    }
    return true;
}

void SmbHostSearchHelper::SetQuestionName(struct NbnameRequest &request)
{
    char nameBuffer[NAME_FIELD_SIZE]{};
    nameBuffer[0] = NAME_PREFIX;
    char *currentPos = request.questionName;
    currentPos[0] = ENCODED_NAME_SIZE;
    currentPos++;
    for (int32_t i = 0; i < NAME_FIELD_SIZE; i++) {
        uint32_t currentChar = static_cast<uint32_t>(toupper(nameBuffer[i]));
        currentPos[i * INDEX_2] = ((currentChar >> NIBBLE_SHIFT) & NIBBLE_MASK) + ENCODING_BASE;
        currentPos[(i * INDEX_2) + 1] = (currentChar & NIBBLE_MASK) + ENCODING_BASE;
    }
    currentPos += ENCODED_NAME_SIZE;
    currentPos[0] = 0;
}

SmbHostSearchHelper::HighResTimer::HighResTimer(int32_t intervalUs)
{
    clock_gettime(CLOCK_MONOTONIC, &lastSendTime_);
    SetInterval(intervalUs);
}

bool SmbHostSearchHelper::HighResTimer::CanSend()
{
    timespec currentTime;
    clock_gettime(CLOCK_MONOTONIC, &currentTime);
    int64_t elapsedNs = (currentTime.tv_sec - lastSendTime_.tv_sec) * SECONDS_TO_NANOSECONDS +
                        (currentTime.tv_nsec - lastSendTime_.tv_nsec);
    
    return elapsedNs >= sendIntervalNs_;
}

void SmbHostSearchHelper::HighResTimer::UpdateSendTime()
{
    clock_gettime(CLOCK_MONOTONIC, &lastSendTime_);
}

void SmbHostSearchHelper::HighResTimer::SetInterval(int32_t intervalUs)
{
    sendIntervalNs_ = intervalUs * KILO_FACTOR;
}

bool SmbHostSearchHelper::NetworkIpRange::GetLocalIPAndMask(std::string& ipStr, std::string& netmaskStr)
{
    int32_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        PRINT_HILOGE("Failed to create sock");
        return false;
    }

    struct ifconf ifc;
    constexpr int32_t bufSize = 1024;
    char buf[bufSize]{};
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
        PRINT_HILOGE("ioctl fail");
        close(sock);
        return false;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        std::string name = it->ifr_name;
        if (name == "lo") {
            continue;
        }
        struct sockaddr_in* addr = (struct sockaddr_in*)&it->ifr_addr;
        if (addr->sin_family != AF_INET) {
            continue;
        }

        ipStr = inet_ntoa(addr->sin_addr);

        struct ifreq ifrMask;
        if (strncpy_s(ifrMask.ifr_name, sizeof(ifrMask.ifr_name), it->ifr_name, IFNAMSIZ) != 0) {
            PRINT_HILOGW("strncpy_s ifrMask fail");
            continue;
        }
        if (ioctl(sock, SIOCGIFNETMASK, &ifrMask) == 0) {
            netmaskStr = inet_ntoa(((struct sockaddr_in*)&ifrMask.ifr_netmask)->sin_addr);
            close(sock);
            return true;
        }
    }
    close(sock);
    PRINT_HILOGE("GetLocalIPAndMask fail");
    return false;
}

std::pair<std::string, std::string> SmbHostSearchHelper::NetworkIpRange::CalculateSubnetRange(const std::string& ipStr,
    const std::string& netmaskStr)
{
    struct in_addr ipAddr;
    struct in_addr netmaskAddr;
    
    if (inet_pton(AF_INET, ipStr.c_str(), &ipAddr) != 1) {
        PRINT_HILOGE("Invalid IP address");
        return {"", ""};
    }
    
    if (inet_pton(AF_INET, netmaskStr.c_str(), &netmaskAddr) != 1) {
        PRINT_HILOGE("Invalid netmask:");
        return {"", ""};
    }
    
    uint32_t ip = ntohl(ipAddr.s_addr);
    uint32_t mask = ntohl(netmaskAddr.s_addr);
    uint32_t network = ip & mask;
    uint32_t broadcast = network | (~mask);
    bool isSmallSubnet = false;
    
    if (mask == MASK_31) {
        isSmallSubnet = true;
    } else if (mask == MASK_32) {
        isSmallSubnet = true;
    }
    
    uint32_t startIp;
    uint32_t endIp;
    
    if (isSmallSubnet) {
        startIp = network;
        endIp = broadcast;
    } else {
        startIp = network + 1;
        endIp = broadcast - 1;
        if (startIp > endIp) {
            startIp = network;
            endIp = broadcast;
        }
    }
    
    struct in_addr startAddr;
    struct in_addr endAddr;
    
    startAddr.s_addr = htonl(startIp);
    endAddr.s_addr = htonl(endIp);
    
    char startStr[INET_ADDRSTRLEN];
    char endStr[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &startAddr, startStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &endAddr, endStr, INET_ADDRSTRLEN);
    
    return {std::string(startStr), std::string(endStr)};
}

SmbHostSearchHelper::NetworkIpRange::NetworkIpRange(const std::string& start, const std::string& end)
{
    inet_aton(start.c_str(), &start_);
    inet_aton(end.c_str(), &end_);
    current_ = start_;
}

std::unique_ptr<SmbHostSearchHelper::NetworkIpRange> SmbHostSearchHelper::NetworkIpRange::CreateFromLocalNetwork()
{
    std::string localIp;
    std::string netmask;
    if (!GetLocalIPAndMask(localIp, netmask)) {
        PRINT_HILOGE("Failed to get local network information");
        return nullptr;
    }
    auto range = CalculateSubnetRange(localIp, netmask);
    return std::make_unique<NetworkIpRange>(range.first, range.second);
}

bool SmbHostSearchHelper::NetworkIpRange::Next(struct in_addr* nextAddr)
{
    if (ntohl(current_.s_addr) > ntohl(end_.s_addr)) {
        return false;
    }
    
    if (nextAddr) {
        *nextAddr = current_;
    }
    
    uint32_t nextIp = ntohl(current_.s_addr) + 1;
    current_.s_addr = htonl(nextIp);
    
    return true;
}

bool SmbHostSearchHelper::HostList::Contains(uint32_t ip) const
{
    return responsedHosts_.find(ip) != responsedHosts_.end();
}

void SmbHostSearchHelper::HostList::Add(uint32_t ip, const std::string& name)
{
    responsedHosts_.insert({ip, name});
}

std::vector<PrintSharedHost> SmbHostSearchHelper::HostList::GetPrintSharedHost() const
{
    std::vector<PrintSharedHost> result;
    for (auto& [ip, name] : responsedHosts_) {
        PrintSharedHost host;
        struct in_addr addr;
        addr.s_addr = ip;
        std::string ipStr = inet_ntoa(addr);
        host.SetIp(ipStr);
        host.SetShareName(name);
        host.SetWorkgroupName("workgroup");
        result.push_back(host);
    }
    return result;
}

bool SmbHostSearchHelper::TestSmbHostAlive(const std::string& ip, int32_t timeoutMs)
{
    if (sock_ < 0) {
        PRINT_HILOGE("Socket is not initialized");
        return false;
    }
    struct in_addr destAddr;
    if (inet_pton(AF_INET, ip.c_str(), &destAddr) != 1) {
        PRINT_HILOGE("Invalid IP address format");
        return false;
    }
    if (!SendQuery(destAddr)) {
        PRINT_HILOGW("Failed to send query");
        return false;
    }
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(sock_, &readSet);
    struct timeval selectTimeout;
    long tvUsec = static_cast<long>(timeoutMs) * KILO_FACTOR;
    long tvSec = tvUsec / (KILO_FACTOR * KILO_FACTOR);
    SetTimeval(selectTimeout, tvSec, tvUsec);
    int32_t result = select(sock_ + 1, &readSet, nullptr, nullptr, &selectTimeout);
    if (result < 0) {
        PRINT_HILOGW("select error, reason: %{private}s", strerror(errno));
        return false;
    } else if (result == 0) {
        PRINT_HILOGD("Timeout waiting for response from %{private}s", ip.c_str());
        return false;
    }
    if (FD_ISSET(sock_, &readSet) && HandleReceive()) {
        PRINT_HILOGD("Reply received");
        return true;
    }
    PRINT_HILOGW("Unexpected state while testing");
    return false;
}

std::string SmbHostSearchHelper::GetFileServerName()
{
    int32_t offset = 0;
    char* buff = recvBuffer_.data();
    int32_t buffsize = static_cast<int32_t>(recvBuffer_.size());
    if (buffsize < HEADER_SKIP_SIZE + 1) {
        PRINT_HILOGW("Head error");
        return "";
    }
    offset = HEADER_SKIP_SIZE;
    unsigned char numberOfNames = static_cast<unsigned char>(buff[offset]);
    offset += 1;
    int32_t nameTableSize = numberOfNames * NAME_ENTRY_SIZE;
    if (offset + nameTableSize > buffsize) {
        PRINT_HILOGW("Failed to retrieve the name table");
        return "";
    }
    for (int32_t numberIndex = 0; numberIndex < numberOfNames; numberIndex++) {
        const Nbname* nameEntry = reinterpret_cast<const Nbname*>(buff + offset + numberIndex * NAME_ENTRY_SIZE);
        char encodedName[NAME_FIELD_SIZE] = {0};
        char c = nameEntry->name[NAME_FIELD_SIZE - 1];
        if (c != FILE_SHARE_SERVER_TYPE) {
            continue;
        }
        for (int32_t nameCharIndex = NAME_FIELD_SIZE - 2; nameCharIndex >= 0; nameCharIndex--) {
            c = nameEntry->name[nameCharIndex];
            if (c == FILE_SHARE_SERVER_TYPE) {
                continue;
            }
            if (memcpy_s(encodedName, sizeof(encodedName), nameEntry->name,
                nameCharIndex + 1) != 0) {
                PRINT_HILOGE("memcpy_s failed");
                return "";
            }
            std::string gbkInput = std::string(encodedName);
            std::string utf8Output;
            return EncodingConverter::GbkToUtf8Iconv(gbkInput, utf8Output) ? utf8Output : gbkInput;
        }
    }
    return "";
}

bool SmbHostSearchHelper::EncodingConverter::GbkToUtf8Iconv(const std::string& gbkInput, std::string& utf8Output)
{
    if (gbkInput.empty()) {
        utf8Output.clear();
        return true;
    }
    
    iconv_t cd = iconv_open("UTF-8", "GBK");
    if (cd == (iconv_t)-1) {
        PRINT_HILOGE("iconv_open fail, errno = %d", errno);
        return false;
    }

    bool success = false;
    size_t inBytesLeft = gbkInput.size();
    size_t outBufferSize = gbkInput.size() * GBK_TO_UTF8_MAX_EXPANSION + 1;
    std::string buffer(outBufferSize, '\0');
    
    char* inBuf = const_cast<char*>(gbkInput.data());
    char* outBuf = &buffer[0];
    size_t outBytesLeft = outBufferSize - 1;
    
    size_t result = iconv(cd, (char**)&inBuf, &inBytesLeft, &outBuf, &outBytesLeft);
    if (result != 0) {
        PRINT_HILOGE("iconv conversion failed, errno = %d", errno);
        success = false;
    } else {
        if (iconv(cd, NULL, NULL, &outBuf, &outBytesLeft) == (size_t)(-1)) {
            PRINT_HILOGW("The converter failed to refresh, errno = %d", errno);
        }
        size_t bytesConverted = outBufferSize - 1 - outBytesLeft;
        utf8Output.assign(buffer.data(), bytesConverted);
        success = true;
    }
    iconv_close(cd);
    return success;
}
}