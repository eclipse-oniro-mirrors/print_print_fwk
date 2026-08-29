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

#include "print_shell_command.h"

#include <cctype>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include <json/json.h>

#include "print_constant.h"
#include "print_job.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "print_margin.h"
#include "print_page_size.h"
#include "print_range.h"
#include "printer_info.h"

namespace OHOS {
namespace Print {

PrintShellCommand::PrintShellCommand(int argc, char* argv[])
    : ShellCommand(argc, argv, TOOL_NAME)
{}

ErrCode PrintShellCommand::CreateCommandMap()
{
    commandMap_ = {
        {"help",                 [this]() { return this->RunAsHelpCommand(); }},
        {"list-added-printers",  [this]() { return this->RunAsListAddedPrinters(); }},
        {"start-print-job",      [this]() { return this->RunAsStartPrintJob(); }},
    };
    return ERR_OK;
}

ErrCode PrintShellCommand::Init()
{
    return ERR_OK;
}

// ========== Subcommand handlers ==========

ErrCode PrintShellCommand::ShowGeneralHelp()
{
    Json::Value subcommands(Json::arrayValue);
    for (const auto& pair : commandMap_) {
        if (pair.first == "help") {
            continue;
        }
        Json::Value cmd;
        cmd["name"] = pair.first;
        if (pair.first == "list-added-printers") {
            cmd["description"] = CMD_DESC_LIST_ADDED_PRINTERS;
        } else if (pair.first == "start-print-job") {
            cmd["description"] = CMD_DESC_START_PRINT_JOB;
        }
        subcommands.append(cmd);
    }
    std::string helpText = std::string(name_) + " - " + TOOL_DESCRIPTION;
    helpText += "\n\nUsage:\n  " + std::string(name_) + " [command] [options]";
    helpText += "\n\nParameters:\n  --help                   Display this help message";
    helpText += "\n\nExamples:\n  " + std::string(name_) + " --help\n  " + std::string(name_) + " <command> --help";
    Json::Value data;
    data["helpText"] = helpText;
    data["subcommands"] = subcommands;
    OutputSuccess(data, resultReceiver_);
    return ERR_OK;
}

ErrCode PrintShellCommand::ShowCommandHelp(const std::string& targetCmd)
{
    if (targetCmd == "list-added-printers") {
        Json::Value data;
        data["helpText"] = HELP_LIST_ADDED_PRINTERS;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    if (targetCmd == "start-print-job") {
        Json::Value data;
        data["helpText"] = HELP_START_PRINT_JOB;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    OutputError(INVALID_COMMAND, "Unknown command: " + targetCmd,
        "Run '" + std::string(name_) + " help' for available commands", resultReceiver_);
    return ERR_INVALID_VALUE;
}

ErrCode PrintShellCommand::RunAsHelpCommand()
{
    std::string targetCmd;
    if (!argList_.empty()) {
        targetCmd = argList_[0];
    }

    if (targetCmd.empty()) {
        return ShowGeneralHelp();
    }
    return ShowCommandHelp(targetCmd);
}

ErrCode PrintShellCommand::RunAsListAddedPrinters()
{
    optind = OPTIND_SUBCOMMAND_START; // Skip program name and subcommand name
    int opt;
    while ((opt = getopt_long(argc_, argv_, LIST_ADDED_PRINTERS_SHORT_OPTIONS,
                              LIST_ADDED_PRINTERS_LONG_OPTIONS, nullptr)) != -1) {
        switch (opt) {
            case LIST_OPTION_HELP:
                argList_.clear();
                argList_.push_back("list-added-printers");
                return RunAsHelpCommand();
            default:
                OutputError(ERR_INVALID_INPUT,
                    "Invalid option. Run 'ohos-print list-added-printers --help' for usage.",
                    "Check the command syntax and try again", resultReceiver_);
                return ERR_INVALID_VALUE;
        }
    }

    auto& client = PrintManagerClient::GetInstance();
    std::vector<std::string> printerNameList;
    int32_t ret = client.QueryAddedPrinter(printerNameList);
    if (ret != E_PRINT_NONE) {
        return HandleQueryAddedPrinterError(ret);
    }

    Json::Value printersArr(Json::arrayValue);
    BuildPrinterList(printerNameList, printersArr);
    Json::Value data;
    data["printers"] = printersArr;
    data["count"] = static_cast<Json::UInt>(printersArr.size());
    OutputSuccess(data, resultReceiver_);
    return ERR_OK;
}

ErrCode PrintShellCommand::RunAsStartPrintJob()
{
    PrintJobParams params;
    int32_t parseRet = ParseStartPrintJobOptions(params);
    if (parseRet == PARSE_HELP_DISPLAYED) {
        return ERR_OK;
    }

    int32_t validateRet = ValidateRequiredParams(params);
    if (parseRet != ERR_OK || validateRet != ERR_OK) {
        return ERR_INVALID_VALUE;
    }

    std::string jobName = ExtractJobName(params.filePath);
    std::vector<uint32_t> fdList;
    int32_t fileRet = OpenFileForPrint(params.filePath, fdList);
    if (fileRet != ERR_OK) {
        CloseFdList(fdList);
        return ERR_INVALID_VALUE;
    }

    if (params.printerId.empty()) {
        int32_t idRet = ResolvePrinterId(params.printerId);
        if (idRet != ERR_OK) {
            CloseFdList(fdList);
            return ERR_INVALID_VALUE;
        }
    }

    if (params.printerUri.empty()) {
        int32_t uriRet = ResolvePrinterUri(params.printerId, params.printerUri);
        if (uriRet != ERR_OK) {
            CloseFdList(fdList);
            return ERR_INVALID_VALUE;
        }
    }

    int32_t statusRet = CheckPrinterStatus(params.printerId, params.printerStatusInput);
    if (statusRet != ERR_OK) {
        CloseFdList(fdList);
        return ERR_INVALID_VALUE;
    }

    int32_t submitRet = BuildAndSubmitPrintJob(params, fdList, jobName);
    CloseFdList(fdList);
    if (submitRet != ERR_OK) {
        return ERR_INVALID_VALUE;
    }

    Json::Value data;
    data["printerId"] = params.printerId;
    data["jobName"] = jobName;
    data["state"] = JOB_STATE_QUEUED;
    OutputSuccess(data, resultReceiver_);
    return ERR_OK;
}

// ========== List-added-printers helpers ==========

void PrintShellCommand::MarshalPrinterInfo(const PrinterInfo &info, Json::Value &data)
{
    data["printerId"] = info.GetPrinterId();
    data["printerName"] = info.GetPrinterName();
    data["uri"] = info.GetUri();
    if (info.HasIsDefaultPrinter()) {
        data["isDefaultPrinter"] = info.GetIsDefaultPrinter();
    }
    if (info.HasPrinterStatus()) {
        data["printerStatus"] = info.GetPrinterStatus();
    }
    if (info.HasPrinterMake()) {
        data["printerMake"] = info.GetPrinterMake();
    }
    if (info.HasAlias()) {
        data["alias"] = info.GetAlias();
    }
    Json::StreamWriterBuilder wBuilder;
    wBuilder["indentation"] = "";
    PRINT_HILOGI("MarshalPrinterInfo success.");
}

int32_t PrintShellCommand::HandleQueryAddedPrinterError(int32_t ret)
{
    if (ret == E_PRINT_NO_PERMISSION) {
        OutputError(ERR_PERMISSION_DENIED,
            "Permission denied: " + std::string(PRINT_PERMISSION) + " is required to query added printers",
            "Please ensure the application has the PRINT permission declared in its configuration",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (ret == E_PRINT_RPC_FAILURE) {
        OutputError(ERR_PRINT_RPC_FAILURE,
            "RPC failure: Failed to communicate with print service",
            "Check if the print service is running and network connectivity is normal",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    OutputError(ERR_PRINT_QUERY_FAILED,
        "Failed to query added printers, error code: " + std::to_string(ret),
        "Check system logs for more details about the print service", resultReceiver_);
    return ERR_INVALID_VALUE;
}

void PrintShellCommand::BuildPrinterList(const std::vector<std::string>& printerNameList, Json::Value& printersArr)
{
    auto& client = PrintManagerClient::GetInstance();
    for (const auto &printerId : printerNameList) {
        PrinterInfo info;
        int32_t infoRet = client.QueryPrinterInfoByPrinterId(printerId, info);
        if (infoRet != E_PRINT_NONE) {
            PRINT_HILOGI("QueryPrinterInfoByPrinterId failed for %{public}s, ret=%{public}d, skipping",
                printerId.c_str(), infoRet);
            continue;
        }
        Json::Value printerJson;
        MarshalPrinterInfo(info, printerJson);
        printersArr.append(printerJson);
    }
}

// ========== Start-print-job helpers ==========

void PrintShellCommand::ApplyStartPrintJobOption(int opt, PrintJobParams& params)
{
    switch (opt) {
        case START_OPTION_PRINTER_ID:
            params.printerId = optarg;
            break;
        case START_OPTION_PRINTER_URI:
            params.printerUri = optarg;
            break;
        case START_OPTION_FILE_PATH:
            params.filePath = optarg;
            break;
        case START_OPTION_DOCUMENT_FORMAT:
            params.documentFormat = optarg;
            break;
        case START_OPTION_PRINTER_STATUS:
            params.printerStatusInput = optarg;
            break;
        case START_OPTION_COPIES:
            params.copiesInput = optarg;
            break;
        case START_OPTION_PAGE_SIZE:
            params.pageSizeInput = optarg;
            break;
        case START_OPTION_DIRECTION:
            params.directionInput = optarg;
            break;
        case START_OPTION_COLOR_MODE:
            params.colorModeInput = optarg;
            break;
        case START_OPTION_DUPLEX:
            params.duplexInput = optarg;
            break;
        case START_OPTION_PAGE_RANGE:
            params.pageRangeInput = optarg;
            break;
        case START_OPTION_COLLATE:
            params.collateInput = optarg;
            params.collate = (params.collateInput == "true" || params.collateInput == "1");
            break;
        default:
            break;
    }
}

int32_t PrintShellCommand::ParseStartPrintJobOptions(PrintJobParams& params)
{
    optind = OPTIND_SUBCOMMAND_START; // Skip program name and subcommand name
    int opt;
    while ((opt = getopt_long(argc_, argv_, START_PRINT_JOB_SHORT_OPTIONS,
                              START_PRINT_JOB_LONG_OPTIONS, nullptr)) != -1) {
        if (opt == START_OPTION_HELP) {
            argList_.clear();
            argList_.push_back("start-print-job");
            RunAsHelpCommand();
            return PARSE_HELP_DISPLAYED;
        }
        if (opt == '?') {
            OutputError(ERR_INVALID_INPUT,
                "Invalid option. Run 'ohos-print start-print-job --help' for usage.",
                "Check the command syntax and try again", resultReceiver_);
            return ERR_INVALID_VALUE;
        }
        ApplyStartPrintJobOption(opt, params);
    }
    return ERR_OK;
}

int32_t PrintShellCommand::ValidateRequiredParams(const PrintJobParams& params)
{
    if (params.filePath.empty()) {
        OutputError(ERR_ARG_MISSING,
            "Missing required parameter: --file-path",
            "Provide the file path to print. Example: --file-path /data/test.pdf",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (params.documentFormat.empty()) {
        OutputError(ERR_ARG_MISSING,
            "Missing required parameter: --document-format",
            "Provide the document format. Example: --document-format application/pdf",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

void PrintShellCommand::CloseFdList(std::vector<uint32_t>& fdList)
{
    for (uint32_t fd : fdList) {
        close(static_cast<int>(fd));
    }
    fdList.clear();
}

int32_t PrintShellCommand::OpenFileForPrint(const std::string& filePath, std::vector<uint32_t>& fdList)
{
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            OutputError(ERR_FILE_OPEN_FAILED,
                "Failed to open file: " + filePath + ", error: file not exist",
                "Please check the file path exists and is readable", resultReceiver_);
        } else if (errno == EACCES) {
            OutputError(ERR_FILE_OPEN_FAILED,
                "Failed to open file: " + filePath + ", error: file exists, but no rights",
                "Please check the file path exists and is readable", resultReceiver_);
        } else {
            OutputError(ERR_FILE_OPEN_FAILED,
                "Failed to open file: " + filePath + ", error: " + strerror(errno),
                "Please check the file path exists and is readable", resultReceiver_);
        }
        return ERR_INVALID_VALUE;
    }
    struct stat fdStat;
    if (fstat(fd, &fdStat) < 0) {
        close(fd);
        OutputError(ERR_INVALID_FD,
            "File descriptor is invalid after opening file: " + filePath,
            "Please check the file is accessible", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    PRINT_HILOGI("Opened file: %{public}s, fd: %{public}d", filePath.c_str(), fd);
    fdList.push_back(static_cast<uint32_t>(fd));
    return ERR_OK;
}

int32_t PrintShellCommand::ResolvePrinterId(std::string& printerId)
{
    auto& client = PrintManagerClient::GetInstance();
    std::vector<std::string> printerNameList;
    int32_t queryRet = client.QueryAddedPrinter(printerNameList);
    if (queryRet != E_PRINT_NONE) {
        OutputError(ERR_PRINT_QUERY_FAILED,
            "Failed to query added printers, error code: " + std::to_string(queryRet),
            "Please provide --printer-id explicitly, or ensure the print service is available",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (printerNameList.empty()) {
        OutputError(ERR_NO_PRINTER,
            "No printer available in the system",
            "Please add a printer first, or provide --printer-id explicitly", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    for (const auto &pid : printerNameList) {
        PrinterInfo info;
        int32_t infoRet = client.QueryPrinterInfoByPrinterId(pid, info);
        if (infoRet == E_PRINT_NONE &&
            info.HasIsDefaultPrinter() && info.GetIsDefaultPrinter()) {
            printerId = pid;
            return ERR_OK;
        }
    }
    OutputError(ERR_NO_DEFAULT_PRINTER,
        "No default printer found in the system",
        "Please set a default printer or provide --printer-id explicitly", resultReceiver_);
    return ERR_INVALID_VALUE;
}

int32_t PrintShellCommand::ResolvePrinterUri(const std::string& printerId, std::string& printerUri)
{
    auto& client = PrintManagerClient::GetInstance();
    PrinterInfo info;
    int32_t infoRet = client.QueryPrinterInfoByPrinterId(printerId, info);
    if (infoRet != E_PRINT_NONE) {
        OutputError(ERR_PRINT_QUERY_FAILED,
            "Failed to query printer info for URI, error code: " + std::to_string(infoRet),
            "Please provide --printer-uri explicitly, or ensure the printer is available",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (info.HasUri()) {
        printerUri = info.GetUri();
    }
    if (printerUri.empty()) {
        OutputError(ERR_NO_PRINTER_URI,
            "Printer URI not available for the specified printer",
            "Please provide --printer-uri explicitly", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

int32_t PrintShellCommand::CheckPrinterStatus(const std::string& printerId, const std::string& printerStatusInput)
{
    uint32_t printerStatus = UINT32_MAX;
    if (!printerStatusInput.empty()) {
        if (!SafeParseUint32(printerStatusInput, printerStatus)) {
            OutputError(ERR_INVALID_INPUT,
                "Invalid printer status value: " + printerStatusInput,
                "Printer status must be a non-negative integer within uint32 range",
                resultReceiver_);
            return ERR_INVALID_VALUE;
        }
    } else {
        auto& client = PrintManagerClient::GetInstance();
        PrinterInfo info;
        int32_t infoRet = client.QueryPrinterInfoByPrinterId(printerId, info);
        if (infoRet != E_PRINT_NONE) {
            OutputError(ERR_PRINT_QUERY_FAILED,
                "Failed to query printer info for: " + printerId,
                "Please check the printer is connected and the print service is available,\n"
                "or use --printer-status to specify the status manually", resultReceiver_);
            return ERR_INVALID_VALUE;
        }
        if (info.HasPrinterStatus()) {
            printerStatus = info.GetPrinterStatus();
        }
    }
    if (printerStatus == PRINTER_STATUS_UNAVAILABLE) {
        OutputError(ERR_PRINTER_UNAVAILABLE,
            "Printer is unavailable (status=UNAVAILABLE), cannot submit print job",
            "Please connect the printer before submitting a print job,\n"
            "or use list-added-printers to check printer status", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

void PrintShellCommand::BuildOptionsJson(const PrintJobParams& params, const std::string& jobName,
    uint32_t copyNumber, Json::Value& optionsJson)
{
    optionsJson["jobName"] = jobName;
    Json::Value jobDesArr(Json::arrayValue);
    jobDesArr.append(jobName);
    bool isImageFormat = params.documentFormat.compare(0, strlen(IMAGE_FORMAT_PREFIX), IMAGE_FORMAT_PREFIX) == 0;
    jobDesArr.append(isImageFormat ? "1" : "0");
    jobDesArr.append(isImageFormat ? "0" : "1");
    optionsJson["jobDesArr"] = jobDesArr;
    optionsJson["printerUri"] = params.printerUri;
    optionsJson["documentFormat"] = params.documentFormat;
    if (!params.copiesInput.empty()) {
        optionsJson["copies"] = std::to_string(copyNumber);
    }
    if (!params.pageSizeInput.empty()) {
        optionsJson["pageSize"] = MapPageSizeToId(params.pageSizeInput);
    }
    if (!params.directionInput.empty()) {
        optionsJson["direction"] = MapDirectionToOption(params.directionInput);
    }
    if (!params.colorModeInput.empty()) {
        optionsJson["colorMode"] = MapColorModeToOption(params.colorModeInput);
    }
    if (!params.duplexInput.empty()) {
        optionsJson["duplex"] = MapDuplexToOption(params.duplexInput);
    }
    if (!params.pageRangeInput.empty()) {
        optionsJson["pageRange"] = params.pageRangeInput;
    }
    if (!params.collateInput.empty()) {
        optionsJson["collate"] = params.collate ? COLLATE_MODE : SEQUENTIAL_MODE;
    }
}

int32_t PrintShellCommand::SetPageRangeOnJob(const std::string& pageRangeInput, PrintJob& printJob)
{
    PrintRange pageRange;
    size_t dashPos = pageRangeInput.find('-');
    if (dashPos != std::string::npos) {
        uint32_t startPage = 0;
        uint32_t endPage = 0;
        if (!SafeParseUint32(pageRangeInput.substr(0, dashPos), startPage) ||
            !SafeParseUint32(pageRangeInput.substr(dashPos + 1), endPage)) {
            OutputError(ERR_INVALID_INPUT,
                "Invalid page range: " + pageRangeInput,
                "Page numbers must be non-negative integers within uint32 range",
                resultReceiver_);
            return ERR_INVALID_VALUE;
        }
        if (startPage > endPage) {
            OutputError(ERR_INVALID_INPUT,
                "Invalid page range: " + pageRangeInput,
                "Start page must not be greater than end page",
                resultReceiver_);
            return ERR_INVALID_VALUE;
        }
        pageRange.SetStartPage(startPage);
        pageRange.SetEndPage(endPage);
    } else {
        std::vector<uint32_t> pages;
        std::istringstream ss(pageRangeInput);
        std::string token;
        while (std::getline(ss, token, ',')) {
            uint32_t pageNum = 0;
            if (!SafeParseUint32(token, pageNum)) {
                OutputError(ERR_INVALID_INPUT,
                    "Invalid page number in range: " + token,
                    "Page numbers must be non-negative integers within uint32 range",
                    resultReceiver_);
                return ERR_INVALID_VALUE;
            }
            pages.push_back(pageNum);
        }
        pageRange.SetPages(pages);
    }
    printJob.SetPageRange(pageRange);
    return ERR_OK;
}

void PrintShellCommand::SetPageSizeOnJob(const std::string& pageSizeId, PrintJob& printJob)
{
    PrintPageSize pageSize;
    if (PrintPageSize::FindPageSizeById(pageSizeId, pageSize)) {
        printJob.SetPageSize(pageSize);
    } else {
        pageSize.SetId(pageSizeId);
        pageSize.SetName(FALLBACK_PAGE_SIZE_NAME);
        pageSize.SetWidth(FALLBACK_PAGE_SIZE_WIDTH);
        pageSize.SetHeight(FALLBACK_PAGE_SIZE_HEIGHT);
        printJob.SetPageSize(pageSize);
    }
}

int32_t PrintShellCommand::MapInputParams(const PrintJobParams& params, MappedParams& mapped)
{
    if (!params.copiesInput.empty()) {
        if (!ParseCopies(params.copiesInput, mapped.copyNumber)) {
            OutputError(ERR_INVALID_INPUT,
                "Invalid copies: " + params.copiesInput,
                "Copies must be a non-negative integer within uint32 range",
                resultReceiver_);
            return ERR_INVALID_VALUE;
        }
    } else {
        mapped.copyNumber = DEFAULT_COPIES;
    }
    mapped.pageSizeId = params.pageSizeInput.empty() ? DEFAULT_PAGE_SIZE_ID : MapPageSizeToId(params.pageSizeInput);
    mapped.direction = MapDirection(params.directionInput.empty() ? DEFAULT_DIRECTION : params.directionInput);
    mapped.colorMode = MapColorMode(params.colorModeInput.empty() ? DEFAULT_COLOR_MODE : params.colorModeInput);
    mapped.duplexMode = MapDuplex(params.duplexInput.empty() ? DEFAULT_DUPLEX_MODE : params.duplexInput);
    return ERR_OK;
}

int32_t PrintShellCommand::BuildAndSubmitPrintJob(const PrintJobParams& params,
    const std::vector<uint32_t>& fdList, const std::string& jobName)
{
    MappedParams mapped;
    int32_t mapRet = MapInputParams(params, mapped);
    if (mapRet != ERR_OK) {
        return mapRet;
    }
    PrintJob printJob;
    printJob.SetFdList(fdList);
    printJob.SetPrinterId(params.printerId);
    printJob.SetCopyNumber(mapped.copyNumber);
    printJob.SetIsLandscape(mapped.direction == DIRECTION_MODE_LANDSCAPE);
    printJob.SetColorMode(mapped.colorMode);
    printJob.SetDuplexMode(mapped.duplexMode);
    printJob.SetIsSequential(!params.collate);

    if (!params.pageRangeInput.empty()) {
        int32_t rangeRet = SetPageRangeOnJob(params.pageRangeInput, printJob);
        if (rangeRet != ERR_OK) {
            return ERR_INVALID_VALUE;
        }
    }

    SetPageSizeOnJob(mapped.pageSizeId, printJob);

    Json::Value optionsJson;
    BuildOptionsJson(params, jobName, mapped.copyNumber, optionsJson);
    Json::StreamWriterBuilder wBuilder;
    wBuilder["indentation"] = "";
    printJob.SetOption(Json::writeString(wBuilder, optionsJson));

    auto& client = PrintManagerClient::GetInstance();
    int32_t ret = client.StartNativePrintJob(printJob);
    return HandleStartPrintJobResult(ret);
}

int32_t PrintShellCommand::HandleStartPrintJobResult(int32_t ret)
{
    if (ret == E_PRINT_NONE) {
        return ERR_OK;
    }
    if (ret == E_PRINT_NO_PERMISSION) {
        OutputError(ERR_PERMISSION_DENIED,
            "Permission denied: " + std::string(PRINT_PERMISSION) + " is required",
            "Please ensure the application has the PRINT permission declared in its configuration",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (ret == E_PRINT_RPC_FAILURE) {
        OutputError(ERR_PRINT_RPC_FAILURE,
            "RPC failure: Failed to communicate with print service",
            "Check if the print service is running and network connectivity is normal",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (ret == E_PRINT_INVALID_PRINTER) {
        OutputError(ERR_INVALID_PRINTER,
            "Invalid printer: The specified printer does not exist",
            "Please check the printer-id and ensure the printer is added",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    OutputError(ERR_PRINT_JOB_FAILED,
        "Failed to start print job, error code: " + std::to_string(ret),
        "Check system logs for more details about the print service",
        resultReceiver_);
    return ERR_INVALID_VALUE;
}

// ========== Public static utility methods ==========

bool PrintShellCommand::SafeParseUint32(const std::string& input, uint32_t& result)
{
    if (input.empty()) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long val = strtoul(input.c_str(), &end, 10);
    if (errno != 0 || *end != '\0' || val > UINT32_MAX) {
        return false;
    }
    result = static_cast<uint32_t>(val);
    return true;
}

std::string PrintShellCommand::ExtractJobName(const std::string& filePath)
{
    size_t lastSlash = filePath.rfind('/');
    if (lastSlash != std::string::npos && lastSlash + 1 < filePath.size()) {
        return filePath.substr(lastSlash + 1);
    }
    return filePath;
}

bool PrintShellCommand::ParseCopies(const std::string& input, uint32_t& result)
{
    return SafeParseUint32(input, result);
}

std::string PrintShellCommand::MapPageSizeToId(const std::string& input)
{
    if (input == "A4") {
        return PAGE_SIZE_ID_A4;
    }
    if (input == "A3") {
        return PAGE_SIZE_ID_A3;
    }
    if (input == "A5") {
        return PAGE_SIZE_ID_A5;
    }
    if (input == "B5") {
        return PAGE_SIZE_ID_B5;
    }
    if (input == "Letter") {
        return PAGE_SIZE_ID_LETTER;
    }
    if (input == "Legal") {
        return PAGE_SIZE_ID_LEGAL;
    }
    return DEFAULT_PAGE_SIZE_ID;
}

uint32_t PrintShellCommand::MapDirection(const std::string& input)
{
    if (input == "横向" || input == "landscape") {
        return DIRECTION_MODE_LANDSCAPE;
    }
    if (input == "自动" || input == "auto") {
        return DIRECTION_MODE_AUTO;
    }
    return DIRECTION_MODE_PORTRAIT;
}

std::string PrintShellCommand::MapDirectionToOption(const std::string& input)
{
    if (input == "横向" || input == "landscape") {
        return DIRECTION_LANDSCAPE;
    }
    if (input == "自动" || input == "auto") {
        return DIRECTION_AUTO;
    }
    return DIRECTION_PORTRAIT;
}

uint32_t PrintShellCommand::MapColorMode(const std::string& input)
{
    if (input == "彩色" || input == "彩印" || input == "color") {
        return COLOR_MODE_COLOR_VALUE;
    }
    return COLOR_MODE_MONO_VALUE;
}

std::string PrintShellCommand::MapColorModeToOption(const std::string& input)
{
    if (input == "彩色" || input == "彩印" || input == "color") {
        return COLOR_MODE_COLOR_VALUE;
    }
    return COLOR_MODE_MONO_VALUE;
}

uint32_t PrintShellCommand::MapDuplex(const std::string& input)
{
    if (input == "双面" || input == "双面长边" || input == "long") {
        return DUPLEX_MODE_TWO_SIDED_LONG_EDGE;
    }
    if (input == "双面短边" || input == "short") {
        return DUPLEX_MODE_TWO_SIDED_SHORT_EDGE;
    }
    return DUPLEX_MODE_ONE_SIDED;
}

std::string PrintShellCommand::MapDuplexToOption(const std::string& input)
{
    if (input == "双面" || input == "双面长边" || input == "long") {
        return DUPLEX_LONG;
    }
    if (input == "双面短边" || input == "short") {
        return DUPLEX_SHORT;
    }
    return DUPLEX_NONE;
}
}  // namespace Print
}  // namespace OHOS
