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

#ifndef PRINT_FWK_TOOLS_OHOS_PRINT_PRINT_SHELL_COMMAND_H
#define PRINT_FWK_TOOLS_OHOS_PRINT_PRINT_SHELL_COMMAND_H

#include <cstdint>
#include <string>
#include <vector>

#include <getopt.h>

#include "shell_command.h"
#include "command_output.h"
#include "printer_info.h"
#include "print_job.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Print {

// --- Tool identity ---
constexpr char TOOL_NAME[] = "ohos-print";
constexpr uint32_t COMMAND_TIME_OUT = 30;

// --- Error code strings ---
constexpr char ERR_PERMISSION_DENIED[] = "ERR_PERMISSION_DENIED";
constexpr char ERR_PRINT_RPC_FAILURE[] = "ERR_PRINT_RPC_FAILURE";
constexpr char ERR_PRINT_QUERY_FAILED[] = "ERR_PRINT_QUERY_FAILED";
constexpr char ERR_FILE_OPEN_FAILED[] = "ERR_FILE_OPEN_FAILED";
constexpr char ERR_NO_PRINTER[] = "ERR_NO_PRINTER";
constexpr char ERR_NO_DEFAULT_PRINTER[] = "ERR_NO_DEFAULT_PRINTER";
constexpr char ERR_NO_PRINTER_URI[] = "ERR_NO_PRINTER_URI";
constexpr char ERR_PRINTER_UNAVAILABLE[] = "ERR_PRINTER_UNAVAILABLE";
constexpr char ERR_INVALID_PRINTER[] = "ERR_INVALID_PRINTER";
constexpr char ERR_PRINT_JOB_FAILED[] = "ERR_PRINT_JOB_FAILED";
constexpr char ERR_INVALID_FD[] = "ERR_INVALID_FD";
constexpr char ERR_INVALID_INPUT[] = "ERR_INVALID_INPUT";
constexpr char ERR_ARG_MISSING[] = "ERR_ARG_MISSING";
constexpr char ERR_COMMAND_TIMEOUT[] = "ERR_COMMAND_TIMEOUT";
constexpr char INVALID_COMMAND[] = "INVALID_COMMAND";

// --- Page size ID constants ---
constexpr char PAGE_SIZE_ID_A4[] = "ISO_A4";
constexpr char PAGE_SIZE_ID_A3[] = "ISO_A3";
constexpr char PAGE_SIZE_ID_A5[] = "ISO_A5";
constexpr char PAGE_SIZE_ID_B5[] = "ISO_B5";
constexpr char PAGE_SIZE_ID_LETTER[] = "NA_LETTER";
constexpr char PAGE_SIZE_ID_LEGAL[] = "NA_LEGAL";

// --- Page size option constants ---

// --- Direction option constants ---
constexpr char DIRECTION_LANDSCAPE[] = "landscape";
constexpr char DIRECTION_PORTRAIT[] = "portrait";
constexpr char DIRECTION_AUTO[] = "auto";

// --- Color mode option constants ---
constexpr char COLOR_MODE_COLOR[] = "color";
constexpr char COLOR_MODE_MONO[] = "mono";
constexpr uint32_t COLOR_MODE_MONO_VALUE = 0;
constexpr uint32_t COLOR_MODE_COLOR_VALUE = 1;

// --- Duplex option constants ---
constexpr char DUPLEX_LONG[] = "long";
constexpr char DUPLEX_SHORT[] = "short";
constexpr char DUPLEX_NONE[] = "none";
constexpr uint32_t DUPLEX_MODE_ONE_SIDED = 0;
constexpr uint32_t DUPLEX_MODE_TWO_SIDED_LONG_EDGE = 1;
constexpr uint32_t DUPLEX_MODE_TWO_SIDED_SHORT_EDGE = 2;

// --- option index offset ---
constexpr int OPTIND_SUBCOMMAND_START = 2;

// --- Default values ---
constexpr uint32_t DEFAULT_COPIES = 1;
constexpr char DEFAULT_PAGE_SIZE_ID[] = "ISO_A4";
constexpr char DEFAULT_DIRECTION[] = "纵向";
constexpr char DEFAULT_COLOR_MODE[] = "黑白";
constexpr char DEFAULT_DUPLEX_MODE[] = "单面";

// --- Fallback page size ---
constexpr char FALLBACK_PAGE_SIZE_NAME[] = "iso_a4_210x297mm";
constexpr int32_t FALLBACK_PAGE_SIZE_WIDTH = 8268;
constexpr int32_t FALLBACK_PAGE_SIZE_HEIGHT = 11692;

// --- Image format prefix ---
constexpr char IMAGE_FORMAT_PREFIX[] = "image/";

// --- Collate option strings ---
constexpr char COLLATE_MODE[] = "collate";
constexpr char SEQUENTIAL_MODE[] = "sequential";

// --- Job state ---
constexpr char JOB_STATE_QUEUED[] = "QUEUED";

// --- Print permission ---
constexpr char PRINT_PERMISSION[] = "ohos.permission.PRINT";

// --- Tool help description ---
constexpr char TOOL_DESCRIPTION[] = "Print management utility for querying and managing printers on the system";

// --- Subcommand descriptions ---
constexpr char CMD_DESC_LIST_ADDED_PRINTERS[] = "Query detailed information of all added printers";
constexpr char CMD_DESC_START_PRINT_JOB[] = "Start a print job";

// --- list-added-printers help text ---
constexpr char HELP_LIST_ADDED_PRINTERS[] =
    "ohos-print list-added-printers - List all added printers with detailed information\n\n"
    "Usage:\n  ohos-print list-added-printers\n\n"
    "Parameters:\n    (No parameters required)\n"
    "    --help                   Display this help message\n\n"
    "Examples:\n  ohos-print list-added-printers";

// --- start-print-job help text ---
constexpr char HELP_START_PRINT_JOB[] =
    "ohos-print start-print-job - Start a print job\n\n"
    "Usage:\n  ohos-print start-print-job [options]\n\n"
    "Required Parameters:\n"
    "  --file-path <string>        File path to print (e.g., /data/test.pdf)\n"
    "  --document-format <string>  Document format (e.g., application/pdf)\n\n"
    "Optional Parameters:\n"
    "  --printer-id <string>       Printer identifier\n"
    "                              (if not provided, the default printer will be used)\n"
    "  --printer-uri <string>      Printer URI\n"
    "                              (e.g., lpd://192.168.43.187:515/auto,\n"
    "                              auto-derived from printer-id if not provided)\n"
    "  --printer-status <uint32>   Printer status\n"
    "                              (0=IDLE, 1=BUSY, 2=UNAVAILABLE;\n"
    "                              auto-derived if not provided)\n"
    "  --copies <string>           Number of copies (e.g., 3, 3份, 5份, default: 1)\n"
    "  --page-size <string>        Page size: A4, A3, A5, B5, Letter, Legal (default: A4)\n"
    "  --direction <string>        Print direction:\n"
    "                              纵向/竖向/portrait, 横向/landscape, 自动/auto\n"
    "                              (default: 纵向)\n"
    "  --color-mode <string>       Color mode: 彩色/彩印/color, 黑白/单色/mono (default: 黑白)\n"
    "  --duplex <string>           Duplex mode: 单面/none, 双面/双面长边/long, 双面短边/short (default: 单面)\n"
    "  --page-range <string>       Page range: start-end (e.g., 1-5) or specific pages (e.g., 1,3,5)\n"
    "  --collate <bool>            Collate mode: true=逐份, false=逐页 (default: true)\n"
    "    --help                   Display this help message\n\n"
    "Examples:\n"
    "  ohos-print start-print-job --file-path /data/test.pdf\n"
    "      --document-format application/pdf\n"
    "  ohos-print start-print-job --file-path /data/test.pdf\n"
    "      --document-format application/pdf\n"
    "      --printer-id printer001 --copies 3 --page-size A4\n"
    "      --direction 纵向 --color-mode 彩色 --duplex 双面";

// --- OptionIndex enums for list-added-printers subcommand ---
enum ListAddedPrintersOptionIndex {
    LIST_OPTION_HELP = 1000,
};

constexpr struct option LIST_ADDED_PRINTERS_LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, LIST_OPTION_HELP},
    {nullptr, 0, nullptr, 0},
};

constexpr char LIST_ADDED_PRINTERS_SHORT_OPTIONS[] = "";

// --- OptionIndex enums for start-print-job subcommand ---
enum StartPrintJobOptionIndex {
    START_OPTION_HELP = 1000,
    START_OPTION_PRINTER_ID,
    START_OPTION_PRINTER_URI,
    START_OPTION_FILE_PATH,
    START_OPTION_DOCUMENT_FORMAT,
    START_OPTION_PRINTER_STATUS,
    START_OPTION_COPIES,
    START_OPTION_PAGE_SIZE,
    START_OPTION_DIRECTION,
    START_OPTION_COLOR_MODE,
    START_OPTION_DUPLEX,
    START_OPTION_PAGE_RANGE,
    START_OPTION_COLLATE,
};

constexpr struct option START_PRINT_JOB_LONG_OPTIONS[] = {
    {"help",            no_argument,       nullptr, START_OPTION_HELP},
    {"printer-id",      required_argument, nullptr, START_OPTION_PRINTER_ID},
    {"printer-uri",     required_argument, nullptr, START_OPTION_PRINTER_URI},
    {"file-path",       required_argument, nullptr, START_OPTION_FILE_PATH},
    {"document-format", required_argument, nullptr, START_OPTION_DOCUMENT_FORMAT},
    {"printer-status",  required_argument, nullptr, START_OPTION_PRINTER_STATUS},
    {"copies",          required_argument, nullptr, START_OPTION_COPIES},
    {"page-size",       required_argument, nullptr, START_OPTION_PAGE_SIZE},
    {"direction",       required_argument, nullptr, START_OPTION_DIRECTION},
    {"color-mode",      required_argument, nullptr, START_OPTION_COLOR_MODE},
    {"duplex",          required_argument, nullptr, START_OPTION_DUPLEX},
    {"page-range",      required_argument, nullptr, START_OPTION_PAGE_RANGE},
    {"collate",         required_argument, nullptr, START_OPTION_COLLATE},
    {nullptr,           0,                 nullptr, 0},
};

constexpr char START_PRINT_JOB_SHORT_OPTIONS[] = "";

struct PrintJobParams {
    std::string printerUri;
    std::string filePath;
    std::string documentFormat;
    std::string printerId;
    std::string printerStatusInput;
    std::string copiesInput;
    std::string pageSizeInput;
    std::string directionInput;
    std::string colorModeInput;
    std::string duplexInput;
    std::string pageRangeInput;
    std::string collateInput;
    bool collate = true;
};

struct MappedParams {
    uint32_t copyNumber;
    std::string pageSizeId;
    bool isLandscape;
    uint32_t colorMode;
    uint32_t duplexMode;
};

class PrintShellCommand : public ShellCommand {
public:
    PrintShellCommand(int argc, char* argv[]);
    ~PrintShellCommand() override = default;

    // Public static utility methods for testability
    static bool SafeParseUint32(const std::string& input, uint32_t& result);
    static std::string ExtractJobName(const std::string& filePath);
    static bool ParseCopies(const std::string& input, uint32_t& result);
    static std::string MapPageSizeToId(const std::string& input);
    static bool MapDirection(const std::string& input);
    static std::string MapDirectionToOption(const std::string& input);
    static uint32_t MapColorMode(const std::string& input);
    static std::string MapColorModeToOption(const std::string& input);
    static uint32_t MapDuplex(const std::string& input);
    static std::string MapDuplexToOption(const std::string& input);

private:
    ErrCode CreateCommandMap() override;
    ErrCode Init() override;

    // --- Subcommand handlers ---
    ErrCode ShowGeneralHelp();
    ErrCode ShowCommandHelp(const std::string& targetCmd);
    ErrCode RunAsHelpCommand();
    ErrCode RunAsListAddedPrinters();
    ErrCode RunAsStartPrintJob();

    // --- List-added-printers helpers ---
    void MarshalPrinterInfo(const PrinterInfo &info, nlohmann::json &data);
    int32_t HandleQueryAddedPrinterError(int32_t ret);
    void BuildPrinterList(const std::vector<std::string>& printerNameList, nlohmann::json& printersArr);

    // --- Start-print-job helpers ---
    void ApplyStartPrintJobOption(int opt, PrintJobParams& params);
    int32_t ParseStartPrintJobOptions(PrintJobParams& params);
    int32_t ValidateRequiredParams(const PrintJobParams& params);
    void CloseFdList(std::vector<uint32_t>& fdList);
    int32_t OpenFileForPrint(const std::string& filePath, std::vector<uint32_t>& fdList);
    int32_t ResolvePrinterId(std::string& printerId);
    int32_t ResolvePrinterUri(const std::string& printerId, std::string& printerUri);
    int32_t CheckPrinterStatus(const std::string& printerId, const std::string& printerStatusInput);
    void BuildOptionsJson(const PrintJobParams& params, const std::string& jobName,
                          uint32_t copyNumber, nlohmann::json& optionsJson);
    int32_t SetPageRangeOnJob(const std::string& pageRangeInput, PrintJob& printJob);
    void SetPageSizeOnJob(const std::string& pageSizeId, PrintJob& printJob);
    int32_t MapInputParams(const PrintJobParams& params, MappedParams& mapped);
    int32_t BuildAndSubmitPrintJob(const PrintJobParams& params,
                                    const std::vector<uint32_t>& fdList,
                                    const std::string& jobName);
    int32_t HandleStartPrintJobResult(int32_t ret);
};
}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_FWK_TOOLS_OHOS_PRINT_PRINT_SHELL_COMMAND_H
