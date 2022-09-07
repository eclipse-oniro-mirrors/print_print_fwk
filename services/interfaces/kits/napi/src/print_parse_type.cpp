
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

#include "print_parse_type.h"

#include "async_call.h"
#include "napi_print_ext.h"
#include "napi_print_utils.h"
#include "print_log.h"
#include "print_manager_client.h"

namespace OHOS::Print {
static constexpr const char *PARAM_INFO_PRINTID = "printerId";
static constexpr const char *PARAM_INFO_PRINTERNAME = "printerName";
static constexpr const char *PARAM_INFO_PRINTERICON = "printerIcon";
static constexpr const char *PARAM_INFO_PRINTERSTATE = "printerState";
static constexpr const char *PARAM_INFO_DESCRIPTION = "description";
static constexpr const char *PARAM_INFO_CAPABILITY = "capability";

static constexpr const char *PARAM_CAPABILITY_MINMARGIN = "minMargin";
static constexpr const char *PARAM_CAPABILITY_PAGESIZE = "pageSize";
static constexpr const char *PARAM_CAPABILITY_RESOLUTION = "resolution";
static constexpr const char *PARAM_CAPABILITY_COLORMODE = "colorMode";
static constexpr const char *PARAM_CAPABILITY_DUPLEXMODE = "duplexMode";

static constexpr const char *PARAM_PAGESIZE_ID = "id";
static constexpr const char *PARAM_PAGESIZE_NAME = "name";
static constexpr const char *PARAM_PAGESIZE_WIDTH = "width";
static constexpr const char *PARAM_PAGESIZE_HEIGHT = "height";

static constexpr const char *PARAM_RESOLUTION_ID = "id";
static constexpr const char *PARAM_RESOLUTION_HORIZONTALDPI = "horizontalDpi";
static constexpr const char *PARAM_RESOLUTION_VERTICALDPI = "verticalDpi";

static constexpr const char *PARAM_MARGIN_TOP = "top";
static constexpr const char *PARAM_MARGIN_BOTTOM = "bottom";
static constexpr const char *PARAM_MARGIN_LEFT = "left";
static constexpr const char *PARAM_MARGIN_RIGHT = "right";

static constexpr const char *PARAM_JOB_FILES = "files";
static constexpr const char *PARAM_JOB_JOBID = "jobId";
static constexpr const char *PARAM_JOB_PRINTERID = "printerId";
static constexpr const char *PARAM_JOB_JOBSTATE = "jobState";
static constexpr const char *PARAM_JOB_COPYNUMBER = "copyNumber";
static constexpr const char *PARAM_JOB_PAGERANGE = "pageRange";
static constexpr const char *PARAM_JOB_ISSEQUENTIAL = "isSequential";
static constexpr const char *PARAM_JOB_PAGESIZE = "pageSize";
static constexpr const char *PARAM_JOB_ISLANDSCAPE = "isLandscape";
static constexpr const char *PARAM_JOB_COLORMODE = "colorMode";
static constexpr const char *PARAM_JOB_DUPLEXMODE = "duplexMode";
static constexpr const char *PARAM_JOB_MARGIN = "margin";
static constexpr const char *PARAM_JOB_PREVIEW = "preview";

static constexpr const char *PARAM_PREATTRIBUTE_RANGE = "previewRange";
static constexpr const char *PARAM_PREATTRIBUTE_RESULT = "result";

static constexpr const char *PARAM_RANGE_STARTPAGE = "startPage";
static constexpr const char *PARAM_RANGE_ENDPAGE = "endPage";
static constexpr const char *PARAM_RANGE_PAGES = "pages";

bool PrintParseType::ParseInfo(napi_env env, napi_value InfoValue, PrinterInfo &info)
{
    if (!ParseInfoParam(env, InfoValue, info)) {
        PRINT_HILOGD("ParseInfoParam is error!");
        return false;
    }
    info.SetPrinterId(NapiPrintUtils::GetUint32Property(env, InfoValue, PARAM_INFO_PRINTID));
    info.SetPrinterName(NapiPrintUtils::GetStringPropertyUtf8(env, InfoValue, PARAM_INFO_PRINTERNAME));
    info.SetPrinterIcon(NapiPrintUtils::GetUint32Property(env, InfoValue, PARAM_INFO_PRINTERICON));
    info.SetPrinterState(NapiPrintUtils::GetUint32Property(env, InfoValue, PARAM_INFO_PRINTERSTATE));
    info.SetDescription(NapiPrintUtils::GetStringPropertyUtf8(env, InfoValue, PARAM_INFO_DESCRIPTION));

    PRINT_HILOGD("info_value printId value is: %{public}d", info.GetPrintId());
    PRINT_HILOGD("info_value printerName value is %{public}s", info.GetPrinterName().c_str());
    PRINT_HILOGD("info_value printerIcon value is %{public}d", info.GetPrinterIcon());
    PRINT_HILOGD("info_value printerState value is  %{public}d", info.GetPrinterState());
    PRINT_HILOGD("info_value description value is  %{public}s", info.GetDescription().c_str());
    return true;
}

bool PrintParseType::ParseCapability(napi_env env, napi_value capValue, PrinterCapability &capability)
{
    if (!ParseCapParam(env, capValue, capability)) {
        PRINT_HILOGD("ParseCapParam is error!");
        return false;
    }
    capability.SetColorMode(NapiPrintUtils::GetUint32Property(env, capValue, PARAM_CAPABILITY_COLORMODE));
    capability.SetDuplexMode(NapiPrintUtils::GetUint32Property(env, capValue, PARAM_CAPABILITY_DUPLEXMODE));
    PRINT_HILOGD("capability_value colorMode value is  %{public}d", capability.GetColorMode());
    PRINT_HILOGD("capability_value duplexMode value is  %{public}d", capability.GetDuplexMode());
    return true;
}

bool PrintParseType::ParsePageSize(napi_env env, napi_value capValue, PrintPageSize &pageSize)
{
    if (!ParsePageSizeParam(env, capValue, pageSize)) {
        PRINT_HILOGD("ParsePageSizeParam is error!");
        return false;
    }
    pageSize.SetId(NapiPrintUtils::GetStringPropertyUtf8(env, capValue, PARAM_PAGESIZE_ID));
    pageSize.SetName(NapiPrintUtils::GetStringPropertyUtf8(env, capValue, PARAM_PAGESIZE_NAME));
    pageSize.SetWidth(NapiPrintUtils::GetUint32Property(env, capValue, PARAM_PAGESIZE_WIDTH));
    pageSize.SetHeight(NapiPrintUtils::GetUint32Property(env, capValue, PARAM_PAGESIZE_HEIGHT));

    PRINT_HILOGD("printerPageSize_value GetId value is %{public}s", pageSize.GetId().c_str());
    PRINT_HILOGD("printerPageSize_value GetName value is %{public}s", pageSize.GetName().c_str());
    PRINT_HILOGD("printerPageSize_value GetWidth value is  %{public}d", pageSize.GetWidth());
    PRINT_HILOGD("printerPageSize_value GetHeight value is  %{public}d", pageSize.GetHeight());
    return true;
}

bool PrintParseType::ParseResolution(napi_env env, napi_value reValue, PrintResolution &resolution)
{
    if (!ParseResolutionParam(env, reValue, resolution)) {
        PRINT_HILOGD("ParseResolutionParam is error!");
        return false;
    }
    resolution.SetId(NapiPrintUtils::GetUint32Property(env, reValue, PARAM_RESOLUTION_ID));
    resolution.SetHorizontalDpi(NapiPrintUtils::GetUint32Property(env, reValue, PARAM_RESOLUTION_HORIZONTALDPI));
    resolution.SetVerticalDpi(NapiPrintUtils::GetUint32Property(env, reValue, PARAM_RESOLUTION_VERTICALDPI));

    PRINT_HILOGD("printerResolution_value GetId value is %{public}d", resolution.GetId());
    PRINT_HILOGD("printerResolution_value GetHorizontalDpi value is %{public}d", resolution.GetHorizontalDpi());
    PRINT_HILOGD("printerResolution_value GetVerticalDpi value is  %{public}d", resolution.GetVerticalDpi());
    return true;
}

bool PrintParseType::ParseMargin(napi_env env, napi_value marginValue, PrintMargin &margin)
{
    if (!ParseMarginParam(env, marginValue, margin)) {
        PRINT_HILOGD("ParseResolutionParam is error!");
        return false;
    }
    margin.SetTop(NapiPrintUtils::GetUint32Property(env, marginValue, PARAM_MARGIN_TOP));
    margin.SetBottom(NapiPrintUtils::GetUint32Property(env, marginValue, PARAM_MARGIN_BOTTOM));
    margin.SetLeft(NapiPrintUtils::GetUint32Property(env, marginValue, PARAM_MARGIN_LEFT));
    margin.SetRight(NapiPrintUtils::GetUint32Property(env, marginValue, PARAM_MARGIN_RIGHT));

    PRINT_HILOGD("printerMargin_value GetTop value is %{public}d", margin.GetTop());
    PRINT_HILOGD("printerMargin_value GetBottom value is %{public}d", margin.GetBottom());
    PRINT_HILOGD("printerMargin_value GetLeft value is  %{public}d", margin.GetLeft());
    PRINT_HILOGD("printerMargin_value GetRight value is  %{public}d", margin.GetRight());

    return true;
}

bool PrintParseType::ParseJob(napi_env env, napi_value jobValue, PrintJob &printJob)
{
    if (!ParseJobParam(env, jobValue, printJob)) {
        PRINT_HILOGD("ParseJobParam is error!");
        return false;
    }
    printJob.SetJobId(NapiPrintUtils::GetUint32Property(env, jobValue, PARAM_JOB_JOBID));
    printJob.SetPrintId(NapiPrintUtils::GetUint32Property(env, jobValue, PARAM_JOB_PRINTERID));
    printJob.SetJobState(NapiPrintUtils::GetUint32Property(env, jobValue, PARAM_JOB_JOBSTATE));
    printJob.SetCopyNumber(NapiPrintUtils::GetUint32Property(env, jobValue, PARAM_JOB_COPYNUMBER));

    PRINT_HILOGD("printJob_value GetJobId value is %{public}d", printJob.GetJobId());
    PRINT_HILOGD("printJob_value GetPrinterId value is %{public}d", printJob.GetPrinterId());
    PRINT_HILOGD("printJob_value GetJobState value is  %{public}d", printJob.GetJobState());
    PRINT_HILOGD("printJob_value GetCopyNumber value is %{public}d", printJob.GetCopyNumber());
    PRINT_HILOGD("printJob_value SetIsLandscape value is %{public}s", printJob.GetIsLandscape() ? "true" : "false");
    PRINT_HILOGD("printJob_value SetIsLandscape value is %{public}s", printJob.GetIsLandscape() ? "true" : "false");
    PRINT_HILOGD("printJob_value ColorMode value is %{public}d", printJob.GetIsSequential());
    PRINT_HILOGD("printJob_value DuplexMode value is %{public}d", printJob.GetDuplexMode());
    return true;
}

bool PrintParseType::ParsePreviewAttribute(napi_env env, napi_value preAttValue, PreviewAttribute &preAtt)
{
    if (!ParsePreviewAttributeParam(env, preAttValue, preAtt)) {
        PRINT_HILOGD("ParsePreviewAttributeParam is error!");
        return false;
    }
    preAtt.SetResult(NapiPrintUtils::GetStringPropertyUtf8(env, preAttValue, PARAM_PREATTRIBUTE_RESULT));
    PRINT_HILOGD("preAtt_value GetResult value is %{public}s", preAtt.GetResult().c_str());
    return true;
}

bool PrintParseType::ParseRange(napi_env env, napi_value rangeValue, PrintRange &range)
{
    if (!ParseRangeParam(env, rangeValue, range)) {
        PRINT_HILOGD("ParseRangeParam is error!");
        return false;
    }
    range.SetStartPage(NapiPrintUtils::GetUint32Property(env, rangeValue, PARAM_RANGE_STARTPAGE));
    range.SetEndPage(NapiPrintUtils::GetUint32Property(env, rangeValue, PARAM_RANGE_ENDPAGE));
    PRINT_HILOGD("printRange_value GetStartPage value is %{public}d", range.GetStartPage());
    PRINT_HILOGD("printRange_value GetEndPage value is %{public}d", range.GetEndPage());
    return true;
}

bool PrintParseType::ParseInfoParam(napi_env env, napi_value InfoValue, PrinterInfo &info)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTID);
    if (NapiPrintUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = NapiPrintUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERNAME);
    if (NapiPrintUtils::GetValueType(env, param_two) != napi_string) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = NapiPrintUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERICON);
    if (NapiPrintUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = NapiPrintUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_PRINTERSTATE);
    if (NapiPrintUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    napi_value param_five = NapiPrintUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_DESCRIPTION);
    if (NapiPrintUtils::GetValueType(env, param_five) != napi_string) {
        PRINT_HILOGD("error param_five");
        return false;
    }
    napi_value param_six = NapiPrintUtils::GetNamedProperty(env, InfoValue, PARAM_INFO_CAPABILITY);
    if (NapiPrintUtils::GetValueType(env, param_six) != napi_object) {
        PRINT_HILOGD("error param_six");
        return false;
    } else {
        PrinterCapability capability;
        if (!ParseCapability(env, param_six, capability)) {
            PRINT_HILOGD("ParseCapability type error!");
            return false;
        }
        info.SetCapability(capability);
    }
    return true;
}

bool PrintParseType::ParseCapParam(napi_env env, napi_value capValue, PrinterCapability &capability)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_MINMARGIN);
    if (NapiPrintUtils::GetValueType(env, param_one) != napi_object) {
        PRINT_HILOGD("error param_one");
        return false;
    } else {
        PrintMargin margin;
        if (!ParseMargin(env, param_one, margin)) {
            PRINT_HILOGD("ParseCapability type error!");
            return false;
        }
        capability.SetMinMargin(margin);
    }

    if (!CoversePriotResolutionObject(env, capValue, capability)) {
        PRINT_HILOGD("error Arr ParsePageSize");
        return false;
    }
    
    if (!ParseArrPrintResolution(env, capValue, capability)) {
        PRINT_HILOGD("error Arr PrintResolution");
        return false;
    }

    napi_value param_four = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_COLORMODE);
    if (NapiPrintUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    napi_value param_five = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_DUPLEXMODE);
    if (NapiPrintUtils::GetValueType(env, param_five) != napi_number) {
        // ParseCapParam()
        PRINT_HILOGD("error param_five");
        return false;
    }
    auto names = NapiPrintUtils::GetPropertyNames(env, capValue);
    return true;
}

void PrintPaeseType::CoversePriotResolutionObject(napi_env env, napi_value capValue, PrinterCapability &capability)
{
     napi_value param_two = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_PAGESIZE);
    if (NapiPrintUtils::GetValueType(env, param_two) != napi_object) {
        PRINT_HILOGD("error param_two");
        return false;
    } else {
        bool isArray = false;
        napi_is_array(env, param_two, &isArray);
        if (!isArray) {
            PRINT_HILOGD("ParsePageSize type error!");
            return false;
        }

        std::vector<PrintPageSize> pageSizeList;
        uint32_t arrayLength = 0;
        napi_get_array_length(env, param_two, &arrayLength);
        for (uint32_t i = 0; i < arrayLength; i++) {
            napi_value pageSizeValue;
            PrintPageSize pageSize;
            napi_get_element(env, param_two, i, &pageSizeValue);
            if (!ParsePageSize(env, pageSizeValue, pageSize)) {
                PRINT_HILOGD("ParsePageSize type error!");
                return false;
            }
            pageSizeList.push_back(pageSize);
        }
        capability.SetPageSize(pageSizeList);
    }
}

bool PrintParseType::ParseArrPrintResolution(napi_env env, napi_value capValue, PrinterCapability &capability)
{
    napi_value param_three = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_RESOLUTION);
    if (NapiPrintUtils::GetValueType(env, param_three) != napi_object) {
        PRINT_HILOGD("error param_three");
        return false;
    } else {
        bool isReArray = false;
        napi_is_array(env, param_three, &isReArray);
        if (!isReArray) {
            PRINT_HILOGD("PrintResolution type error!");
            return false;
        }
        std::vector<PrintResolution> resolutionList;
        uint32_t arrayReLength = 0;
        napi_get_array_length(env, param_three, &arrayReLength);
        for (uint32_t i = 0; i < arrayReLength; i++) {
            napi_value reValue;
            PrintResolution resolution;
            napi_get_element(env, param_three, i, &reValue);
            if (!ParseResolution(env, reValue, resolution)) {
                PRINT_HILOGD("PrintResolution type error!");
                return false;
            }
            resolutionList.push_back(resolution);
        }
        capability.SetResolution(resolutionList);
    }
    return true;
}
bool PrintParseType::ParsePageSizeParam(napi_env env, napi_value capValue, PrintPageSize &pageSize)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_ID);
    if (NapiPrintUtils::GetValueType(env, param_one) != napi_string) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_NAME);
    if (NapiPrintUtils::GetValueType(env, param_two) != napi_string) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_WIDTH);
    if (NapiPrintUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_HEIGHT);
    if (NapiPrintUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    return true;
}

bool PrintParseType::ParseResolutionParam(napi_env env, napi_value reValue, PrintResolution &resolution)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, reValue, PARAM_RESOLUTION_ID);
    if (NapiPrintUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = NapiPrintUtils::GetNamedProperty(env, reValue, PARAM_RESOLUTION_HORIZONTALDPI);
    if (NapiPrintUtils::GetValueType(env, param_two) != napi_number) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = NapiPrintUtils::GetNamedProperty(env, reValue, PARAM_RESOLUTION_VERTICALDPI);
    if (NapiPrintUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    return true;
}

bool PrintParseType::ParseMarginParam(napi_env env, napi_value marginValue, PrintMargin &margin)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, marginValue, PARAM_MARGIN_TOP);
    if (NapiPrintUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = NapiPrintUtils::GetNamedProperty(env, marginValue, PARAM_MARGIN_BOTTOM);
    if (NapiPrintUtils::GetValueType(env, param_two) != napi_number) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = NapiPrintUtils::GetNamedProperty(env, marginValue, PARAM_MARGIN_LEFT);
    if (NapiPrintUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = NapiPrintUtils::GetNamedProperty(env, marginValue, PARAM_MARGIN_RIGHT);
    if (NapiPrintUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    auto names = NapiPrintUtils::GetPropertyNames(env, marginValue);
    PRINT_HILOGD("current margin paramster name list size = %{public}zu", names.size());
    return true;
}
bool PrintParseType::ParseArrFiles(napi_env env, napi_value jobValue, PrintJob &printJob)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_FILES);
    bool isFileArray = false;
    napi_is_array(env, param_one, &isFileArray);
    if (!isFileArray) {
        PRINT_HILOGD("PrinterJobFile type error!");
        return false;
    }
    std::vector<std::string> printfiles;
    uint32_t arrayReLength = 0;
    napi_get_array_length(env, param_one, &arrayReLength);
    for (uint32_t i = 0; i < arrayReLength; i++) {
        napi_value filesValue;
        napi_get_element(env, param_one, i, &filesValue);
        std::string files = NapiPrintUtils::GetStringFromValueUtf8(env, filesValue);
        PRINT_HILOGD("printJob_value param_one %{public}s", files.c_str());
        printfiles.push_back(files);
    }
    printJob.SetFiles(printfiles);
    return true;
}

bool PrintParseType::ParseHasNum(napi_env env, napi_value jobValue, PrintJob &printJob)
{
    if (!NapiPrintUtils::HasNamedProperty(env, jobValue, PARAM_JOB_ISSEQUENTIAL)) {
        PRINT_HILOGD("No isSequential present, ignore it");
    } else {
        napi_value param_seven = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_ISSEQUENTIAL);
        if (NapiPrintUtils::GetValueType(env, param_seven) != napi_boolean) {
            PRINT_HILOGD("error param_seven");
            return false;
        } else {
            printJob.SetIsSequential(NapiPrintUtils::GetUint32Property(env, jobValue, PARAM_JOB_ISSEQUENTIAL));
        }
    }
    if (!NapiPrintUtils::HasNamedProperty(env, jobValue, PARAM_JOB_ISLANDSCAPE)) {
        PRINT_HILOGD("No isLandscape present, ignore it");
    } else {
        napi_value param_nine = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_ISLANDSCAPE);
        if (NapiPrintUtils::GetValueType(env, param_nine) != napi_boolean) {
            PRINT_HILOGD("error param_nine");
            return false;
        } else {
            printJob.SetIsLandscape(NapiPrintUtils::GetBooleanProperty(env, jobValue, PARAM_JOB_ISLANDSCAPE));
        }
    }
    if (!NapiPrintUtils::HasNamedProperty(env, jobValue, PARAM_JOB_COLORMODE)) {
        PRINT_HILOGD("No colorMode present, ignore it");
    } else {
        napi_value param_ten = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_COLORMODE);
        if (NapiPrintUtils::GetValueType(env, param_ten) != napi_number) {
            PRINT_HILOGD("error param_ten");
            return false;
        } else {
            printJob.SetColorMode(NapiPrintUtils::GetUint32Property(env, jobValue, PARAM_JOB_COLORMODE));
        }
    }

    if (!NapiPrintUtils::HasNamedProperty(env, jobValue, PARAM_JOB_DUPLEXMODE)) {
        PRINT_HILOGD("No duplexMode present, ignore it");
    } else {
        napi_value param_eleven = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_DUPLEXMODE);
        if (NapiPrintUtils::GetValueType(env, param_eleven) != napi_number) {
            PRINT_HILOGD("error param_eleven");
            return false;
        } else {
            printJob.SetDuplexMode(NapiPrintUtils::GetUint32Property(env, jobValue, PARAM_JOB_DUPLEXMODE));
        }
    }
    return true;
}

bool PrintParseType::ParseHasObj(napi_env env, napi_value jobValue, PrintJob &printJob)
{
    if (!NapiPrintUtils::HasNamedProperty(env, jobValue, PARAM_JOB_PAGESIZE)) {
        PRINT_HILOGD("No pageSize present, ignore it");
    } else {
        napi_value param_eight = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_PAGESIZE);
        if (NapiPrintUtils::GetValueType(env, param_eight) != napi_object) {
            PRINT_HILOGD("error param_eight");
            return false;
        } else {
            PrintPageSize pagesize;
            if (!ParsePageSize(env, param_eight, pagesize)) {
                PRINT_HILOGD("ParsePageSize type error!");
                return false;
            }
            printJob.SetPageSize(pagesize);
        }
    }

    if (!NapiPrintUtils::HasNamedProperty(env, jobValue, PARAM_JOB_MARGIN)) {
        PRINT_HILOGD("No isSequential present, ignore it");
    } else {
        napi_value param_twelve = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_MARGIN);
        if (NapiPrintUtils::GetValueType(env, param_twelve) != napi_object) {
            PRINT_HILOGD("error param_twelve");
            return false;
        } else {
            PrintMargin margin;
            if (!ParseMargin(env, param_twelve, margin)) {
                PRINT_HILOGD("PrintMargin type error!");
            }
            printJob.SetMargin(margin);
        }
    }

    if (!NapiPrintUtils::HasNamedProperty(env, jobValue, PARAM_JOB_PREVIEW)) {
        PRINT_HILOGD("No PreviewAttribute present, ignore it");
    } else {
        napi_value param_thirteen = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_PREVIEW);
        PreviewAttribute previewAttribute;
        if (!ParsePreviewAttribute(env, param_thirteen, previewAttribute)) {
            PRINT_HILOGD("ParsePreviewAttribute type error!");
            return false;
        }
        printJob.SetPreview(previewAttribute);
    }
    return true;
}

bool PrintParseType::ParseJobParam(napi_env env, napi_value jobValue, PrintJob &printJob)
{
    if (!ParseArrFiles(env, jobValue, printJob)) {
        PRINT_HILOGD("ParseArrFiles error");
        return false;
    }

    napi_value param_two = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_JOBID);
    if (NapiPrintUtils::GetValueType(env, param_two) != napi_number) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    napi_value param_three = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_PRINTERID);
    if (NapiPrintUtils::GetValueType(env, param_three) != napi_number) {
        PRINT_HILOGD("error param_three");
        return false;
    }
    napi_value param_four = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_JOBSTATE);
    if (NapiPrintUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    napi_value param_five = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_COPYNUMBER);
    if (NapiPrintUtils::GetValueType(env, param_five) != napi_number) {
        PRINT_HILOGD("error param_five");
        return false;
    }
    napi_value param_six = NapiPrintUtils::GetNamedProperty(env, jobValue, PARAM_JOB_PAGERANGE);
    if (NapiPrintUtils::GetValueType(env, param_six) != napi_object) {
        PRINT_HILOGD("error param_six");
        return false;
    } else {
        PrintRange range;
        if (!ParseRange(env, param_six, range)) {
            PRINT_HILOGD("ParseRange type error!");
            return false;
        }
        printJob.SetPageRange(range);
    }

    if (!ParseHasObj(env, jobValue, printJob) && !ParseHasNum(env, jobValue, printJob)) {
        PRINT_HILOGD("default-value has error!");
        return false;
    }
    return true;
}

bool PrintParseType::ParsePreviewAttributeParam(napi_env env, napi_value preAttValue, PreviewAttribute &preAtt)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, preAttValue, PARAM_PREATTRIBUTE_RANGE);
    if (NapiPrintUtils::GetValueType(env, param_one) != napi_object) {
        PRINT_HILOGD("error param_one");
        return false;
    } else {
        PrintRange range;
        if (!ParseRange(env, param_one, range)) {
            PRINT_HILOGD("ParseRange type error!");
            return false;
        }
        preAtt.SetPreviewRange(range);
    }

    napi_value param_two = NapiPrintUtils::GetNamedProperty(env, preAttValue, PARAM_PREATTRIBUTE_RESULT);
    if (NapiPrintUtils::GetValueType(env, param_two) != napi_string) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    return true;
}
bool PrintParseType::ParseRangeParam(napi_env env, napi_value rangeValue, PrintRange &range)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, rangeValue, PARAM_RANGE_STARTPAGE);
    if (NapiPrintUtils::GetValueType(env, param_one) != napi_number) {
        PRINT_HILOGD("error param_one");
        return false;
    }
    napi_value param_two = NapiPrintUtils::GetNamedProperty(env, rangeValue, PARAM_RANGE_ENDPAGE);
    if (NapiPrintUtils::GetValueType(env, param_two) != napi_number) {
        PRINT_HILOGD("error param_two");
        return false;
    }
    PRINT_HILOGD("Set startPage, endPage value begin.");
    napi_value startPage, endPage, param_three = NapiPrintUtils::GetNamedProperty(env, rangeValue, PARAM_RANGE_PAGES);
    bool isArray = false;
    napi_is_array(env, param_three, &isArray);
    uint32_t arrayLength = 0, startPageNum, endPageNum;
    napi_get_array_length(env, param_three, &arrayLength);
    if (!isArray || arrayLength != NapiPrintUtils::ARGC_TWO) {
        PRINT_HILOGD("ParseRangeParam pages array error!");
        return false;
    }
    PRINT_HILOGD("Set startPageNum value begin.");
    napi_get_element(env, param_three, 0, &startPage);
    napi_get_element(env, param_three, 1, &endPage);
    napi_get_value_uint32(env, startPage, &startPageNum);
    napi_get_value_uint32(env, endPage, &endPageNum);
    if (startPageNum > endPageNum) {
        PRINT_HILOGD("startPage is less than endPage, Param Pages is illegal!");
        return false;
    }
    PRINT_HILOGD("Set page value begin.");
    std::vector<uint32_t> page = { startPageNum, endPageNum };
    range.SetPages(page);
    PRINT_HILOGD("SetPage value is : %{public}d, %{public}d.", startPageNum, endPageNum);
    return true;
}
} // namespace OHOS::Print
