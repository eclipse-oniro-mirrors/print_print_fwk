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

#include "printer_capability.h"

#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
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

PrinterCapability::PrinterCapability() : minMargin_(), colorMode_(0), duplexMode_(0)
{
    pageSizeList_.clear();
    resolutionList_.clear();
}

PrinterCapability::PrinterCapability(const PrinterCapability &right)
{
    minMargin_ = right.minMargin_;
    colorMode_ = right.colorMode_;
    duplexMode_ = right.duplexMode_;
    SetPageSize(right.pageSizeList_);
    SetResolution(right.resolutionList_);
}

PrinterCapability &PrinterCapability::operator=(const PrinterCapability &right)
{
    if (this != &right) {
        minMargin_ = right.minMargin_;
        colorMode_ = right.colorMode_;
        duplexMode_ = right.duplexMode_;
        SetPageSize(right.pageSizeList_);
        SetResolution(right.resolutionList_);
    }
    return *this;
}

PrinterCapability::~PrinterCapability() {}

void PrinterCapability::SetMinMargin(const PrintMargin &minMargin)
{
    minMargin_ = minMargin;
}

void PrinterCapability::SetPageSize(const std::vector<PrintPageSize> &pageSizeList)
{
    pageSizeList_.clear();
    pageSizeList_.assign(pageSizeList.begin(), pageSizeList.end());
}

void PrinterCapability::SetResolution(const std::vector<PrintResolution> &resolutionList)
{
    resolutionList_.clear();
    resolutionList_.assign(resolutionList.begin(), resolutionList.end());
}

void PrinterCapability::SetColorMode(uint32_t colorMode)
{
    colorMode_ = colorMode;
}

void PrinterCapability::SetDuplexMode(uint32_t duplexMode)
{
    duplexMode_ = duplexMode;
}

void PrinterCapability::GetMinMargin(PrintMargin &margin) const
{
    margin = minMargin_;
}

void PrinterCapability::GetPageSize(std::vector<PrintPageSize> &pageSizeList) const
{
    pageSizeList.clear();
    pageSizeList.assign(pageSizeList_.begin(), pageSizeList_.end());
}

void PrinterCapability::GetResolution(std::vector<PrintResolution> &resolutionList) const
{
    resolutionList.clear();
    resolutionList.assign(resolutionList_.begin(), resolutionList_.end());
}

uint32_t PrinterCapability::GetColorMode() const
{
    return colorMode_;
}

uint32_t PrinterCapability::GetDuplexMode() const
{
    return duplexMode_;
}

void PrinterCapability::ConvertToParcel(MessageParcel &reply) const
{
    std::vector<PrintPageSize> pageSizeList;
    std::vector<PrintResolution> resolutionList;

    GetPageSize(pageSizeList);
    GetResolution(resolutionList);
    uint32_t arraypageSizeLength = pageSizeList.size();
    reply.WriteUint32(arraypageSizeLength);
    uint32_t resolutionLength = resolutionList.size();
    reply.WriteUint32(resolutionLength);

    PrintMargin minMargin;
    GetMinMargin(minMargin);
    reply.WriteUint32(minMargin.GetTop());
    reply.WriteUint32(minMargin.GetBottom());
    reply.WriteUint32(minMargin.GetLeft());
    reply.WriteUint32(minMargin.GetRight());

    for (uint32_t i = 0; i < arraypageSizeLength; i++) {
        reply.WriteString(pageSizeList[i].GetId());
        reply.WriteString(pageSizeList[i].GetName());
        reply.WriteUint32(pageSizeList[i].GetWidth());
        reply.WriteUint32(pageSizeList[i].GetHeight());
    }

    for (uint32_t i = 0; i < resolutionLength; i++) {
        reply.WriteUint32(resolutionList[i].GetId());
        reply.WriteUint32(resolutionList[i].GetHorizontalDpi());
        reply.WriteUint32(resolutionList[i].GetVerticalDpi());
    }

    reply.WriteUint32(GetColorMode());
    reply.WriteUint32(GetDuplexMode());
}

void PrinterCapability::BuildFromParcel(MessageParcel &data)
{
    uint32_t arraypageSizeLength = data.ReadUint32();
    uint32_t resolutionLength = data.ReadUint32();
    PRINT_HILOGD("PrintServiceProxy, arraypageSizeLength = %{public}d", arraypageSizeLength);
    PRINT_HILOGD("PrintServiceProxy, resolutionLength = %{public}d", resolutionLength);

    PrintMargin margin;
    margin.SetTop(data.ReadUint32());
    margin.SetBottom(data.ReadUint32());
    margin.SetLeft(data.ReadUint32());
    margin.SetRight(data.ReadUint32());
    SetMinMargin(margin);

    if (arraypageSizeLength > 0) {
        std::vector<PrintPageSize> pageSizeList;
        for (uint32_t i = 0; i < arraypageSizeLength; i++) {
            PrintPageSize pageSize;
            pageSize.SetId(data.ReadString());
            pageSize.SetName(data.ReadString());
            pageSize.SetWidth(data.ReadUint32());
            pageSize.SetHeight(data.ReadUint32());
            pageSizeList.push_back(pageSize);
        }
        SetPageSize(pageSizeList);
    }

    if (resolutionLength > 0) {
        std::vector<PrintResolution> resolutionList;
        for (uint32_t i = 0; i < resolutionLength; i++) {
            PrintResolution res;
            res.SetId(data.ReadUint32());
            res.SetHorizontalDpi(data.ReadUint32());
            res.SetVerticalDpi(data.ReadUint32());
            resolutionList.push_back(res);
        }
        SetResolution(resolutionList);
    }

    SetColorMode(data.ReadUint32());
    SetDuplexMode(data.ReadUint32());
    Dump();
}

void PrinterCapability::ConvertToJs(napi_env env, napi_value *result) const
{
    PRINT_HILOGD("Enter ConvertToJs---->");
    napi_value resultPrintMargin;
    napi_create_object(env, result);
    napi_create_object(env, &resultPrintMargin);
    napi_value arrPageSize, arrResolution;
    napi_status status = napi_create_array(env, &arrPageSize);
    status = napi_create_array(env, &arrResolution);

    NapiPrintUtils::SetUint32Property(env, *result, "colorMode", GetColorMode());
    NapiPrintUtils::SetUint32Property(env, *result, "duplexMode", GetDuplexMode());

    PrintMargin margin;
    GetMinMargin(margin);
    NapiPrintUtils::SetUint32Property(env, resultPrintMargin, "top", margin.GetTop());
    NapiPrintUtils::SetUint32Property(env, resultPrintMargin, "bottom", margin.GetBottom());
    NapiPrintUtils::SetUint32Property(env, resultPrintMargin, "left", margin.GetLeft());
    NapiPrintUtils::SetUint32Property(env, resultPrintMargin, "right", margin.GetRight());

    std::vector<PrintPageSize> pageSize;
    GetPageSize(pageSize);
    uint32_t printerCapabilityLength = pageSize.size();

    for (uint32_t i = 0; i < printerCapabilityLength; i++) {
        napi_value resultPrinterPageSize;
        napi_create_object(env, &resultPrinterPageSize);
        NapiPrintUtils::SetStringPropertyUtf8(env, resultPrinterPageSize, "id", pageSize[i].GetId().c_str());
        NapiPrintUtils::SetStringPropertyUtf8(env, resultPrinterPageSize, "name", pageSize[i].GetName().c_str());
        NapiPrintUtils::SetUint32Property(env, resultPrinterPageSize, "width", pageSize[i].GetWidth());
        NapiPrintUtils::SetUint32Property(env, resultPrinterPageSize, "height", pageSize[i].GetHeight());
        status = napi_set_element(env, arrPageSize, i, resultPrinterPageSize);
    }

    std::vector<PrintResolution> resolutionList;
    GetResolution(resolutionList);
    uint32_t printerCapabilityresolutionLength = resolutionList.size();
    for (uint32_t i = 0; i < printerCapabilityresolutionLength; i++) {
        napi_value resultPrinterResolution;
        napi_create_object(env, &resultPrinterResolution);
        NapiPrintUtils::SetUint32Property(env, resultPrinterResolution, "id", resolutionList[i].GetId());
        NapiPrintUtils::SetUint32Property(
            env, resultPrinterResolution, "horizontalDpi", resolutionList[i].GetHorizontalDpi());
        NapiPrintUtils::SetUint32Property(
            env, resultPrinterResolution, "verticalDpi", resolutionList[i].GetVerticalDpi());
        status = napi_set_element(env, arrResolution, i, resultPrinterResolution);
    }

    status = napi_set_named_property(env, *result, "minMargin", resultPrintMargin);
    PRINT_HILOGD("output ---- status[%{public}d]", status);
    napi_set_named_property(env, *result, "pageSize", arrPageSize);
    napi_set_named_property(env, *result, "resolution", arrResolution);
    PRINT_HILOGD("ouput over---->");
}

void PrinterCapability::BuildFromJs(napi_env env, napi_value capValue)
{
    ParseCapability(env, capValue);
}

bool PrinterCapability::ParseCapability(napi_env env, napi_value capValue)
{
    if (!ParseCapabilityParam(env, capValue)) {
        PRINT_HILOGD("ParseCapParam is error!");
        return false;
    }
    SetColorMode(NapiPrintUtils::GetUint32Property(env, capValue, PARAM_CAPABILITY_COLORMODE));
    SetDuplexMode(NapiPrintUtils::GetUint32Property(env, capValue, PARAM_CAPABILITY_DUPLEXMODE));
    PRINT_HILOGD("capability_value colorMode value is  %{public}d", GetColorMode());
    PRINT_HILOGD("capability_value duplexMode value is  %{public}d", GetDuplexMode());
    return true;
}

void PrinterCapability::ParseCapabilityObject(napi_env env, napi_value capValue)
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
        SetResolution(resolutionList);
    }
    napi_value param_four = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_COLORMODE);
    if (NapiPrintUtils::GetValueType(env, param_four) != napi_number) {
        PRINT_HILOGD("error param_four");
        return false;
    }
    napi_value param_five = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_CAPABILITY_DUPLEXMODE);
    if (NapiPrintUtils::GetValueType(env, param_five) != napi_number) {
        PRINT_HILOGD("error param_five");
        return false;
    }
}

bool PrinterCapability::ParseCapabilityParam(napi_env env, napi_value capValue)
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
        SetMinMargin(margin);
    }

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
        SetPageSize(pageSizeList);
    }
    
    ParseCapabilityObject(env, capValue);
    auto names = NapiPrintUtils::GetPropertyNames(env, capValue);
    return true;
}

bool PrinterCapability::ParseMargin(napi_env env, napi_value marginValue, PrintMargin &margin)
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

bool PrinterCapability::ParseMarginParam(napi_env env, napi_value marginValue, PrintMargin &margin)
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

bool PrinterCapability::ParsePageSize(napi_env env, napi_value capValue, PrintPageSize &pageSize)
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

bool PrinterCapability::ParsePageSizeParam(napi_env env, napi_value capValue, PrintPageSize &pageSize)
{
    napi_value param_one = NapiPrintUtils::GetNamedProperty(env, capValue, PARAM_PAGESIZE_ID);
    if (NapiPrintUtils::GetValueType(env, param_one) != napi_number) {
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

bool PrinterCapability::ParseResolution(napi_env env, napi_value reValue, PrintResolution &resolution)
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

bool PrinterCapability::ParseResolutionParam(napi_env env, napi_value reValue, PrintResolution &resolution)
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

void PrinterCapability::Dump()
{
    PRINT_HILOGD("colorMode_ = %{public}d", colorMode_);
    PRINT_HILOGD("duplexMode_ = %{public}d", duplexMode_);
    minMargin_.Dump();
    auto pageIt = pageSizeList_.begin();
    while (pageIt != pageSizeList_.end()) {
        pageIt->Dump();
        pageIt++;
    }

    auto resIt = resolutionList_.begin();
    while (resIt != resolutionList_.end()) {
        resIt->Dump();
        resIt++;
    }
}
} // namespace OHOS::Print
