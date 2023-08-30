//
// Created by h00660855 on 2023/7/18
//

#include "iprint_adapter.h"

namespace OHOS::Print {

void PrintDocumentAdapter::onStartLayoutWrite(const std::string &jobId, const PrintAttributes &oldAttrs,
        const PrintAttributes &newAttrs, uint32_t fd,
        std::function<void(std::string, uint32_t)> writeResultCallback)
{
}

void PrintDocumentAdapter::onJobStateChanged(const std::string &jobId, uint32_t state)
{
}
}