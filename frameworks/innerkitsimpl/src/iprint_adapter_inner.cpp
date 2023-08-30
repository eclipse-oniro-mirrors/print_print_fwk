//
// Created by h00660855 on 2023/7/18
//

#include "iprint_adapter_inner.h"
#include "print_constant.h"

namespace OHOS::Print {

void PrintDocumentInnerAdapter::onStartLayoutWrite(const std::string &jobId, const PrintAttributes &oldAttrs,
    const PrintAttributes &newAttrs, uint32_t fd,
    std::function<void(std::string, uint32_t)> writeResultCallback)
{
    PRINT_HILOGI("onStartLayoutWrite jobId:%{public}s", jobId.c_str());
    // 应用写layout和write file的逻辑

    //
    writeResultCallback(jobId, PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS);
}

void PrintDocumentInnerAdapter::onJobStateChanged(const std::string &jobId, uint32_t state)
{
    PRINT_HILOGI("onJobStateChanged jobId:%{public}s state:%{public}d", jobId.c_str(), state);
}
}