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

#ifndef PRINT_LOG
#define PRINT_LOG

#define CONFIG_PRINT_LOG
#ifdef CONFIG_PRINT_LOG
#include "hilog/log.h"

#ifdef PRINT_HILOGF
#undef PRINT_HILOGF
#endif

#ifdef PRINT_HILOGE
#undef PRINT_HILOGE
#endif

#ifdef PRINT_HILOGW
#undef PRINT_HILOGW
#endif

#ifdef PRINT_HILOGD
#undef PRINT_HILOGD
#endif

#ifdef PRINT_HILOGI
#undef PRINT_HILOGI
#endif

#define PRINT_LOG_TAG "printkit"
#define PRINT_LOG_DOMAIN 0xD001C00
static constexpr OHOS::HiviewDFX::HiLogLabel PRINT_LOG_LABEL = {LOG_CORE, PRINT_LOG_DOMAIN, PRINT_LOG_TAG};

#define MAKE_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define PRINT_HILOGF(fmt, ...)                                        								\
    (void)OHOS::HiviewDFX::HiLog::Fatal(PRINT_LOG_LABEL, "[%{public}s %{public}s %{public}d] " fmt,	\
    MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define PRINT_HILOGE(fmt, ...)                                      									\
    (void)OHOS::HiviewDFX::HiLog::Error(PRINT_LOG_LABEL, "[%{public}s %{public}s %{public}d] " fmt,	\
    MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define PRINT_HILOGW(fmt, ...)                                                        				\
    (void)OHOS::HiviewDFX::HiLog::Warn(PRINT_LOG_LABEL, "[%{public}s %{public}s %{public}d] " fmt,	\
    MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define PRINT_HILOGD(fmt, ...)                                                            			\
    (void)OHOS::HiviewDFX::HiLog::Debug(PRINT_LOG_LABEL, "[%{public}s %{public}s %{public}d] " fmt,	\
    MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define PRINT_HILOGI(fmt, ...)                                                     					\
    (void)OHOS::HiviewDFX::HiLog::Info(PRINT_LOG_LABEL, "[%{public}s %{public}s %{public}d] " fmt,	\
    MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#else

#define PRINT_HILOGF(fmt, ...)
#define PRINT_HILOGE(fmt, ...)
#define PRINT_HILOGW(fmt, ...)
#define PRINT_HILOGD(fmt, ...)
#define PRINT_HILOGI(fmt, ...)
#endif // CONFIG_PRINT_LOG

#endif /* PRINT_LOG */