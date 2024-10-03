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

#ifndef SCAN_LOG
#define SCAN_LOG

#define CONFIG_SCAN_LOG
#ifdef CONFIG_SCAN_LOG
#include "hilog/log.h"

#ifdef SCAN_HILOGF
#undef SCAN_HILOGF
#endif

#ifdef SCAN_HILOGE
#undef SCAN_HILOGE
#endif

#ifdef SCAN_HILOGW
#undef SCAN_HILOGW
#endif

#ifdef SCAN_HILOGD
#undef SCAN_HILOGD
#endif

#ifdef SCAN_HILOGI
#undef SCAN_HILOGI
#endif

#define SCAN_LOG_TAG "scankit"
#define SCAN_LOG_DOMAIN 0xD001C00

#ifdef IS_RELEASE_VERSION
#define SCAN_MAKE_FILE_NAME ""
#else
#define SCAN_MAKE_FILE_NAME \
    (__builtin_strrchr(__FILE_NAME__, '/') ? __builtin_strrchr(__FILE_NAME__, '/') + 1 : __FILE_NAME__)
#endif

#define SCAN_HILOGF(fmt, ...)                                        								\
    (void)HILOG_IMPL(LOG_CORE, LOG_FATAL, SCAN_LOG_DOMAIN, SCAN_LOG_TAG, "[%{public}s %{public}s %{public}d] " fmt,	\
    SCAN_MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define SCAN_HILOGE(fmt, ...)                                      									\
    (void)HILOG_IMPL(LOG_CORE, LOG_ERROR, SCAN_LOG_DOMAIN, SCAN_LOG_TAG, "[%{public}s %{public}s %{public}d] " fmt,	\
    SCAN_MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define SCAN_HILOGW(fmt, ...)                                                        				\
    (void)HILOG_IMPL(LOG_CORE, LOG_WARN, SCAN_LOG_DOMAIN, SCAN_LOG_TAG, "[%{public}s %{public}s %{public}d] " fmt,	\
    SCAN_MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define SCAN_HILOGD(fmt, ...)                                                            			\
    (void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, SCAN_LOG_DOMAIN, SCAN_LOG_TAG, "[%{public}s %{public}s %{public}d] " fmt,	\
    SCAN_MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define SCAN_HILOGI(fmt, ...)                                                     					\
    (void)HILOG_IMPL(LOG_CORE, LOG_INFO, SCAN_LOG_DOMAIN, SCAN_LOG_TAG, "[%{public}s %{public}s %{public}d] " fmt,	\
    SCAN_MAKE_FILE_NAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#else

#define SCAN_HILOGF(fmt, ...)
#define SCAN_HILOGE(fmt, ...)
#define SCAN_HILOGW(fmt, ...)
#define SCAN_HILOGD(fmt, ...)
#define SCAN_HILOGI(fmt, ...)
#endif // CONFIG_SCAN_LOG

#endif /* SCAN_LOG */
