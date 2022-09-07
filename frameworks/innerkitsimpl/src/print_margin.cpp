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

#include "print_margin.h"

#include "print_log.h"

namespace OHOS::Print {
PrintMargin::PrintMargin() : top_(0), bottom_(0), left_(0), right_(0) {}

PrintMargin::PrintMargin(const PrintMargin &right) {
  top_ = right.top_;
  bottom_ = right.bottom_;
  left_ = right.left_;
  right_ = right.right_;
}

PrintMargin &PrintMargin::operator=(const PrintMargin &right) {
  if (this != &right) {
    top_ = right.top_;
    bottom_ = right.bottom_;
    left_ = right.left_;
    right_ = right.right_;
  }
  return *this;
}

PrintMargin::~PrintMargin() {}

void PrintMargin::SetTop(uint32_t top) { top_ = top; }

void PrintMargin::SetBottom(uint32_t bottom) { bottom_ = bottom; }

void PrintMargin::SetLeft(uint32_t left) { left_ = left; }

void PrintMargin::SetRight(uint32_t right) { right_ = right; }

uint32_t PrintMargin::GetTop() const { return top_; }

uint32_t PrintMargin::GetBottom() const { return bottom_; }

uint32_t PrintMargin::GetLeft() const { return left_; }

uint32_t PrintMargin::GetRight() const { return right_; }

void PrintMargin::Dump() {
  PRINT_HILOGD("top_ = %{public}d", top_);
  PRINT_HILOGD("bottom_ = %{public}d", bottom_);
  PRINT_HILOGD("left_ = %{public}d", left_);
  PRINT_HILOGD("right_ = %{public}d", right_);
}
} // namespace OHOS::Print
