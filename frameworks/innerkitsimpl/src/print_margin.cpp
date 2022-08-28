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
#include "log.h"

namespace OHOS::Print {
    PrintMargin::PrintMargin () 
        : top_(0), bottom_(0), left_(0), right_(0) {
        
    }

    void PrintMargin::SetTop(uint32_t top)
    {
        top_ = top;
    }

    void PrintMargin::SetBottom(uint32_t bottom)
    {
        bottom_ = bottom;
    }

    void PrintMargin::SetLeft(uint32_t left)
    {
        left_ = left;
    }

    void PrintMargin::SetRight(uint32_t right)
    {
        right_ = right;
    }

    uint32_t PrintMargin::GetTop() const
    {
        return top_;
    }

    uint32_t PrintMargin::GetBottom() const
    {
        return bottom_;
    }

    uint32_t PrintMargin::GetLeft() const
    {
        return left_;
    }

    uint32_t PrintMargin::GetRight() const
    {
        return right_;
    }

    PrintMargin &PrintMargin::operator=(const PrintMargin &printMargin)
    {
        if(this != &printMargin){
            this->top_ = printMargin.top_;
            this->bottom_ = printMargin.bottom_;
            this->left_ = printMargin.left_;
            this->right_ = printMargin.right_;  
        }
        return *this;
    }

   void PrintMargin::Dump()
    {
        PRINT_HILOGD("top_ = %{public}d", top_);
        PRINT_HILOGD("bottom_ = %{public}d", bottom_);
        PRINT_HILOGD("left_ = %{public}d", left_);
        PRINT_HILOGD("right_ = %{public}d", right_);
    }

PrintMargin ::~PrintMargin ()
{

}

} // namespace OHOS::Print
