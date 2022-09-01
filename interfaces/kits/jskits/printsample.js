/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

import printmanager from '@ohos.app.print';
// start print
export async function startPrint() {
	Array<string> fileList = ['./data/printsample.pdf', './data/photo.jpg'];
    await printmanager.print(fileList).then(async (task) => {
		task.on('block', () => {
            console.info('[block] event is called');
        });
		task.on('success', () => {
            console.info('[success] event is called');
        });
		task.on('fail', () => {
            console.info('[fail] event is called');
        });
		task.on('cancel', () => {
            console.info('[cancel] event is called');
        });
    });
}
