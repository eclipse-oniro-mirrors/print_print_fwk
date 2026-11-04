#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Compile the actual AI notifier path against host-side OS boundary stubs.

Usage: python test/host/run_ai_notifier_user_switch_test.py --cxx g++
Use --source-ref <commit> to run the same scenarios against an earlier revision.
This checks notification requests and fault reports, not device IPC or UI delivery.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def extract_function(source, signature):
    start = source.index(signature)
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--source-ref")
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()
    compiler = shutil.which(args.cxx)
    if not compiler:
        parser.error(f"C++ compiler not found: {args.cxx}")
    env = dict(os.environ)
    env["PATH"] = str(Path(compiler).parent) + os.pathsep + env.get("PATH", "")

    def read(path):
        if args.source_ref:
            return subprocess.check_output(
                ["git", "show", f"{args.source_ref}:{path}"], cwd=repo
            ).decode("utf-8")
        return (repo / path).read_text(encoding="utf-8")

    def run(build_dir):
        failed = False
        for variant in ("print_service", "print_service_phone"):
            work = build_dir / variant
            work.mkdir(parents=True, exist_ok=True)
            service = f"services/{variant}"
            for name in ("print_failure_ai_notifier.h", "print_notification_builder.h"):
                (work / name).write_text(read(f"{service}/include/{name}"), encoding="utf-8")
            (work / "notifier.cpp").write_text(
                read(f"{service}/src/print_failure_ai_notifier.cpp"), encoding="utf-8")
            (work / "print_constant.h").write_text(read("utils/include/print_constant.h"), encoding="utf-8")
            (work / "print_log.h").write_text(
                "#define PRINT_HILOGI(...)\n#define PRINT_HILOGE(...)\n#define PRINT_HILOGD(...)\n"
                "#define PRINT_HILOGW(...)\n", encoding="utf-8")
            for name in ("udmf.h", "uds.h", "udmf_capi_common.h", "notification_request.h", "hisys_event_util.h"):
                (work / name).write_text('#include "ai_notifier_host_stubs.h"\n', encoding="utf-8")
            for name in ("ai_notifier_host_stubs.h", "ai_notifier_user_switch_test.cpp"):
                shutil.copyfile(Path(__file__).parent / name, work / name)

            builder = read(f"{service}/src/print_notification_builder.cpp")
            constants = builder[builder.index("namespace {"):builder.index("namespace OHOS::Print {")]
            signatures = [
                "Notification::NotificationRequest PrintNotificationBuilder::BuildRequest(",
                "std::shared_ptr<Notification::NotificationActionButton> PrintNotificationBuilder::CreateAiButton(",
                "std::string PrintNotificationBuilder::GetFaultKey(",
                "std::string PrintNotificationBuilder::SubStateToResourceKey(",
                "bool PrintNotificationBuilder::IsForegroundUser(",
                "int32_t PrintNotificationBuilder::CreateNotification(",
            ]
            functions = [extract_function(builder, s) for s in signatures if s in builder]
            functions.append(extract_function(read(f"{service}/src/print_service_ability.cpp"),
                                              "void PrintServiceAbility::HandleJobBlockedState("))
            (work / "production.inc").write_text(
                constants + "\nnamespace OHOS::Print {\n" + "\n".join(functions) + "\n}\n",
                encoding="utf-8")
            exe = "regression.exe" if os.name == "nt" else "regression"
            subprocess.run(
                [compiler, "-std=c++20", "-DHAVE_PRINT_FAILURE_AI_NOTIFIER", "-I.", "-include", "cstdint",
                 "ai_notifier_user_switch_test.cpp", "notifier.cpp", "-o", exe],
                cwd=work, env=env, check=True)
            print(f"\n{variant}", flush=True)
            failed |= subprocess.run([str(work / exe)], cwd=work, env=env).returncode != 0
        return int(failed)

    if args.build_dir:
        return run(args.build_dir.resolve())
    with tempfile.TemporaryDirectory(prefix="print-ai-notifier-") as directory:
        return run(Path(directory))


if __name__ == "__main__":
    raise SystemExit(main())
