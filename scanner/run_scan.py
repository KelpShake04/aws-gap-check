"""CodeBuild에서 Prowler 스캔을 한 번 실행하고 결과를 S3에 올린다.

입력은 StartBuild 환경 변수 override로 받는다(SCAN_ID, USER_SUB, ROLE_ARN,
EXTERNAL_ID; RESULTS_BUCKET은 프로젝트 설정). 모든 값을 정규식으로 검증하고,
Prowler는 셸을 거치지 않고 인자 목록으로 실행하므로 값이 명령으로 해석될 수 없다.

Prowler 공식 이미지의 venv Python으로 실행한다(boto3가 들어 있다).
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
PROWLER_BIN = "/home/prowler/.venv/bin/prowler"
# 이미지 사용자가 root가 아니어도 쓸 수 있는 위치
OUTPUT_DIR = "/tmp/prowler-out"
OUTPUT_NAME = "prowler"
SCAN_REGION = "ap-northeast-2"

# \d는 유니코드 숫자도 받으므로 [0-9]를 쓴다. fullmatch로 전체가 맞아야 통과한다.
PATTERNS = {
    "SCAN_ID": r"[0-9]{14}-[0-9a-f]{8}",
    "USER_SUB": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "ROLE_ARN": r"arn:aws:iam::[0-9]{12}:role/AwsGapCheckReadOnlyRole",
    "EXTERNAL_ID": r"agc-[0-9a-f]{32}",
    "RESULTS_BUCKET": r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",
}


class InputError(Exception):
    """환경 변수 형식 오류. 메시지에 입력값을 넣지 않는다."""


class ResultError(Exception):
    """Prowler 결과 파일을 올릴 수 없음."""


def read_inputs(env) -> dict:
    inputs = {}
    for name, pattern in PATTERNS.items():
        value = env.get(name, "")
        if not re.fullmatch(pattern, value):
            raise InputError(f"{name} 형식이 올바르지 않습니다")
        inputs[name] = value
    return inputs


def prowler_command(inputs: dict, output_dir: str) -> list:
    return [
        PROWLER_BIN, "aws",
        "--role", inputs["ROLE_ARN"],
        "--external-id", inputs["EXTERNAL_ID"],
        # 고객 계정 CloudTrail에서 어느 스캔이 접근했는지 보이게 한다
        "--role-session-name", f"aws-gap-check-{inputs['SCAN_ID']}",
        "--checks-file", str(HERE / "core-checks.json"),
        "--region", SCAN_REGION,
        "--output-formats", "json-ocsf",
        "--output-directory", output_dir,
        "--output-filename", OUTPUT_NAME,
        # FAIL 항목이 있어도 종료 코드 3을 내지 않게 한다(빌드 실패로 처리되지 않도록)
        "--ignore-exit-code-3",
        "--no-banner",
        "--no-color",
    ]


def result_key(inputs: dict) -> str:
    return f"raw/{inputs['USER_SUB']}/{inputs['SCAN_ID']}/prowler.ocsf.json"


def check_result(path: pathlib.Path) -> int:
    """결과 파일이 OCSF JSON 배열인지 확인하고 finding 수를 돌려준다."""
    if not path.is_file() or path.stat().st_size == 0:
        raise ResultError("결과 파일이 없거나 비어 있습니다")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        raise ResultError("결과 파일이 JSON이 아닙니다") from None
    if not isinstance(data, list):
        raise ResultError("OCSF 결과는 JSON 배열이어야 합니다")
    return len(data)


def s3_upload(path: pathlib.Path, bucket: str, key: str) -> None:
    import boto3  # Prowler 이미지의 venv에 있다

    # CodeBuild 역할 자격 증명으로 올린다. 고객 계정 자격 증명은 Prowler 프로세스 안에서만 쓰인다.
    boto3.client("s3").upload_file(
        str(path), bucket, key, ExtraArgs={"ContentType": "application/json"}
    )


def main(env=os.environ, run=subprocess.run, upload=s3_upload,
         output_dir: str = OUTPUT_DIR) -> int:
    try:
        inputs = read_inputs(env)
    except InputError as err:
        print(f"입력 오류: {err}", file=sys.stderr)
        return 2

    print(f"스캔 {inputs['SCAN_ID']} 시작", flush=True)
    process = run(prowler_command(inputs, output_dir), check=False)
    if process.returncode != 0:
        print(f"Prowler 실패 (종료 코드 {process.returncode})", file=sys.stderr)
        return process.returncode

    path = pathlib.Path(output_dir) / f"{OUTPUT_NAME}.ocsf.json"
    try:
        count = check_result(path)
    except ResultError as err:
        print(f"결과 오류: {err}", file=sys.stderr)
        return 3
    upload(path, inputs["RESULTS_BUCKET"], result_key(inputs))
    print(f"finding {count}건 업로드 완료", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
