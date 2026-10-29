#!/usr/bin/env python3
"""T0.2 Gemini 스파이크. CloudShell에서 레포 루트 기준으로 실행한다.

    python3 scripts/spike_gemini.py              # Flash 모델을 골라 한 번 호출
    python3 scripts/spike_gemini.py --model gemini-x-flash

SSM SecureString에서 API 키를 읽어(aws CLI) 쓸 수 있는 Flash 모델 목록을 보여 주고,
check 해설 형식의 구조화 출력을 한 번 받아 본다. API 키는 어디에도 출력하지 않는다.
결과(모델 이름, 응답 시간, 한국어 품질)를 HANDOFF에 적는다.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "backend"))

from gapcheck import llm  # noqa: E402
from gapcheck.explain import EXPLANATION_SCHEMA, SYSTEM_EXPLAIN as SYSTEM_PROMPT  # noqa: E402

PARAM_NAME = "/gapcheck/gemini-api-key"
EXCLUDED_WORDS = ("image", "tts", "audio", "live", "embedding")

# Prowler 5.46.0의 s3_bucket_public_access 메타데이터에서 가져온 예시 입력
SAMPLE_CHECK = {
    "check_id": "s3_bucket_public_access",
    "title": "S3 bucket is not publicly accessible to Everyone or Authenticated Users",
    "severity": "critical",
    "service": "s3",
    "resource_type": "AwsS3Bucket",
    "description": (
        "Amazon S3 buckets are evaluated for public access via ACLs and bucket policies."
    ),
    "risk": (
        "Publicly accessible buckets jeopardize confidentiality through unauthenticated "
        "reads, integrity through write or ACL changes, and availability via object "
        "deletion or overwrite."
    ),
    "recommendation": (
        "Enable S3 Block Public Access at account and bucket levels. Apply least "
        "privilege with explicit principals; avoid ACLs via Object Ownership."
    ),
    "affected_resources": 1,
    "regions": ["ap-northeast-2"],
}


def read_api_key(param_name: str) -> str:
    result = subprocess.run(
        ["aws", "ssm", "get-parameter", "--name", param_name, "--with-decryption",
         "--query", "Parameter.Value", "--output", "text"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.exit(f"SSM 파라미터 {param_name}을 읽지 못했습니다: {result.stderr.strip()[:300]}")
    key = result.stdout.strip()
    if not key:
        sys.exit(f"SSM 파라미터 {param_name}이 비어 있습니다")
    return key


def flash_candidates(models: list) -> list:
    names = []
    for model in models:
        name = model.get("name", "").replace("models/", "", 1)
        if "generateContent" not in model.get("supportedGenerationMethods", []):
            continue
        if "flash" not in name or any(word in name for word in EXCLUDED_WORDS):
            continue
        names.append(name)
    # 이름 역순(대개 최신 버전이 앞), 그다음 정식 버전과 lite가 아닌 모델을 앞으로
    names.sort(reverse=True)
    names.sort(key=lambda n: ("preview" in n or "exp" in n, "lite" in n))
    return names


def check_shape(result: dict) -> list:
    problems = []
    for field in ("summary", "risk", "impact"):
        value = result.get(field)
        limit = EXPLANATION_SCHEMA["properties"][field]["maxLength"]
        if not isinstance(value, str) or not value:
            problems.append(f"{field}: 문자열이 아님")
        elif len(value) > limit:
            problems.append(f"{field}: {len(value)}자 (> {limit})")
    steps = result.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 5:
        problems.append("steps: 1~5개 배열이 아님")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", help="호출할 모델 이름 (생략하면 Flash 후보 중 첫 번째)")
    parser.add_argument("--param", default=PARAM_NAME, help="API 키가 든 SSM 파라미터 이름")
    args = parser.parse_args()

    api_key = read_api_key(args.param)

    try:
        models = llm.list_models(api_key)
    except llm.LLMError as err:
        print(f"모델 목록 조회 실패: {err}")
        return 1
    candidates = flash_candidates(models)
    print(f"generateContent를 지원하는 Flash 모델 {len(candidates)}개:")
    for name in candidates:
        print(f"  - {name}")
    model = args.model or (candidates[0] if candidates else "")
    if not model:
        print("쓸 수 있는 Flash 모델이 없습니다. --model로 직접 지정하세요.")
        return 1
    print(f"\n호출 모델: {model} (스키마 필드: {llm.SCHEMA_FIELD})")

    user_prompt = "다음 점검 항목을 해설하라.\n" + json.dumps(SAMPLE_CHECK, ensure_ascii=False)
    started = time.monotonic()
    try:
        result = llm.generate_json(SYSTEM_PROMPT, user_prompt, EXPLANATION_SCHEMA,
                                   model=model, api_key=api_key, timeout=60)
    except llm.RateLimited as err:
        print(f"한도 초과(429). 서버가 알려 준 대기 시간: {err.retry_after}초")
        return 1
    except llm.LLMError as err:
        print(f"호출 실패 ({type(err).__name__}): {err}")
        return 1
    elapsed = time.monotonic() - started

    print(f"응답 시간: {elapsed:.1f}초\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    problems = check_shape(result)
    print("\n형식 확인: " + ("통과" if not problems else "; ".join(problems)))
    print(f"\nHANDOFF에 적을 값: GEMINI_MODEL={model}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
