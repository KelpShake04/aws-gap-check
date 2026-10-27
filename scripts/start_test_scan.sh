#!/usr/bin/env bash
# T0.5 스파이크용: 계정 연결 API가 생기기 전에 스캔 빌드를 직접 시작한다.
# Phase 2부터는 웹 화면(API)이 같은 일을 한다.
#
#   scripts/start_test_scan.sh <대상 계정 ID> <ExternalId>
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "사용법: $0 <대상 계정 ID> <ExternalId>" >&2
  exit 2
fi
ACCOUNT_ID="$1"
EXTERNAL_ID="$2"
REGION="${AWS_REGION:-ap-northeast-2}"
[[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || { echo "계정 ID는 12자리 숫자입니다." >&2; exit 2; }
[[ "$EXTERNAL_ID" =~ ^agc-[0-9a-f]{32}$ ]] || { echo "ExternalId는 agc- 뒤에 hex 32자리입니다." >&2; exit 2; }

SCAN_ID="$(date -u +%Y%m%d%H%M%S)-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
# Cognito 도입 전이라 고정된 스파이크용 사용자 ID를 쓴다.
USER_SUB="00000000-0000-4000-8000-000000000000"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/AwsGapCheckReadOnlyRole"

# 값은 위에서 형식을 확인했으므로 따옴표나 역슬래시가 들어 있지 않다.
OVERRIDES="[
  {\"name\":\"SCAN_ID\",\"value\":\"$SCAN_ID\",\"type\":\"PLAINTEXT\"},
  {\"name\":\"USER_SUB\",\"value\":\"$USER_SUB\",\"type\":\"PLAINTEXT\"},
  {\"name\":\"ROLE_ARN\",\"value\":\"$ROLE_ARN\",\"type\":\"PLAINTEXT\"},
  {\"name\":\"EXTERNAL_ID\",\"value\":\"$EXTERNAL_ID\",\"type\":\"PLAINTEXT\"}
]"

BUILD_ID="$(aws codebuild start-build --region "$REGION" \
  --project-name aws-gap-check-scanner \
  --environment-variables-override "$OVERRIDES" \
  --query build.id --output text)"

echo "빌드 시작: $BUILD_ID"
echo "결과 키: raw/$USER_SUB/$SCAN_ID/prowler.ocsf.json"
echo "진행 확인: aws codebuild batch-get-builds --ids $BUILD_ID --query 'builds[0].[buildStatus,currentPhase]' --output text"
