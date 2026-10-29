#!/usr/bin/env bash
# 로컬 PC에서 실제 계정을 스캔할 때: 관리자 프로필로 aws-gap-check-app-role을 맡아
# 1시간짜리 임시 자격 증명을 .env.aws(레포에 올라가지 않음)에 쓴다. compose의 app이 이 파일을 읽는다.
# 사용: scripts/local_aws_creds.sh <관리자 프로필>   그다음 docker compose up -d app
# 1시간이 지나면 다시 실행하고 app을 다시 띄운다.
set -euo pipefail
cd "$(dirname "$0")/.."
profile="${1:?관리자 프로필 이름이 필요합니다}"

account="$(aws sts get-caller-identity --profile "$profile" --query Account --output text)"
umask 077
aws sts assume-role --profile "$profile" --duration-seconds 3600 \
  --role-arn "arn:aws:iam::${account}:role/aws-gap-check-app-role" \
  --role-session-name aws-gap-check-local \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text |
  awk '{ printf "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_SESSION_TOKEN=%s\n", $1, $2, $3 }' > .env.aws
echo ".env.aws에 임시 자격 증명을 썼습니다(1시간 유효). docker compose up -d app 으로 반영하세요."
