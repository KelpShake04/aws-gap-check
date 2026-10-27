#!/usr/bin/env bash
# 팀원 로그인 계정을 만든다(셀프 가입은 꺼져 있음). Cognito가 임시 비밀번호를 메일로 보내고,
# 처음 로그인할 때 새 비밀번호를 정하게 한다. 비밀번호는 이 스크립트에 나타나지 않는다.
#
#   scripts/create_user.sh <이메일>
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
  echo "사용법: $0 <이메일>" >&2
  exit 2
fi
STACK_NAME="${STACK_NAME:-aws-gap-check}"
export AWS_DEFAULT_REGION="${AWS_REGION:-ap-northeast-2}"

POOL_ID="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)"
aws cognito-idp admin-create-user --user-pool-id "$POOL_ID" --username "$1" \
  --user-attributes Name=email,Value="$1" Name=email_verified,Value=true \
  --desired-delivery-mediums EMAIL --query User.UserStatus --output text
echo "$1 에게 임시 비밀번호 메일을 보냈습니다."
