#!/usr/bin/env bash
# 서비스 스택을 배포한다. CloudShell(서비스 계정, root가 아닌 관리자)에서 레포 루트 기준으로 실행한다.
#
#   scripts/deploy.sh          # 계정·리전을 보여 주고 확인을 받은 뒤 배포
#   scripts/deploy.sh --yes    # 확인 없이 배포
#
# 환경 변수: STACK_NAME(기본 aws-gap-check), AWS_REGION(기본 ap-northeast-2),
#            PROWLER_IMAGE(지정하면 템플릿 기본 이미지 대신 사용)
set -euo pipefail

STACK_NAME="${STACK_NAME:-aws-gap-check}"
REGION="${AWS_REGION:-ap-northeast-2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
if [[ "$CALLER_ARN" == *":root" ]]; then
  echo "root 사용자로는 배포하지 않습니다. 관리자 IAM 사용자/Role로 로그인하세요." >&2
  exit 1
fi
ARTIFACT_BUCKET="aws-gap-check-artifacts-${ACCOUNT_ID}-${REGION}"

echo "배포 주체: $CALLER_ARN"
echo "리전: $REGION / 스택: $STACK_NAME / 아티팩트 버킷: $ARTIFACT_BUCKET"
if [[ "${1:-}" != "--yes" ]]; then
  read -r -p "이 계정에 배포할까요? [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "취소했습니다."; exit 1; }
fi

if ! aws s3api head-bucket --bucket "$ARTIFACT_BUCKET" 2>/dev/null; then
  echo "아티팩트 버킷 생성"
  aws s3api create-bucket --bucket "$ARTIFACT_BUCKET" --region "$REGION" \
    --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  aws s3api put-public-access-block --bucket "$ARTIFACT_BUCKET" \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws s3api put-bucket-encryption --bucket "$ARTIFACT_BUCKET" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# 같은 내용이면 같은 zip이 나오게 시각을 고정한다. 해시가 바뀔 때만 CodeBuild 소스가 바뀐다.
python3 - "$ROOT/scanner" "$WORK_DIR/scanner.zip" <<'EOF'
import pathlib
import sys
import zipfile

src, dst = pathlib.Path(sys.argv[1]), sys.argv[2]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(src.iterdir()):
        if path.is_file() and path.suffix in {".py", ".yml", ".json"}:
            info = zipfile.ZipInfo(path.name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes(), zipfile.ZIP_DEFLATED)
EOF
SCANNER_KEY="scanner/scanner-$(sha256sum "$WORK_DIR/scanner.zip" | cut -c1-16).zip"
aws s3 cp "$WORK_DIR/scanner.zip" "s3://$ARTIFACT_BUCKET/$SCANNER_KEY" --only-show-errors

PARAMS=("ArtifactBucket=$ARTIFACT_BUCKET" "ScannerSourceKey=$SCANNER_KEY")
if [[ -n "${PROWLER_IMAGE:-}" ]]; then
  PARAMS+=("ProwlerImage=$PROWLER_IMAGE")
fi

aws cloudformation deploy \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "$ROOT/infra/service.yaml" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "${PARAMS[@]}" \
  --no-fail-on-empty-changeset

aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs" --output table
