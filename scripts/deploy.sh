#!/usr/bin/env bash
# 서비스 스택과 웹 화면을 배포한다. CloudShell(서비스 계정, root가 아닌 관리자)에서 레포 루트 기준으로 실행한다.
#
#   scripts/deploy.sh          # 계정·리전을 보여 주고 확인을 받은 뒤 배포
#   scripts/deploy.sh --yes    # 확인 없이 배포
#
# 환경 변수(선택): GEMINI_MODEL(T0.2에서 확인한 모델, 한 번 넣으면 스택이 기억함),
#   PROWLER_IMAGE, STACK_NAME(기본 aws-gap-check), AWS_REGION(기본 ap-northeast-2)
set -euo pipefail

STACK_NAME="${STACK_NAME:-aws-gap-check}"
REGION="${AWS_REGION:-ap-northeast-2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AWS_DEFAULT_REGION="$REGION"

CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
if [[ "$CALLER_ARN" == *":root" ]]; then
  echo "root 사용자로는 배포하지 않습니다. 관리자 IAM 사용자/Role로 로그인하세요." >&2
  exit 1
fi
ARTIFACT_BUCKET="aws-gap-check-artifacts-${ACCOUNT_ID}-${REGION}"
# Hosted UI 도메인 접두사: 계정마다 같고 계정 ID가 드러나지 않는 값
COGNITO_PREFIX="gapcheck-$(printf '%s' "${ACCOUNT_ID}-gapcheck" | sha256sum | cut -c1-10)"

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
find "$ROOT/backend" -name __pycache__ -type d -prune -exec rm -rf {} +

# 1) 스캐너 소스. 같은 내용이면 같은 zip이 나오게 시각을 고정한다(해시가 바뀔 때만 CodeBuild 소스가 바뀜).
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

# 2) Lambda 코드 패키징(backend/)과 스택 배포
aws cloudformation package \
  --template-file "$ROOT/infra/service.yaml" \
  --s3-bucket "$ARTIFACT_BUCKET" --s3-prefix lambda \
  --output-template-file "$WORK_DIR/packaged.yaml" >/dev/null

PARAMS=("ArtifactBucket=$ARTIFACT_BUCKET" "ScannerSourceKey=$SCANNER_KEY" "CognitoDomainPrefix=$COGNITO_PREFIX")
[[ -n "${GEMINI_MODEL:-}" ]] && PARAMS+=("GeminiModel=$GEMINI_MODEL")
[[ -n "${PROWLER_IMAGE:-}" ]] && PARAMS+=("ProwlerImage=$PROWLER_IMAGE")

aws cloudformation deploy \
  --stack-name "$STACK_NAME" \
  --template-file "$WORK_DIR/packaged.yaml" \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
  --parameter-overrides "${PARAMS[@]}" \
  --no-fail-on-empty-changeset

# 3) 웹 화면: 스택 출력으로 config.json을 만들고 올린 뒤 CloudFront 캐시를 비운다
aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs" --output json > "$WORK_DIR/outputs.json"
python3 - "$WORK_DIR/outputs.json" "$WORK_DIR" "$REGION" <<'EOF'
import json
import pathlib
import sys

outputs = {o["OutputKey"]: o["OutputValue"] for o in json.load(open(sys.argv[1]))}
work = pathlib.Path(sys.argv[2])
config = {
    "region": sys.argv[3],
    "apiUrl": outputs["ApiUrl"],
    "cognitoDomain": outputs["CognitoDomain"],
    "clientId": outputs["UserPoolClientId"],
    "redirectUri": outputs["SiteUrl"],
}
(work / "config.json").write_text(json.dumps(config, indent=2))
for key in ("SiteBucketName", "DistributionId", "SiteUrl", "UserPoolId"):
    (work / key).write_text(outputs[key])
EOF
SITE_BUCKET="$(cat "$WORK_DIR/SiteBucketName")"
aws s3 sync "$ROOT/frontend/" "s3://$SITE_BUCKET/" --delete --exclude "config.json" --only-show-errors
aws s3 cp "$WORK_DIR/config.json" "s3://$SITE_BUCKET/config.json" \
  --content-type application/json --cache-control no-store --only-show-errors
aws s3 cp "$ROOT/infra/customer-role.yaml" "s3://$SITE_BUCKET/customer-role.yaml" \
  --content-type text/yaml --only-show-errors
aws cloudfront create-invalidation --distribution-id "$(cat "$WORK_DIR/DistributionId")" \
  --paths "/*" --query Invalidation.Id --output text >/dev/null

echo
echo "배포 완료"
echo "  웹사이트: $(cat "$WORK_DIR/SiteUrl")  (CloudFront 반영에 몇 분 걸릴 수 있음)"
echo "  사용자 추가: scripts/create_user.sh <이메일>"
