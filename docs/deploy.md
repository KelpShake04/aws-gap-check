# 배포와 스파이크 실행 가이드

사용자가 서비스 계정 콘솔의 **CloudShell**에서 직접 실행하는 명령을 모았다. Claude 세션은 AWS 자격 증명과 Gemini 키를 받지 않으므로 이 단계들은 대신 실행할 수 없다. 결과는 맨 아래 양식대로 `docs/HANDOFF.md`에 적거나 대화에 붙여 넣는다. **API 키, 액세스 키, 계정 ID는 붙여 넣지 않는다.**

## 0. 준비

1. 서비스 계정 콘솔에 **root가 아닌** 관리자 IAM 사용자 또는 Role로 로그인하고, 리전을 서울(`ap-northeast-2`)로 바꾼 뒤 CloudShell을 연다.
2. 확인:
   ```bash
   aws sts get-caller-identity --query Arn --output text   # ...:root 이면 안 된다
   python3 --version
   ```
3. 코드 가져오기. PR이 머지되기 전에는 PR 브랜치를 쓴다.
   - 레포가 공개면:
     ```bash
     git clone -b claude/jolly-cori-omuqsi https://github.com/KelpShake04/aws-gap-check.git
     cd aws-gap-check
     ```
   - 비공개면: GitHub 웹에서 브랜치를 고르고 **Code → Download ZIP**으로 받은 뒤, CloudShell **Actions → Upload file**로 올려 `unzip`한다. 이 방식은 토큰이 필요 없다.
4. Service Quotas 콘솔에서 CodeBuild의 동시 실행 빌드 한도를 확인한다(T0.3). 1 이상이면 된다.

## 1. Gemini 스파이크 (T0.2)

1. [Google AI Studio](https://aistudio.google.com/)에서 API 키를 만든다.
2. 키가 화면과 셸 히스토리에 남지 않게 SSM SecureString으로 저장한다(무료, KMS는 AWS 관리형 `aws/ssm`).
   ```bash
   read -rs GEMINI_KEY        # 키를 붙여 넣고 Enter (화면에 표시되지 않음)
   aws ssm put-parameter --name /aws-gap-check/gemini-api-key \
     --type SecureString --value "$GEMINI_KEY"
   unset GEMINI_KEY
   ```
   키를 바꿀 때는 `--overwrite`를 붙인다.
3. 실행:
   ```bash
   python3 scripts/spike_gemini.py
   ```
   쓸 수 있는 Flash 모델 목록, 호출한 모델, 응답 시간, 한국어 해설 JSON, 형식 확인 결과가 나온다. 키는 출력되지 않는다.
4. `HTTP 400`이 나오고 메시지에 `responseJsonSchema`가 언급되면 그 메시지를 그대로 알려 준다(스키마 필드 이름을 바꿔야 한다).
5. AI Studio의 사용량 화면에서 이 모델의 RPM/RPD 한도를 확인한다.

## 2. 서비스 스택 배포 (T0.5)

```bash
scripts/deploy.sh
```

- 배포 주체, 리전, 스택 이름을 보여 주고 `y`를 입력해야 진행한다. root면 거부한다.
- 처음 실행하면 아티팩트 버킷(`aws-gap-check-artifacts-<계정>-ap-northeast-2`, 퍼블릭 차단·암호화)을 만든다.
- 만드는 리소스: 결과 버킷(30일 후 자동 삭제), CodeBuild 프로젝트 `aws-gap-check-scanner`(동시 1개, 30분 제한), `aws-gap-check-scanner-role`, 로그 그룹(14일 보존). 상시 비용이 드는 리소스는 없다.
- 끝나면 출력 표에 `ResultsBucketName`이 나온다.

## 3. 자체 테스트용 고객 Role (T0.4)

조원 계정 대신 서비스 계정 자신을 스캔 대상으로 쓴다.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
EXTERNAL_ID=$(python3 -c "import secrets; print('agc-' + secrets.token_hex(16))")
echo "$EXTERNAL_ID"     # 4단계에서 다시 쓴다

aws cloudformation deploy --stack-name aws-gap-check-readonly-role \
  --template-file infra/customer-role.yaml --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ServiceAccountId="$ACCOUNT_ID" ExternalId="$EXTERNAL_ID"
```

`AwsGapCheckReadOnlyRole`이 생긴다(`SecurityAudit` + `ViewOnlyAccess`, 쓰기 권한 없음). 같은 계정에는 이 Role을 하나만 만들 수 있다.

## 4. 테스트 스캔 (T0.5)

```bash
scripts/start_test_scan.sh "$ACCOUNT_ID" "$EXTERNAL_ID"
aws logs tail /aws/codebuild/aws-gap-check-scanner --follow     # Ctrl+C로 종료
```

끝나면(보통 수 분) 단계별 시간과 결과를 확인한다. `PROVISIONING` 시간에 이미지 pull이 들어가고, `BUILD` 시간이 Prowler 스캔 시간이다.

```bash
BUILD_ID=<시작할 때 출력된 빌드 ID>
aws codebuild batch-get-builds --ids "$BUILD_ID" \
  --query 'builds[0].[buildStatus, phases[].[phaseType, durationInSeconds]]' --output json
aws logs filter-log-events --log-group-name /aws/codebuild/aws-gap-check-scanner \
  --filter-pattern AccessDenied --query 'length(events)'
```

결과 파일을 받아 요약한다. `<버킷>`은 2단계 출력의 `ResultsBucketName`, `<결과 키>`는 시작할 때 출력된 값이다.

```bash
mkdir -p out
aws s3 cp "s3://<버킷>/<결과 키>" out/prowler.ocsf.json
python3 - <<'EOF'
import collections, json
findings = json.load(open("out/prowler.ocsf.json"))
print("finding:", len(findings))
print("상태:", dict(collections.Counter(f["status_code"] for f in findings)))
checks = {f["metadata"]["event_code"] for f in findings}
print("실행된 check:", len(checks), "/ IAM check 포함:", any(c.startswith("iam_") for c in checks))
EOF
```

**ExternalId가 틀리면 막히는지**도 한 번 확인한다(발표 자료용). 다른 값으로 시작하면 빌드가 `FAILED`여야 한다.

```bash
scripts/start_test_scan.sh "$ACCOUNT_ID" "agc-$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
```

### 문제가 생기면

- `PROVISIONING`에서 이미지를 못 받으면 Docker Hub 이미지로 다시 배포한다: `PROWLER_IMAGE=prowlercloud/prowler:5.46.0 scripts/deploy.sh`
- `BUILD`에서 권한이나 사용자 문제(이미지 사용자가 root가 아님)로 실패하면 `aws logs tail` 출력의 오류 줄을 알려 준다. 계획의 전환 기준에 따라 표준 이미지나 Fargate로 바꿀지 정한다.
- 실제 결과를 테스트 fixture로 쓰려면 익명화한 뒤 내용을 직접 확인하고 공유한다.
  ```bash
  python3 scripts/sanitize_ocsf.py out/prowler.ocsf.json out/sanitized.json
  ```

## 5. 기록 양식

```
## Phase 0 스파이크 결과 (YYYY-MM-DD)
- Gemini: 모델=, responseJsonSchema 동작=예/아니오, 응답 시간=초, 한국어 품질=, 한도(RPM/RPD)=
- 배포: 주체 종류(IAM 사용자/Role), CodeBuild 동시 실행 한도=
- CodeBuild: 이미지=, PROVISIONING=초, BUILD=초, finding=건(FAIL=건), 실행된 check=개, AccessDenied=건, IAM check 포함=예/아니오
- ExternalId 틀린 스캔: FAILED 확인=예/아니오
```

## 정리

Phase 1에서도 같은 스택을 계속 쓰므로 지금은 지우지 않는다. 지울 때는 결과 버킷을 비운 뒤 `aws cloudformation delete-stack`으로 `aws-gap-check-readonly-role`, `aws-gap-check` 순서로 삭제하고, 아티팩트 버킷은 직접 비우고 삭제한다. 삭제는 사용자가 결정한다.
