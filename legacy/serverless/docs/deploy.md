# 배포와 실행 가이드

사용자가 서비스 계정 콘솔의 **CloudShell**에서 직접 실행하는 명령을 모았다. Claude 세션은 AWS 자격 증명과 Gemini 키를 받지 않으므로 이 단계들은 대신 실행할 수 없다. 결과는 맨 아래 양식대로 `docs/HANDOFF.md`에 적거나 대화에 붙여 넣는다. **API 키, 비밀번호, 계정 ID는 붙여 넣지 않는다.**

## 0. 준비

1. 서비스 계정 콘솔에 **root가 아닌** 관리자 IAM 사용자 또는 Role로 로그인하고, 리전을 서울(`ap-northeast-2`)로 바꾼 뒤 CloudShell을 연다.
2. 확인:
   ```bash
   aws sts get-caller-identity --query Arn --output text   # ...:root 이면 안 된다
   python3 --version
   ```
3. 코드 가져오기. PR이 머지되기 전에는 PR 브랜치를 쓴다. 레포가 비공개라 GitHub 웹에서 브랜치를 고르고 **Code → Download ZIP**으로 받은 뒤, CloudShell **Actions → Upload file**로 올려 `unzip`한다(토큰이 필요 없다).
4. Service Quotas 콘솔에서 CodeBuild의 동시 실행 빌드 한도를 확인한다. 1 이상이면 된다.

## 1. Gemini 키 저장과 스파이크

1. [Google AI Studio](https://aistudio.google.com/)에서 API 키를 만든다.
2. 키가 화면과 셸 히스토리에 남지 않게 SSM SecureString으로 저장한다(무료, KMS는 AWS 관리형 `aws/ssm`).
   ```bash
   read -rs GEMINI_KEY        # 키를 붙여 넣고 Enter (화면에 표시되지 않음)
   aws ssm put-parameter --name /aws-gap-check/gemini-api-key \
     --type SecureString --value "$GEMINI_KEY"
   unset GEMINI_KEY
   ```
   키를 바꿀 때는 `--overwrite`를 붙인다.
3. `python3 scripts/spike_gemini.py` → 쓸 수 있는 Flash 모델, 응답 시간, 한국어 해설 JSON이 나온다. 마지막 줄의 `GEMINI_MODEL=...` 값을 2단계에서 쓴다.
4. `HTTP 400`이 나오고 메시지에 `responseJsonSchema`가 언급되면 메시지를 그대로 알려 준다.

## 2. 배포

```bash
GEMINI_MODEL=<1단계에서 나온 모델> scripts/deploy.sh
```

- 배포 주체, 리전, 스택 이름을 보여 주고 `y`를 입력해야 진행한다. root면 거부한다.
- 만드는 것: 웹(S3 + CloudFront), Cognito, HTTP API + Lambda 2개, DynamoDB, 결과 버킷, CodeBuild 스캐너, EventBridge 규칙, 로그 그룹(14일). 상시 비용이 드는 리소스는 없다(NAT, EC2 없음).
- 처음 배포는 CloudFront 때문에 10분 안팎 걸린다. 끝나면 웹사이트 주소가 나온다.
- `GEMINI_MODEL`은 한 번 넣으면 스택이 기억한다. 비워 두면 AI 해설 없이 Prowler 원문만 보여 준다.

## 3. 로그인 사용자 만들기

셀프 가입은 꺼져 있다. 팀원마다:

```bash
scripts/create_user.sh <이메일>
```

임시 비밀번호가 메일로 간다. 웹사이트에서 로그인하면 새 비밀번호를 정하게 한다. confused deputy 시연을 하려면 사용자를 2명 만든다.

## 4. 계정 연결

웹사이트 **계정 연결 → 새 연결 만들기**를 누르면 템플릿 다운로드 링크와 `ServiceAccountId`, `ExternalId`가 나온다.

- **조원 계정:** 조원이 자기 계정 콘솔에서 템플릿을 업로드해 스택을 만든다(스택 이름 `aws-gap-check-readonly-role`, IAM 확인란 체크). 끝나면 웹에서 그 계정 ID로 **검증**한다.
- **조원 계정이 없으면(대체 경로):** 서비스 계정 자신에 같은 템플릿을 배포하고 서비스 계정 ID로 검증한다. 이 경우 같은 계정이라는 점을 발표에서 밝힌다.
- 같은 계정에는 이 Role을 하나만 만들 수 있다. 다른 연결의 ExternalId로 바꾸려면 스택 파라미터를 업데이트한다.

## 5. 스캔과 리포트

**스캔 → 스캔 시작**. 상태가 대기 중 → 스캔 중 → 결과 처리 중 → AI 해설 중 → 완료로 바뀐다. 리포트 화면에서 AI 우선순위, 항목별 해설, 영향받는 리소스를 본다.

진행 상황과 문제는 로그로 확인한다.

```bash
aws logs tail /aws/codebuild/aws-gap-check-scanner --since 30m
aws logs tail /aws-gap-check/scan-finished --since 30m
aws logs tail /aws-gap-check/api --since 30m
```

## 6. 측정(첫 스캔 후 기록)

```bash
BUILD_ID=$(aws codebuild list-builds-for-project --project-name aws-gap-check-scanner --query 'ids[0]' --output text)
aws codebuild batch-get-builds --ids "$BUILD_ID" \
  --query 'builds[0].[buildStatus, phases[].[phaseType, durationInSeconds]]' --output json
aws logs filter-log-events --log-group-name /aws/codebuild/aws-gap-check-scanner \
  --filter-pattern AccessDenied --query 'length(events)'
```

`PROVISIONING`은 이미지 내려받기, `BUILD`는 Prowler 스캔 시간이다. 웹을 거치지 않고 빌드만 돌려 보려면 `scripts/start_test_scan.sh <계정 ID> <ExternalId>`를 쓴다(이때는 웹에 결과가 나오지 않는다).

## 7. 기록 양식

```
## 배포·스파이크 결과 (YYYY-MM-DD)
- Gemini: 모델=, responseJsonSchema 동작=예/아니오, 응답 시간=초, 한국어 품질=, 한도(RPM/RPD)=
- 배포: 주체 종류(IAM 사용자/Role), 소요 시간=분, 오류=
- CodeBuild: PROVISIONING=초, BUILD=초, 실패 check=개, AccessDenied=건
- 처리: 스캔 시작부터 완료까지=분, AI 해설 성공=개/전체, 폴백=개
- confused deputy: 다른 사용자가 같은 계정 ID로 검증 → 실패 확인=예/아니오
```

## 문제가 생기면

| 증상 | 확인·조치 |
|---|---|
| 배포가 `CognitoDomainPrefix` 관련으로 실패 | 도메인 접두사 충돌. `deploy.sh`의 `COGNITO_PREFIX` 계산에 문자를 덧붙여 다시 배포 |
| `PROVISIONING` 실패 | `PROWLER_IMAGE=prowlercloud/prowler:5.46.0 scripts/deploy.sh`로 Docker Hub 이미지 사용 |
| `BUILD` 실패 | CodeBuild 로그의 오류 줄을 알려 준다. Role 삭제·ExternalId 불일치면 연결을 다시 검증 |
| 리포트가 "Prowler 원문"만 표시 | `GEMINI_MODEL` 설정, SSM 키, `/aws-gap-check/scan-finished` 로그의 `Gemini key unavailable` 확인 |
| 로그인 후 빈 화면 | 브라우저 개발자 도구 콘솔 오류와 `config.json` 내용 확인 |

## 정리

발표 전까지는 지우지 않는다. 지울 때의 순서와 명령은 `docs/demo-runbook.md`의 "발표 후 정리"에 있다. 삭제는 사용자가 결정한다.
