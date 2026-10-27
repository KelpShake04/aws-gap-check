# aws-gap-check 구현 계획

작성일 2026-10-28. 상태: 초안, 사용자 승인 전. 설계: [`docs/superpowers/specs/2026-10-28-aws-gap-check-design.md`](../specs/2026-10-28-aws-gap-check-design.md)

**목표:** 12월 초 발표에서 "로그인 → 계정 연결(ExternalId) → 스캔 → AI 한국어 해설 리포트" 전 과정을 시연할 수 있는 서버리스 웹 서비스를 11/24까지 만든다. 마지막 주는 안정화와 발표 자료에 쓴다.

**구조:** 정적 웹(S3 + CloudFront) → Cognito 로그인 → API Gateway(HTTP API) + Lambda → CodeBuild에서 Prowler가 고객 Role을 맡아 스캔 → 결과 S3 → EventBridge가 처리 Lambda 호출 → 파싱, DynamoDB 저장, Gemini 해설.

**기술 스택:** Python 3.13(Lambda, 표준 라이브러리와 Lambda 내장 boto3), Prowler 5.46.0(버전 고정), CloudFormation(`AWS::Serverless` 변환) + AWS CLI, 빌드 단계 없는 HTML/JS, Gemini REST API(`urllib`), 테스트는 `unittest`.

Prowler CLI 옵션, OCSF 출력 필드, check ID와 심각도는 PyPI의 `prowler==5.46.0` 패키지 소스에서 직접 확인했다.

---

## 1. 승인받을 결정

설계 문서가 빌더에게 남긴 결정과 계획하면서 새로 생긴 결정이다. "제안"대로 진행해도 되는지, 바꿀 항목이 있는지 알려 주면 된다.

| # | 항목 | 제안 | 이유 | 대안 |
|---|---|---|---|---|
| D1 | 스캔 실행 환경 | CodeBuild | VPC, 서브넷, 공인 IP를 설정할 필요가 없어 NAT 문제가 생기지 않는다. `StartBuild` 한 번으로 실행되고 로그, 타임아웃, 상태 이벤트가 기본 제공된다. 월 100분 무료. | Fargate: 공식 이미지를 그대로 돌리기 좋지만 기본 VPC 공개 서브넷과 공인 IP 설정, ECS 클러스터, 태스크 정의가 더 필요하다. T0.5 스파이크에서 CodeBuild가 막히면 전환한다. |
| D2 | IaC | CloudFormation(`AWS::Serverless` 변환) + AWS CLI `package`/`deploy` | 추가 도구 없이 AWS CLI만으로 배포한다. 고객 Role 템플릿도 CloudFormation이라 한 형식으로 통일된다. | CDK: 코드는 짧아지지만 Node.js와 bootstrap 스택이 추가된다. |
| D3 | 배포 위치 | 서비스 계정 콘솔의 CloudShell에서 `scripts/deploy.sh` 실행 | 장기 액세스 키를 만들지 않는다(서비스 컨셉과 일관). git, python, AWS CLI가 이미 있다. 콘솔 로그인은 root가 아닌 관리자 IAM 주체여야 한다. | 로컬 PC + `aws configure sso`. 나중에 GitHub Actions OIDC 배포(선택). |
| D4 | Gemini에 보내는 데이터 | Prowler 점검 메타데이터(check 제목, 설명, 위험, 권장 조치)와 영향 리소스 수, 리전만. 리소스 이름, 태그, 계정 ID, `status_detail`은 보내지 않는다. | 고객 데이터가 Google로 가지 않는다(무료 등급은 입력이 제품 개선에 쓰일 수 있다). 공격자가 조작할 수 있는 문자열이 프롬프트에 없어 인젝션 표면이 사라진다. check 단위라 캐시가 잘 맞아 무료 한도를 아낀다. | v2(시간이 남으면): `status_detail`을 마스킹하고 길이를 제한해 3개까지 추가한다. 리소스별 맞춤 해설이 되지만 마스킹과 인젝션 방어 작업이 늘어난다. |
| D5 | 프런트엔드 | 빌드 없는 HTML + vanilla JS(ES modules), Cognito Hosted UI + PKCE 직접 구현 | npm 의존성 0개. 화면 4개 규모라 프레임워크 이득이 작다. | React + Vite(조원이 React를 안다면). |
| D6 | Gemini 키 저장 | SSM Parameter Store SecureString `/aws-gap-check/gemini-api-key` | 무료(Secrets Manager는 시크릿당 월 $0.40). 값은 사용자가 직접 넣고, 템플릿과 레포에는 파라미터 이름만 둔다. | Secrets Manager. |
| D7 | 가입 방식 | Cognito 셀프 가입 끔, 관리자가 팀원 계정만 생성 | 불특정 사용자 모집은 비목표다. 스캐너 남용과 비용 공격을 막는다. | 셀프 가입 + 이메일 인증. |
| D8 | 점검 범위 | 핵심 check 33개([부록 A](#부록-a-핵심-check-초안)), 리전은 `ap-northeast-2`만 | 시연 시간을 줄인다. 실제 소요 시간은 T0.5에서 측정해 목록을 조정한다. | Prowler 전체(수백 개, 수십 분). |

---

## 2. 아키텍처

```
[브라우저] ──HTTPS──> CloudFront ──OAC──> S3 (정적 웹)
   │  └─ 로그인: Cognito Hosted UI (Authorization Code + PKCE)
   │
   └─ Bearer JWT ──> API Gateway HTTP API (JWT authorizer)
                        │
                        ▼
                   ApiFunction (Lambda)
                     ├─ DynamoDB: 연결, 스캔, 결과
                     ├─ sts:AssumeRole (연결 검증)
                     └─ codebuild:StartBuild (스캔 시작)
                              │
                              ▼
                   CodeBuild (Prowler 5.46.0 이미지)
                     ├─ sts:AssumeRole + ExternalId ──> [고객 계정] AwsGapCheckReadOnlyRole
                     │                                   (SecurityAudit + ViewOnlyAccess)
                     └─ s3:PutObject ──> S3 결과 버킷 raw/{sub}/{scanId}/
                              │
                   EventBridge (CodeBuild 상태 변경)
                              ▼
                   ScanFinishedFunction (Lambda)
                     ├─ 결과 읽기 → 파싱·그룹화 → DynamoDB
                     ├─ SSM의 키로 Gemini API 호출 (해설, 우선순위)
                     └─ SNS (critical/high가 있으면, P2)
```

### 2.1 스캔 한 번의 흐름

1. 사용자가 "스캔"을 누르면 ApiFunction이 연결 상태(ACTIVE)와 사용 한도(사용자당 동시 1개, 하루 10회)를 확인하고 `StartBuild`를 호출한다. 환경 변수 override로 `ROLE_ARN`, `EXTERNAL_ID`, `SCAN_ID`, `USER_SUB`를 넘긴다. 스캔 상태는 `QUEUED`.
2. CodeBuild는 환경 변수를 정규식으로 다시 검증한 뒤 Prowler를 실행한다.
   ```
   prowler aws --role "$ROLE_ARN" --external-id "$EXTERNAL_ID" \
     --checks-file core-checks.json --region ap-northeast-2 \
     -M json-ocsf --ignore-exit-code-3 --no-banner -o out -F prowler
   ```
   `--ignore-exit-code-3`이 없으면 FAIL 항목이 하나만 있어도 Prowler가 종료 코드 3을 내고 빌드가 실패로 끝난다.
3. `upload_result.py`가 `out/prowler.ocsf.json`을 `raw/{sub}/{scanId}/prowler.ocsf.json`에 올린다. 업로드는 CodeBuild 자체 역할로 하고, 고객 계정 자격 증명은 쓰지 않는다.
4. EventBridge 규칙이 이 프로젝트의 `IN_PROGRESS`, `SUCCEEDED`, `FAILED`, `STOPPED`, `TIMED_OUT` 이벤트를 ScanFinishedFunction에 넘긴다. 함수는 `BatchGetBuilds`로 빌드의 환경 변수를 읽어 어느 스캔인지 찾는다.
5. 성공이면 FAIL 항목만 check 단위로 묶어 저장하고(`PROCESSING`), check마다 해설을 붙이고(`EXPLAINING`), 스캔 전체 우선순위 요약을 만든 뒤 `DONE`. 실패면 `FAILED`와 실패한 빌드 단계를 기록한다.
6. 화면은 `GET /scans/{id}`를 5초 간격으로 조회해 진행 상태를 보여 준다.

### 2.2 IAM 역할 (최소 권한)

| 역할 | 허용 | 없는 권한 |
|---|---|---|
| `aws-gap-check-api-role` (ApiFunction) | 테이블 CRUD, `codebuild:StartBuild`(이 프로젝트만), `sts:AssumeRole`(`arn:aws:iam::*:role/AwsGapCheckReadOnlyRole`만), 결과 버킷 `raw/*` List·Delete | Gemini 키 |
| `aws-gap-check-scanner-role` (CodeBuild) | `sts:AssumeRole`(같은 Role 이름만), 결과 버킷 `raw/*` PutObject, 자기 로그 그룹 쓰기 | DynamoDB, SSM |
| `aws-gap-check-processor-role` (ScanFinishedFunction) | `codebuild:BatchGetBuilds`, `raw/*` GetObject, 테이블 CRUD, `ssm:GetParameter`(키 파라미터 하나), SNS Publish | 고객 계정 |
| 고객 계정 `AwsGapCheckReadOnlyRole` | AWS 관리형 `SecurityAudit`, `ViewOnlyAccess` | 쓰기 권한 전부 |

- 고객 Role 신뢰 정책은 서비스 계정을 Principal로 두되, `sts:ExternalId` 일치와 `aws:PrincipalArn`이 위 api/scanner 역할일 때만 허용한다. 서비스 계정의 다른 주체는 ExternalId를 알아도 맡을 수 없다.
- 역할 이름을 고정해 두어 템플릿이 ARN을 만들 수 있다. 사용자는 Role ARN 대신 12자리 계정 ID만 입력하고, 서버가 고정 Role 이름으로 ARN을 만든다(임의 ARN 입력 차단).
- ExternalId는 비밀값이 아니다(AWS 안내). CodeBuild 환경 변수로 평문 전달해도 되며, 서버가 만들고 사용자가 바꿀 수 없다는 점이 핵심이다.

---

## 3. 데이터 설계

### 3.1 DynamoDB 단일 테이블 `aws-gap-check`

On-demand 요금, TTL 속성 `expiresAt`, 기본 암호화.

| 항목 | PK | SK | 주요 속성 |
|---|---|---|---|
| 연결 | `USER#{sub}` | `CONN#{connId}` | accountId, externalId, status(PENDING/ACTIVE/FAILED), verifiedAt |
| 스캔 | `USER#{sub}` | `SCAN#{scanId}` | connId, accountId, status, buildId, 심각도별 개수, aiSummary, 실패 단계, expiresAt |
| 결과(check 단위) | `USER#{sub}#SCAN#{scanId}` | `FIND#{rank}#{checkId}` | title, severity, service, 리소스 목록(최대 100개, uid·name·region), totalCount, Prowler 원문(위험, 권장 조치, 참고 URL), explanation, explainSource(gemini/prowler), expiresAt |
| 해설 캐시 | `EXPLAIN#{checkId}` | `{promptVersion}#{model}` | explanation, createdAt |

- 사용자 데이터 키에는 모두 JWT의 `sub`가 들어간다. 요청 본문이나 경로 값으로 남의 키를 만들 수 없다(IDOR 방지). 결과 항목도 `USER#{sub}#SCAN#...` 키라 sub 없이 접근할 수 없다.
- `scanId`는 `YYYYMMDDHHMMSS-xxxxxxxx`(UTC 시각 + 랜덤 hex 8자리)라 정렬 순서가 곧 시간 순서다.
- 해설 캐시에는 고객 데이터가 없어(D4) 사용자 사이에 공유해도 된다.
- 리소스 태그와 OCSF `resources[].data`(버킷 정책 원문 등)는 저장하지 않는다.

### 3.2 S3

- 정적 웹 버킷: 퍼블릭 차단, CloudFront OAC로만 읽는다.
- 결과 버킷: 퍼블릭 차단, SSE-S3, `aws:SecureTransport` 강제, 버전 관리 끔(삭제가 실제 삭제가 되도록), `raw/` 30일 후 만료.
- 배포 아티팩트 버킷: 퍼블릭 차단, 암호화. `deploy.sh`가 없으면 만든다.

### 3.3 보존과 삭제

- 스캔 결과는 30일 보존(S3 수명주기 + DynamoDB TTL).
- "결과 삭제" 버튼은 해당 스캔의 DynamoDB 항목과 `raw/{sub}/{scanId}/` 객체를 즉시 지운다.
- 연결 삭제는 우리 쪽 기록만 지우고, 고객 계정의 CloudFormation 스택 삭제 방법을 화면에 안내한다.

---

## 4. API

모든 경로는 Cognito JWT(access token)가 필요하다. 본문은 JSON, 16KB 제한. HTTP API 기본 throttling은 초당 5, 버스트 10.

| 메서드와 경로 | 동작 |
|---|---|
| `POST /connections` | 서버가 ExternalId(`agc-` + hex 32자리)를 만들어 PENDING 연결을 생성한다. 응답에 ExternalId, 서비스 계정 ID, 템플릿 다운로드 경로 |
| `GET /connections` | 내 연결 목록 |
| `POST /connections/{id}/verify` | body `{accountId}`(12자리 숫자만). ExternalId로 AssumeRole → GetCallerIdentity로 계정 일치 확인 → ACTIVE |
| `DELETE /connections/{id}` | 연결 기록 삭제 |
| `POST /scans` | body `{connectionId}`. 한도 확인 후 StartBuild |
| `GET /scans` | 내 스캔 목록 |
| `GET /scans/{id}` | 스캔 상태, check별 결과, 해설, 우선순위 요약 |
| `DELETE /scans/{id}` | 결과 즉시 삭제 |

템플릿은 웹사이트에서 내려받아 CloudFormation 콘솔에 업로드하는 방식으로 시작한다. quick-create 링크는 템플릿을 S3 URL로 공개해야 해서 여유가 있을 때 검토한다.

---

## 5. AI 해설 설계

- **모델 교체 지점:** `backend/gapcheck/llm.py`의 `generate_json(system, user, schema) -> dict` 하나. Gemini REST API(`POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`)를 `urllib`로 호출한다. 키는 URL 쿼리가 아니라 `x-goog-api-key` 헤더로 보내 로그에 남지 않게 한다. `generationConfig.responseMimeType=application/json`과 응답 스키마로 JSON만 받는다. 모델 이름은 환경 변수 `GEMINI_MODEL`이고 T0.2에서 확인한 Flash 모델로 정한다. Bedrock으로 바꿀 때는 이 파일만 바꾼다.
- **check별 해설.** 입력: check_id, 제목, 심각도, 서비스, 리소스 유형, Prowler 설명·위험·권장 조치, 영향 리소스 수, 리전 목록. 출력 스키마:
  ```json
  {"summary": "≤80자", "risk": "≤400자", "impact": "≤400자", "steps": ["각 ≤200자, 1~5개"]}
  ```
- **스캔 우선순위 요약.** 입력: 실패 check의 (check_id, 제목, 심각도, 개수) 목록. 출력: `{"overall": "≤300자", "top": [{"check_id": "...", "reason": "≤200자"}]}`(최대 3개). `top[].check_id`가 이번 스캔의 실패 check 목록에 없으면 버린다(환각 방지).
- **검증:** 모델이 스키마를 지켜도 서버에서 다시 검증한다. `gapcheck/validate.py`는 type, required, maxLength, maxItems, enum만 지원하는 작은 검증기다(표준 라이브러리). 스키마에 없는 필드는 버리고, 실패하면 1회 재시도 후 폴백한다.
- **폴백:** Gemini 오류, 한도 초과, 검증 실패 시 Prowler 원문(영어 위험·권장 조치)을 `explainSource=prowler`로 저장하고 화면에 "AI 해설 생성 실패, 원문 표시"로 보여 준다. 시연 화면이 비지 않는다.
- **한도 관리:** 캐시(`EXPLAIN#{checkId}`)를 먼저 본다. 호출 간격은 설정값 `GEMINI_MAX_RPM`으로 조절하고, 429는 응답의 재시도 대기 시간만큼 기다려 1회 재시도한다. Lambda 남은 시간이 60초 미만이면 남은 항목은 폴백으로 채운다. 발표 전에 핵심 check 해설을 미리 캐시해 두고(`scripts/warm_cache.py`), 우선순위 요약은 매번 새로 호출해 라이브 AI 호출을 보여 준다.
- **출력 처리:** 해설은 화면에서 `textContent`로만 넣는다. 해설은 어떤 API 호출이나 리소스 변경도 일으키지 않는다(조언 전용).

---

## 6. 레포 구조

```
infra/
  service.yaml             서비스 계정 스택 전체
  customer-role.yaml       고객(테스트) 계정용 읽기 전용 Role
backend/
  gapcheck/                순수 로직. boto3를 import하지 않고 클라이언트를 인자로 받는다
    ids.py                 ExternalId, scanId 생성, 계정 ID 검증
    store.py               DynamoDB 키 규칙과 읽기/쓰기
    connections.py         연결 생성, 검증(AssumeRole), 삭제
    scans.py               스캔 시작, 조회, 삭제, 사용 한도
    findings.py            Prowler OCSF 파싱, 그룹화, 정렬
    validate.py            작은 JSON 스키마 검증기
    explain.py             프롬프트, 캐시, 호출 간격, 폴백
    llm.py                 Gemini 호출 (모델 교체 지점)
  handlers/
    api.py                 HTTP API 라우터 (ApiFunction)
    scan_finished.py       CodeBuild 상태 이벤트 처리 (ScanFinishedFunction)
scanner/
  buildspec.yml
  core-checks.json         {"aws": [...]} (Prowler --checks-file 형식)
  upload_result.py
frontend/
  index.html  app.js  auth.js  api.js  style.css
tests/
  fixtures/                OCSF 샘플(합성, 이후 익명화한 실제 샘플), HTTP API·EventBridge 이벤트 샘플
  test_*.py
scripts/
  deploy.sh                package → deploy → 프런트 업로드, config.json 생성 → CloudFront 무효화
  spike_gemini.py          SSM에서 키를 읽어 모델 목록과 구조화 출력 1회 확인 (키는 출력하지 않음)
  sanitize_ocsf.py         실제 결과의 계정 ID, ARN, 리소스 이름을 치환해 fixture로 만듦
  warm_cache.py            핵심 check 해설 미리 생성
.github/workflows/test.yml unittest + cfn-lint
```

`gapcheck/`가 boto3를 import하지 않으므로 테스트는 표준 라이브러리 `unittest`만으로 돈다. AWS 클라이언트와 HTTP 호출은 가짜 객체를 주입한다.

**새 의존성:** 런타임 0개(boto3는 Lambda 런타임과 Prowler 이미지에 이미 있다). 개발용으로 CI에서만 `cfn-lint`를 쓴다. 템플릿 오류를 배포 전에 잡을 방법이 표준 라이브러리에는 없고, Claude 세션은 AWS에 배포할 수 없어서 템플릿 검증을 CI에서 해야 사용자와의 왕복이 줄어든다.

---

## 7. 작업 방식

- **역할 분담**
  - Claude(클라우드 세션): 코드, 템플릿, 테스트, PR. AWS 자격 증명과 Gemini 키는 받지 않는다.
  - 사용자: CloudShell 배포, SSM에 키 저장, 스파이크 실행 후 결과 공유(키, 계정 ID 제외), PR 리뷰와 머지, 비용이 드는 작업 승인.
  - 조원(연락되면): 자기 계정에 `customer-role.yaml` 배포, 취약 리소스 생성과 삭제, 발표 자료 일부(아키텍처 그림, 보안 설계 슬라이드), 리허설. 연락이 안 되면 서비스 계정 안 Role로 대체하고, 같은 계정이라는 점을 발표에서 밝힌다.
- **브랜치와 PR:** Phase마다 브랜치 1개와 PR 1개(큰 Phase는 나눈다). main 직접 push 금지, 머지는 사용자.
- **TDD:** `gapcheck/` 로직은 테스트를 먼저 쓰고 실패를 확인한 뒤 구현한다. 실행: `python -m unittest discover -s tests -v`.
- **"완료" 기준:** 코드 작업은 unittest와 cfn-lint 통과 + PR. 기능 완료는 사용자가 배포해서 각 Phase의 "배포 확인" 항목을 실제로 확인한 뒤다. 확인 결과는 `docs/HANDOFF.md`에 적는다.
- **실행 전에 사용자 확인이 필요한 AWS 작업:** 스택 첫 배포와 IAM이 크게 바뀌는 업데이트, 스택·버킷 삭제, 취약 리소스 생성, 서비스 한도 상향 요청.

---

## 8. 단계별 작업

우선순위: **P0** 시연에 반드시 필요, **P1** 발표 품질, **P2** 여유가 있으면.

### Phase 0. 기반과 스파이크 (10/28–11/03)

**T0.1 레포 골격 [Claude, P0]**
- `.gitignore`(`.env`, `*.pem`, `out/`, `__pycache__/`, `frontend/config.json`), 6장의 디렉터리, `tests/test_smoke.py`, `.github/workflows/test.yml`(Python 3.13, unittest, cfn-lint).
- 확인: CI 통과.

**T0.2 Gemini 스파이크 [Claude 작성 → 사용자 실행, P0]**
- 먼저 `llm.py`와 `tests/test_llm.py`를 쓴다. 테스트: 요청 본문과 헤더 형식, 키가 URL과 예외 메시지에 없음, 429, 안전 필터 차단 응답, 잘못된 JSON 처리.
- 사용자: AI Studio에서 키 발급 → CloudShell에서 아래처럼 저장(키가 화면과 셸 히스토리에 남지 않게) → `python3 scripts/spike_gemini.py`.
  ```
  read -rs GEMINI_KEY
  aws ssm put-parameter --name /aws-gap-check/gemini-api-key --type SecureString --value "$GEMINI_KEY"
  unset GEMINI_KEY
  ```
- 기록: 사용 가능한 Flash 모델 이름, 구조화 출력 성공 여부, 한국어 품질, AI Studio에 표시된 RPM/RPD.
- 확인: 스키마에 맞는 한국어 JSON을 1회 받음.

**T0.3 배포 환경 확인 [사용자, P0]**
- CloudShell에서 `aws sts get-caller-identity`로 root가 아닌 관리자 주체인지 확인하고 레포를 clone한다.
- Service Quotas에서 CodeBuild 동시 실행 한도를 확인한다. 신규 계정은 낮을 수 있다. 1이어도 시연에는 충분하지만 상향 요청은 시간이 걸리므로 첫 주에 본다.

**T0.4 고객 Role 템플릿 [Claude 작성 → 사용자 배포, P0]**
- `infra/customer-role.yaml`: 파라미터 `ServiceAccountId`(12자리 숫자 패턴), `ExternalId`(허용 문자 패턴). Role `AwsGapCheckReadOnlyRole`, 2.2절의 신뢰 정책, `SecurityAudit`와 `ViewOnlyAccess`, `MaxSessionDuration` 3600, 출력 RoleArn.
- 사용자는 먼저 서비스 계정 자체에 배포해 스파이크 대상으로 쓴다(ServiceAccountId = 자기 계정).

**T0.5 스캐너 최소 스택과 Prowler 스파이크 [Claude 작성 → 사용자 배포·실행, P0]**
- `infra/service.yaml` 1차: 결과 버킷, CodeBuild 프로젝트(이미지 `public.ecr.aws/prowler-cloud/prowler:5.46.0` 고정, 소스는 아티팩트 버킷의 `scanner/` zip, 타임아웃 30분, `general1.small`), scanner 역할, 로그 그룹 14일 보존.
- `scanner/buildspec.yml`, `scanner/core-checks.json`, `scanner/upload_result.py`. 테스트: 업로드 키 경로 규칙, 빈 파일과 깨진 JSON 거부.
- 사용자: 콘솔에서 환경 변수 override로 빌드 1회 실행.
- 기록: 이미지 태그 존재 여부와 pull 시간, 스캔 시간, AccessDenied 오류 여부, 결과 크기, 실패 check 수, `--region` 지정 시 IAM 같은 글로벌 서비스 check가 함께 도는지.
- **전환 기준:** 공식 이미지가 CodeBuild에서 돌지 않고(비 root 사용자, entrypoint 문제 등), 표준 이미지 + `pip install prowler==5.46.0`도 설치에만 5분을 넘기면 Fargate(기본 VPC 공개 서브넷 + 공인 IP, NAT 없음)로 바꾼다. 그 경우 T0.5와 Phase 2를 고쳐 다시 승인받는다.

**T0.6 결과 샘플 [Claude, P0]**
- Prowler 소스의 OCSF 매핑(`prowler/lib/outputs/ocsf/ocsf.py`)대로 합성 fixture를 먼저 만든다. 태그와 리소스 이름에 인젝션 문구와 HTML 조각을 넣는다.
- 스파이크 결과가 나오면 사용자가 `scripts/sanitize_ocsf.py`로 익명화하고, 내용을 직접 확인한 뒤 fixture로 추가한다.

**Phase 0 종료 조건:** Gemini JSON 응답 1회, CodeBuild에서 핵심 check 스캔 완료와 결과 업로드, 실행 환경 확정, HANDOFF 갱신.

### Phase 1. 로그인과 계정 연결 (11/04–11/07)

**T1.1 `ids.py` [P0]** 테스트 먼저: ExternalId 형식과 유일성, 계정 ID는 `^\d{12}$`만 통과(공백, 13자리, 문자 거부), scanId 정렬 순서.

**T1.2 `store.py` [P0]** 키 함수와 저장소 함수(테이블 객체 주입). 테스트: 다른 sub로 조회하면 결과 없음(IDOR), TTL 값 설정.

**T1.3 `connections.py` [P0]** create, verify, delete. verify 테스트: 성공, AccessDenied면 FAILED와 안내 메시지, 다른 계정 ID가 응답되면 거부, ExternalId는 항상 저장된 서버 값 사용.

**T1.4 `handlers/api.py` [P0]** HTTP API v2 이벤트 라우팅. 사용자 식별은 `requestContext.authorizer.jwt.claims.sub`로만 한다. 본문 크기와 JSON 오류를 처리하고, 오류 응답에 내부 정보(스택 트레이스, ARN)를 넣지 않는다. 테스트는 이벤트 샘플로.

**T1.5 `service.yaml` 2차 [P0]** DynamoDB, Cognito(관리자만 사용자 생성, Hosted UI 도메인, 시크릿 없는 클라이언트 + code flow), HTTP API + JWT authorizer + CORS(CloudFront 도메인만) + throttling, ApiFunction, 정적 웹 버킷 + CloudFront + OAC. CloudFront, Cognito 콜백 URL, HTTP API CORS 사이에 순환 참조가 생기지 않게 배치한다.

**T1.6 프런트 최소 [P0]** `auth.js`(PKCE 로그인·로그아웃, 토큰은 sessionStorage), 연결 화면(ExternalId 표시, 템플릿 다운로드, 계정 ID 입력, 검증 버튼). `deploy.sh`가 스택 출력으로 `config.json`을 만든다.

배포 확인:
- [ ] Cognito 사용자 2명 생성, 로그인과 로그아웃 동작
- [ ] 연결 생성 → 템플릿 배포(서비스 계정 또는 조원 계정) → 검증 후 ACTIVE
- [ ] **Confused deputy 시나리오:** 사용자 B가 같은 계정 ID로 연결을 만들어 검증하면 B의 ExternalId가 달라 실패
- [ ] 토큰 없이 API 호출하면 401

### Phase 2. 스캔 실행 (11/08–11/11)

**T2.1 `scans.py` [P0]** start(ACTIVE 확인, 동시 1개·하루 10회 한도, StartBuild override, QUEUED 저장), list, get, delete(S3 `raw/{sub}/{scanId}/`와 DynamoDB 항목). 테스트: 한도 초과 거부, 남의 연결 ID로 시작 불가, CodeBuild 한도 오류는 429로 변환.

**T2.2 buildspec 확정 [P0]** 환경 변수를 정규식으로 다시 검증하고 실패하면 즉시 종료한다(명령 주입 방지). 변수는 모두 따옴표로 감싼다. 로그에는 Prowler 요약만 남긴다.

**T2.3 `scan_finished.py` 1차 [P0]** 이벤트 → `BatchGetBuilds`로 SCAN_ID, USER_SUB 확인 → 상태 갱신(RUNNING, 또는 FAILED와 실패 단계). 같은 이벤트가 두 번 와도 결과가 같아야 한다(멱등).

**T2.4 `service.yaml` 3차 [P0]** EventBridge 규칙(프로젝트 이름으로 필터), ScanFinishedFunction, 권한.

배포 확인:
- [ ] 스캔 시작 → CodeBuild 실행 → 결과 파일이 S3에 생성 → 상태 갱신
- [ ] 고객 Role의 ExternalId를 일부러 틀리게 한 스캔은 FAILED로 표시
- [ ] 연속으로 두 번 시작하면 두 번째는 거부

### Phase 3. 결과 처리와 AI 해설 (11/12–11/18)

**T3.1 `findings.py` [P0]** OCSF에서 필요한 필드만 꺼낸다: `metadata.event_code`(check ID), `status_code`, `severity`, `finding_info.title`/`desc`, `risk_details`, `remediation.desc`/`references`, `resources[].uid`/`name`/`region`/`type`. FAIL만 남기고 check 단위로 묶은 뒤 심각도(critical → informational), 리소스 수 순으로 정렬한다. check당 리소스는 100개까지. 테스트: fixture 기반 개수, 정렬, 상한, 알 수 없는 심각도, 태그와 `resources[].data`가 결과에 없음.

**T3.2 `validate.py` [P0]** 테스트: 필수 필드 누락, 길이 초과, 배열 초과, 타입 오류, 추가 필드 제거.

**T3.3 `explain.py` [P0]** 테스트: fixture의 리소스 이름, 태그, 계정 ID, 인젝션 문구가 프롬프트 문자열에 하나도 없음. 캐시가 있으면 LLM을 호출하지 않음. 검증 실패 → 1회 재시도 → 폴백. 시간 예산 초과 → 폴백.

**T3.4 우선순위 요약 [P1]** 테스트: 실패 목록에 없는 check_id 제거.

**T3.5 `scan_finished.py` 2차 [P0]** 파싱 → 저장 → 해설 → 요약 → DONE. 함수 타임아웃 600초.

배포 확인:
- [ ] 실제 스캔 결과에 한국어 해설이 붙고, 두 번째 스캔은 캐시 덕분에 Gemini 호출 수가 줄어듦(로그로 확인)
- [ ] `GEMINI_MODEL`을 잘못된 값으로 배포하면 Prowler 원문 폴백이 표시됨(확인 후 되돌림)
- [ ] CloudWatch 로그에 API 키와 토큰이 없음

### Phase 4. 리포트 화면과 전체 시연 (11/19–11/24)

**T4.1 화면 [P0]** 스캔 목록, 시작, 진행 상태(5초 폴링). 리포트: 심각도별 개수, AI 우선순위 Top 3, check 카드(요약, 위험, 영향, 조치 단계, 영향 리소스 목록, 해설 출처), 결과 삭제 버튼. 데이터는 모두 `textContent`와 DOM API로 넣는다. CI 테스트로 `frontend/*.js`에 `innerHTML`, `insertAdjacentHTML`, `eval`이 없는지 검사한다.

**T4.2 보안 헤더 [P1]** CloudFront Response Headers Policy: CSP(`default-src 'self'`, `connect-src`는 API와 Cognito 도메인만, `frame-ancestors 'none'`), HSTS, `X-Content-Type-Options`.

**T4.3 SNS 알림 [P2]** critical/high가 있으면 개수와 링크만 메일로 보낸다(리소스 정보 제외). 메일 주소는 배포 파라미터.

**T4.4 시연 시나리오 [사용자·조원, P0]** 테스트 계정에 비용이 거의 없는 취약 설정을 만든다. 만들기 전에 사용자 확인을 받고, 시연 후 삭제 체크리스트로 지운다.
- 22번 포트를 0.0.0.0/0에 연 Security Group(인스턴스 없음)
- MFA 없는 콘솔 IAM 사용자(액세스 키 없음)
- 퍼블릭 액세스 차단을 끈 S3 버킷(실제 공개 정책을 넣을지는 사용자 결정, 넣는다면 더미 파일만)
- EBS 기본 암호화 꺼짐(대부분 계정의 기본값)
- 태그 값에 인젝션 문구를 넣은 리소스 1개(프롬프트 인젝션·XSS 방어 시연용)

**T4.5 E2E 리허설 [P0]** 처음부터 끝까지 1회 돌리고, 버그 목록을 만들어 고친다.

배포 확인:
- [ ] 조원(또는 대체) 계정으로 로그인 → 연결 → 스캔 → 리포트까지 10분 이내
- [ ] 태그에 넣은 인젝션 문구가 Gemini로 가지 않고, 리포트에는 글자 그대로만 보임

### Phase 5. 마감 (11/25–12/01, 기능 동결 11/27)

**T5.1 사전 스캔 [P0]** 발표 전날 스캔해 결과를 남기고 화면을 캡처한다. 라이브 시연이 실패하면 이 결과로 진행한다.

**T5.2 발표 문서 [P0]**
- `docs/architecture.md`: 그림, 서비스별 역할, IAM 역할 표, 비용
- `docs/security-design.md`: 위협과 대응 표(confused deputy, 액세스 키 미수령, IDOR, XSS, 프롬프트 인젝션, Google 전송 데이터 최소화, 빌드 명령 주입, 비용 남용)
- `docs/demo-runbook.md`: 시연 순서, 실패 시 대체 경로

**T5.3 정리 계획 [P1]** 발표 후 삭제 순서(취약 리소스 → 고객 Role 스택 → 서비스 스택 → 버킷). 실행은 사용자 확인 후.

**여유가 있으면:** EventBridge 정기 스캔, D4의 v2 입력, 직접 만든 최소 권한 정책(SecurityAudit 대체), GitHub Actions OIDC 배포, CloudFormation quick-create 링크.

---

## 9. 일정

| 주 | 기간 | 범위 | 마일스톤 |
|---|---|---|---|
| 1 | 10/28–11/03 | Phase 0 | 계획 승인, Gemini·CodeBuild 스파이크 완료, 실행 환경 확정 |
| 2 | 11/04–11/11 | Phase 1, 2 | 배포 환경에서 로그인 → 연결 → 스캔 시작 동작 |
| 3 | 11/12–11/18 | Phase 3 | 한국어 해설이 붙은 결과 저장 |
| 4 | 11/19–11/24 | Phase 4 | **MVP 완료**: 전 과정 시연 가능 |
| 5 | 11/25–12/01 | Phase 5 | 기능 동결 11/27, 문서, 리허설, 사전 스캔 |

일정이 밀리면 P2, P1 순으로 뺀다. P0는 줄이지 않는다.

---

## 10. 비용 추정 (월, 스캔 30회 가정)

| 항목 | 예상 |
|---|---|
| CodeBuild `general1.small` | 30회 × 약 6분 = 180분. 무료 100분을 빼면 80분 × $0.005 ≈ $0.4 (서울 리전 단가는 확인 필요) |
| Lambda, API Gateway, DynamoDB, Cognito, CloudFront, S3 | 사용량이 작아 $0~0.5 |
| CloudWatch Logs (14일 보존) | 약 $0.1 |
| SSM SecureString, KMS `aws/ssm` | $0 |
| Gemini | 무료 등급 |
| **합계** | **약 $1~2** (예산 $10 이내, NAT Gateway 없음) |

---

## 11. 위험과 대응

| 위험 | 대응 |
|---|---|
| Gemini 무료 한도가 낮거나 모델이 바뀜 | check 단위 캐시, 호출 간격 조절, Prowler 원문 폴백, 모델 이름은 설정값, 발표 전 캐시 미리 채움 |
| CodeBuild에서 Prowler 이미지가 안 돌거나 동시 실행 한도가 낮음 | 첫 주 T0.3, T0.5에서 확인, 전환 기준에 따라 Fargate |
| 조원 연락 불가 | 서비스 계정 안 Role로 대체(발표에서 명시) |
| Prowler 업데이트로 check ID나 출력 형식이 바뀜 | 5.46.0 고정, 업그레이드는 fixture 테스트 통과 후 |
| 배포 권한 부족 | 첫 주 T0.3에서 확인 |
| 비용 초과 | 기존 Budgets 알림, 사용자별 스캔 한도, 로그 보존 14일, NAT 없음 |
| 중지한 RDS(`dev-robby-rds`)가 7일 뒤 자동 시작 | 프로젝트와 별개지만 매주 확인(삭제 여부는 사용자 결정) |
| 일정 지연 | P0/P1/P2 우선순위, 기능 동결 11/27 |

---

## 12. 아직 모르는 것과 확인 시점

| 모르는 것 | 확인 |
|---|---|
| Gemini 사용 가능 모델과 한도 | T0.2 |
| 배포 권한, CodeBuild 한도 | T0.3 |
| CodeBuild와 Fargate 중 최종 선택 | T0.5 |
| Prowler 실행 시간, 권한 충분 여부 | T0.5 |
| 평가 기준(IaC 필수 여부, 시연 시간) | 사용자가 수업 공지 확인 후 범위와 일정 조정 |
| 조원 참여 | 11/04까지 연락이 안 되면 대체 경로로 확정 |

---

## 부록 A. 핵심 check 초안

`scanner/core-checks.json`에 들어갈 목록이다. ID와 심각도는 Prowler 5.46.0 메타데이터 기준. T0.5에서 실행 시간과 권한 오류를 보고 조정한다.

**S3 공개·암호화 (8)**
| check ID | 심각도 |
|---|---|
| `s3_bucket_public_access` | critical |
| `s3_bucket_public_list_acl` | critical |
| `s3_bucket_public_write_acl` | critical |
| `s3_bucket_policy_public_write_access` | critical |
| `s3_account_level_public_access_blocks` | high |
| `s3_bucket_level_public_access_block` | high |
| `s3_bucket_default_encryption` | medium |
| `s3_bucket_secure_transport_policy` | medium |

**Security Group (7)**
| check ID | 심각도 |
|---|---|
| `ec2_securitygroup_allow_ingress_from_internet_to_all_ports` | critical |
| `ec2_securitygroup_allow_ingress_from_internet_to_any_port` | high |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | high |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389` | high |
| `ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports` | high |
| `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306` | high |
| `ec2_securitygroup_default_restrict_traffic` | high |

**IAM (10)**
| check ID | 심각도 |
|---|---|
| `iam_root_mfa_enabled` | critical |
| `iam_no_root_access_key` | critical |
| `iam_user_administrator_access_policy` | critical |
| `iam_avoid_root_usage` | high |
| `iam_user_mfa_enabled_console_access` | high |
| `iam_policy_allows_privilege_escalation` | high |
| `iam_role_cross_service_confused_deputy_prevention` | high |
| `iam_rotate_access_key_90_days` | medium |
| `iam_user_accesskey_unused` | medium |
| `iam_password_policy_minimum_length_14` | medium |

**암호화·노출 (7)**
| check ID | 심각도 |
|---|---|
| `ec2_ebs_public_snapshot` | critical |
| `rds_instance_no_public_access` | critical |
| `ec2_ebs_default_encryption` | high |
| `ec2_ebs_volume_encryption` | high |
| `ec2_ebs_snapshots_encrypted` | high |
| `rds_instance_storage_encrypted` | high |
| `kms_cmk_rotation_enabled` | high |

**로깅 (1)**
| check ID | 심각도 |
|---|---|
| `cloudtrail_multi_region_enabled` | high |
