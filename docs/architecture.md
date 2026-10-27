# 아키텍처

발표 자료용 요약. 설계 배경은 `docs/superpowers/specs/`, 작업 계획은 `docs/superpowers/plans/`에 있다.

## 한 장 그림

```
[브라우저] ──HTTPS──> CloudFront ──OAC──> S3 (정적 웹, 비공개 버킷)
   │  └─ 로그인: Cognito Hosted UI (Authorization Code + PKCE)
   │
   └─ Bearer JWT ──> API Gateway HTTP API (JWT authorizer, throttling)
                        │
                        ▼
                   ApiFunction (Lambda)
                     ├─ DynamoDB: 연결, 스캔, 결과 (키에 사용자 sub)
                     ├─ sts:AssumeRole (연결 검증)
                     └─ codebuild:StartBuild (스캔 시작)
                              │
                              ▼
                   CodeBuild (Prowler 5.46.0 공식 이미지)
                     ├─ sts:AssumeRole + ExternalId ──> [고객 계정] AwsGapCheckReadOnlyRole
                     │                                   (SecurityAudit + ViewOnlyAccess)
                     └─ s3:PutObject ──> 결과 버킷 raw/{sub}/{scanId}/ (30일 후 삭제)
                              │
                   EventBridge (CodeBuild 상태 변경)
                              ▼
                   ScanFinishedFunction (Lambda)
                     ├─ 결과 읽기 → FAIL만 check 단위로 묶어 DynamoDB에 저장
                     └─ SSM SecureString의 키로 Gemini API 호출 → 한국어 해설, 우선순위
```

## 서비스별 역할

| 서비스 | 역할 | 고른 이유 |
|---|---|---|
| S3 + CloudFront | 웹 화면 | 서버 없이 정적 호스팅, OAC로 버킷 비공개 유지, 보안 헤더(CSP) |
| Cognito | 로그인 | 관리형 인증, PKCE, 관리자만 사용자 생성 |
| API Gateway HTTP API | API | JWT 검증을 게이트웨이에서 처리, REST API보다 저렴 |
| Lambda | API, 결과 처리 | 요청이 있을 때만 실행, 무료 사용량 안 |
| CodeBuild | Prowler 실행 | VPC·NAT 없이 인터넷 접근, 분 단위 과금(월 100분 무료), 로그·타임아웃 기본 제공 |
| EventBridge | 스캔 끝 알림 | 폴링 없이 빌드 상태 변경을 받음 |
| DynamoDB | 연결·스캔·결과·해설 캐시 | 온디맨드 과금, TTL로 자동 삭제 |
| SSM Parameter Store | Gemini 키 | SecureString 무료, 키를 코드·레포·템플릿에 두지 않음 |
| Gemini API | 해설, 우선순위 | Bedrock 모델 접근 불가로 대체. 호출부(`llm.py`) 하나만 바꾸면 교체 가능 |

## IAM 역할

| 역할 | 할 수 있는 일 | 할 수 없는 일 |
|---|---|---|
| `aws-gap-check-api-role` | 테이블 읽기·쓰기, 스캐너 빌드 시작, 고객 Role 맡기(검증), 결과 파일 삭제 | Gemini 키 읽기 |
| `aws-gap-check-scanner-role` | 고객 Role 맡기, 결과 파일 쓰기(`raw/*`), 로그 쓰기 | DynamoDB, SSM |
| `aws-gap-check-processor-role` | 빌드 정보 읽기, 결과 파일 읽기, 테이블 쓰기, Gemini 키 읽기 | 고객 계정 접근 |
| 고객 `AwsGapCheckReadOnlyRole` | 읽기 전용 점검(SecurityAudit, ViewOnlyAccess) | 모든 쓰기 |

고객 Role 신뢰 정책은 ExternalId 일치와 `aws:PrincipalArn`(api, scanner 역할) 두 조건을 모두 요구한다.

## 스캔 한 번의 흐름

1. 사용자가 스캔을 시작하면 API가 연결 상태와 한도(동시 1개, 하루 10회)를 확인하고 스캔을 `QUEUED`로 저장한 뒤 CodeBuild를 시작한다.
2. CodeBuild의 `run_scan.py`가 입력을 정규식으로 검증하고, 셸 없이 Prowler를 실행해 핵심 check 33개를 점검한다.
3. 결과(OCSF JSON)를 `raw/{sub}/{scanId}/`에 올린다.
4. EventBridge가 빌드 상태를 처리 Lambda에 넘긴다. 실패면 `FAILED`, 성공이면 파싱 → 저장(`EXPLAINING`) → check마다 해설 → 우선순위 요약 → `DONE`.
5. 화면은 5초마다 상태를 조회해 해설이 붙는 과정을 보여 준다.

## 비용 (월, 스캔 30회 가정)

CodeBuild 약 $0.4(무료 100분 초과분), 나머지(Lambda, API Gateway, DynamoDB, Cognito, CloudFront, S3, 로그)는 사용량이 작아 $1 미만. Gemini는 무료 등급. NAT Gateway와 상시 서버가 없다.
