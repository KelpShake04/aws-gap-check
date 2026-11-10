# 아키텍처

발표 자료용 요약. 실행 방법은 `docs/container.md`, 설계 배경은 `docs/superpowers/specs/2026-10-28-container-redesign.md`에 있다. 서버리스 구성(2026-10-28 이전)은 `legacy/serverless/`에 보관했다.

## 한 장 그림

```
[브라우저] ──HTTPS(443)──> EC2 한 대 (Ubuntu 24.04, Docker Compose)
                            │
                            ├─ caddy: TLS 종료(Let's Encrypt, <이름>.duckdns.org), 80은 인증서 발급·리다이렉트
                            │    └─> app:8080 (외부에 열리지 않음)
                            ├─ app: Python 표준 라이브러리 HTTP 서버 + 스캔 작업자 스레드
                            │    ├─ mysql:3306: 사용자, 세션, 연결, 스캔, 결과, 해설 캐시
                            │    ├─ Prowler 5.47.0 (같은 이미지, 셸 없이 인자 목록으로 실행)
                            │    │    └─ check 메타데이터: 공식 수정 예시(콘솔·CLI·CloudFormation·Terraform)
                            │    │    └─ compliance JSON: check → ISMS-P 통제 항목(KISA 2023) 매핑
                            │    │    └─ sts:AssumeRole + ExternalId ──> [고객 계정] AwsGapCheckReadOnlyRole
                            │    │                                        (SecurityAudit + ViewOnlyAccess)
                            │    │    └─ Cost Explorer(us-east-1): 비용 조회 (같은 Role, 6시간 캐시)
                            │    ├─ 스케줄러(작업자 스레드): 주기가 지난 연결에 자동 스캔 생성
                            │    ├─ Amazon SES: 새 위험 항목 알림 메일 (확인된 보내는 주소 하나)
                            │    ├─ SSM SecureString: Gemini 키 (인스턴스 Role로 읽음)
                            │    └─ Gemini API: 한국어 해설, 우선순위 (실패하면 Prowler 원문)
                            │         └─ AI 상담 Agent: function calling, 읽기 전용 도구 5개(본인 스캔 DB만)
                            └─ mysql: 앱 전용 계정(SELECT/INSERT/UPDATE/DELETE만), 볼륨에 영속
```

배포(CD):

```
[개발자] PR → main 병합 ──> GitHub Actions test (unittest + MySQL 8.4.9 + cfn-lint)
                              └─ 성공 ──> deploy (environment production: 관리자 승인 필요)
                                           └─ OIDC(액세스 키 없음) ──> aws-gap-check-github-deploy Role
                                                └─ ssm:SendCommand(고정 문서 agc-deploy만) ──> EC2
                                                     잠금 → git pull → build → 진행 중 스캔 대기 → 교체 → 응답 확인
```

AWS 쪽에서 필요한 것은 EC2 한 대, 인스턴스 Role, Security Group(80, 443), SSM 파라미터 2개(Gemini 키, DuckDNS 토큰)이고, 알림 메일을 쓰면 SES에서 확인된 이메일 주소가 더 필요하다. `infra/ec2.yaml` 하나로 만든다.

## 구성 요소별 역할

| 구성 요소 | 역할 | 고른 이유 |
|---|---|---|
| EC2 1대 | 모든 컨테이너 실행 | 과제 조건(EC2 1개), 조원이 배포·설명하기 쉬움 |
| Docker Compose | mysql, app, caddy를 한 번에 기동 | 서비스가 늘어도 명령은 `docker compose up -d` 하나, `restart: unless-stopped`로 재부팅 후 자동 기동 |
| caddy | HTTPS | 인증서 발급·갱신 자동, 앱은 HTTP만 처리 |
| 앱(Python 표준 라이브러리) | 로그인, API, 정적 파일, 스캔 작업자 | 의존성은 PyMySQL 하나(해시 고정) |
| MySQL 8.4.9 | 데이터 저장 | 수업 RDS와 같은 버전, 평가 항목(DBMS·ERD)에 대응. ERD는 `docs/erd.md` |
| Prowler 5.47.0 | 점검 실행, 공식 수정 예시 | 공식 이미지를 기반으로 앱 코드만 얹음. OCSF 결과에는 수정 코드가 없어서 이미지 안 `<check>.metadata.json`의 `Remediation.Code`를 check ID로 읽어 화면에 붙인다(`findings.remediation_code`, 자동 적용 안 함) |
| SSM Parameter Store | Gemini 키, DuckDNS 토큰 | SecureString 무료, 키를 코드·레포·user data에 두지 않음 |
| Gemini API | 해설, 우선순위 | Bedrock 모델 접근 불가로 대체. 호출부(`llm.py`) 하나만 바꾸면 교체 가능 |
| Cost Explorer | 계정별 이번 달 비용·예상·서비스별 비중 | 스캔과 같은 고객 Role로 조회. 호출당 $0.01이라 6시간 메모리 캐시, 새로고침 5분 제한(`billing.py`) |
| 스케줄러 | 자동 점검(매일/매주) | 별도 서비스 없이 작업자 스레드가 60초마다 확인(`scheduler.py`). 스캔은 수동 스캔과 같은 큐·한도를 쓴다 |
| Amazon SES | 알림 메일 | 비밀번호·SMTP 키 없이 인스턴스 Role로 발송. 직전 스캔에 없던 치명·높음 항목이 있을 때만(`notify.py`) |
| DuckDNS | 무료 도메인 | Elastic IP 없이 부팅마다 현재 IP를 등록 |
| ISMS-P 매핑 | 리포트를 국내 인증 기준(KISA ISMS-P 2023) 통제 항목별로 묶어 보기 | Prowler 이미지 안 `kisa_isms_p_2023_korean_aws.json`을 check ID로 읽음(`findings.isms_p`). 추가 데이터·DB 변경 없음. 거의 모든 점검이 걸리는 2.10.2 클라우드 보안은 화면 막대에서 뺀다 |
| AI 상담 Agent | 리포트 화면에서 "뭐부터 고쳐?" 같은 질문에 답 | Gemini function calling(`agent.py`). 모델이 도구를 골라 DB의 본인 스캔만 읽고 그 결과로 답한다. 아래 "AI 상담 Agent" |
| GitHub Actions | CI(테스트)와 CD(자동 배포) | public 레포라 무료. 배포는 OIDC로 Role을 맡아 저장된 키가 없고, 관리자 승인 뒤에만 서버에 반영 |

## IAM

| 역할 | 할 수 있는 일 | 할 수 없는 일 |
|---|---|---|
| `aws-gap-check-app-role` (EC2 인스턴스 Role) | 고객 `AwsGapCheckReadOnlyRole` 맡기, 파라미터 2개 읽기, Session Manager 접속, (설정 시) 보내는 주소를 `ses:FromAddress` 조건으로 고정한 `ses:SendEmail`(SES 샌드박스는 받는 주소 ID도 확인해 Resource는 `identity/*`) | 그 밖의 모든 AWS API |
| `aws-gap-check-github-deploy` (GitHub Actions OIDC) | 그 인스턴스에 고정 SSM 문서 `agc-deploy` 실행 + 결과 조회. 신뢰 정책은 이 레포(immutable subject)의 environment `production`만 | 임의 셸 명령, 다른 인스턴스, 그 밖의 모든 AWS API |
| 고객 `AwsGapCheckReadOnlyRole` | 읽기 전용 점검·비용 조회(SecurityAudit, ViewOnlyAccess, ce:GetCostAndUsage·ce:GetCostForecast) | 모든 쓰기 |

고객 Role 신뢰 정책은 ExternalId 일치와 `aws:PrincipalArn`(위 인스턴스 Role) 두 조건을 모두 요구한다. 인스턴스는 IMDSv2만 허용한다(hop limit 2: 컨테이너에서 쓰기 위해).

## 스캔 한 번의 흐름

1. 사용자가 스캔을 시작하면 앱이 연결 상태와 한도(동시 1개, 하루 `DAILY_SCAN_LIMIT`회, 기본 10)를 확인하고 스캔을 `QUEUED`로 저장한 뒤 작업자를 깨운다.
2. 작업자가 QUEUED 스캔을 하나씩 `RUNNING`으로 바꾸고, 입력을 정규식으로 검증한 뒤 셸 없이 Prowler를 실행해 핵심 check(`scanner/core-checks.json`)를 점검한다.
3. 결과(OCSF JSON)를 읽어 FAIL만 check 단위로 묶어 DB에 저장한다(`EXPLAINING`).
4. check마다 Gemini 해설(캐시 우선), 우선순위 요약을 만들고 `DONE`으로 바꾼다. 연속으로 3번 실패하면 남은 호출을 건너뛰고 Prowler 원문으로 대체한다.
5. 화면은 5초마다 상태를 조회해 해설이 붙는 과정을 보여 준다. 서버가 재시작되면 진행 중이던 스캔은 `FAILED`로 표시한다.

## AI 상담 Agent

- 흐름: 질문 → Gemini가 도구 선택 → 앱이 도구 실행(DB 읽기) → 결과를 다시 Gemini에 → 답. 도구 왕복은 최대 4번이고 마지막 걸음은 도구를 막아(`functionCallingConfig` NONE) 글로 답하게 한다. Gemini 3 계열의 `thoughtSignature`를 지키려고 모델 응답을 고치지 않고 대화에 붙인다.
- 도구 5개(모두 읽기 전용): `list_findings`(실패 항목·ISMS-P 항목), `get_check_detail`, `get_remediation_code`(Prowler 공식 수정 예시), `search_isms_p`(ISMS-P 통제 설명 키워드 검색), `get_score_history`(같은 계정의 점수 추이).
- 보안: 도구는 로그인 사용자 `user_id`와 그 스캔으로만 조회한다(IDOR 방지). 고객 AWS를 직접 부르지 않고 자동 수정도 없다. 사용자당 10분에 10번, 진행 중 1개, 질문·대화 길이 제한, 요청 본문 16KB. 대화는 서버에 저장하지 않는다.
- 근거: ISMS-P 번호·이름처럼 사실은 도구 결과로만 답하게 지시하고, 첫 걸음은 도구 호출을 강제한다(`scripts/agent_eval.py`로 채점).

## 대시보드·비용·알림

- **대시보드(홈)**: 연결된 계정마다 카드 하나. 이번 달 사용액·월말 예상·지난달, 최근 30일 일별 비용, 서비스별 비중(도넛), 최신 스캔의 심각도 분포, 자동 점검 설정. 위에는 전체 계정 요약.
- **비용**: `GET /api/connections/{id}/cost`. 고객 Role을 맡아 Cost Explorer를 부르고(`GetCostAndUsage`, `GetCostForecast`) 결과를 6시간 캐시한다. 크레딧·환불을 뺀 사용액이다.
- **자동 점검**: 계정마다 끔/매일/매주. 켜면 작업자가 주기가 지난 연결에 스캔을 만든다(사용자당 동시 1개·하루 한도 그대로).
- **알림**: 스캔이 끝났을 때 직전 완료 스캔에 없던 치명·높음 항목이 있으면 로그인 이메일로 메일(계정 ID, 항목 제목, 개수, 결과 링크만). 같은 결과면 보내지 않는다. `MAIL_FROM`이 없으면 꺼진다.

## 비용

인스턴스는 `c7i-flex.large`(Free Tier 계정이라 `t3.medium`이 거부돼 변경). 켜 둔 동안 시간 단위로 과금되고, 중지하면 EBS 30GB만 월 약 $2.4(실제 청구는 대시보드의 비용 화면이나 Budgets로 확인). 상시 서버 비용이 있으므로 안 쓸 때는 반드시 중지한다. 단, 자동 점검과 알림은 서버가 켜져 있을 때만 돈다. NAT Gateway, 로드 밸런서, Elastic IP는 쓰지 않는다. Gemini는 무료 등급. Cost Explorer 호출은 건당 $0.01(캐시로 하루 수 건 이내).
