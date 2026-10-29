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
                            │    ├─ Prowler 5.46.0 (같은 이미지, 셸 없이 인자 목록으로 실행)
                            │    │    └─ sts:AssumeRole + ExternalId ──> [고객 계정] AwsGapCheckReadOnlyRole
                            │    │                                        (SecurityAudit + ViewOnlyAccess)
                            │    ├─ SSM SecureString: Gemini 키 (인스턴스 Role로 읽음)
                            │    └─ Gemini API: 한국어 해설, 우선순위 (실패하면 Prowler 원문)
                            └─ mysql: 앱 전용 계정(SELECT/INSERT/UPDATE/DELETE만), 볼륨에 영속
```

AWS 쪽에서 필요한 것은 EC2 한 대, 인스턴스 Role, Security Group(80, 443), SSM 파라미터 2개(Gemini 키, DuckDNS 토큰)뿐이다. `infra/ec2.yaml` 하나로 만든다.

## 구성 요소별 역할

| 구성 요소 | 역할 | 고른 이유 |
|---|---|---|
| EC2 1대 | 모든 컨테이너 실행 | 과제 조건(EC2 1개), 조원이 배포·설명하기 쉬움 |
| Docker Compose | mysql, app, caddy를 한 번에 기동 | 서비스가 늘어도 명령은 `docker compose up -d` 하나, `restart: unless-stopped`로 재부팅 후 자동 기동 |
| caddy | HTTPS | 인증서 발급·갱신 자동, 앱은 HTTP만 처리 |
| 앱(Python 표준 라이브러리) | 로그인, API, 정적 파일, 스캔 작업자 | 의존성은 PyMySQL 하나(해시 고정) |
| MySQL 8.4.9 | 데이터 저장 | 수업 RDS와 같은 버전, 평가 항목(DBMS·ERD)에 대응. ERD는 `docs/erd.md` |
| Prowler 5.46.0 | 점검 실행 | 공식 이미지를 기반으로 앱 코드만 얹음 |
| SSM Parameter Store | Gemini 키, DuckDNS 토큰 | SecureString 무료, 키를 코드·레포·user data에 두지 않음 |
| Gemini API | 해설, 우선순위 | Bedrock 모델 접근 불가로 대체. 호출부(`llm.py`) 하나만 바꾸면 교체 가능 |
| DuckDNS | 무료 도메인 | Elastic IP 없이 부팅마다 현재 IP를 등록 |

## IAM

| 역할 | 할 수 있는 일 | 할 수 없는 일 |
|---|---|---|
| `aws-gap-check-app-role` (EC2 인스턴스 Role) | 고객 `AwsGapCheckReadOnlyRole` 맡기, 파라미터 2개 읽기, Session Manager 접속 | 그 밖의 모든 AWS API |
| 고객 `AwsGapCheckReadOnlyRole` | 읽기 전용 점검(SecurityAudit, ViewOnlyAccess) | 모든 쓰기 |

고객 Role 신뢰 정책은 ExternalId 일치와 `aws:PrincipalArn`(위 인스턴스 Role) 두 조건을 모두 요구한다. 인스턴스는 IMDSv2만 허용한다(hop limit 2: 컨테이너에서 쓰기 위해).

## 스캔 한 번의 흐름

1. 사용자가 스캔을 시작하면 앱이 연결 상태와 한도(동시 1개, 하루 `DAILY_SCAN_LIMIT`회, 기본 10)를 확인하고 스캔을 `QUEUED`로 저장한 뒤 작업자를 깨운다.
2. 작업자가 QUEUED 스캔을 하나씩 `RUNNING`으로 바꾸고, 입력을 정규식으로 검증한 뒤 셸 없이 Prowler를 실행해 핵심 check 33개를 점검한다.
3. 결과(OCSF JSON)를 읽어 FAIL만 check 단위로 묶어 DB에 저장한다(`EXPLAINING`).
4. check마다 Gemini 해설(캐시 우선), 우선순위 요약을 만들고 `DONE`으로 바꾼다. 연속으로 3번 실패하면 남은 호출을 건너뛰고 Prowler 원문으로 대체한다.
5. 화면은 5초마다 상태를 조회해 해설이 붙는 과정을 보여 준다. 서버가 재시작되면 진행 중이던 스캔은 `FAILED`로 표시한다.

## 비용

`t3.medium` 켜 둔 동안 시간당 약 $0.05(추정), 중지하면 EBS 30GB만 월 약 $2.4. 상시 서버 비용이 있으므로 안 쓸 때는 반드시 중지한다. NAT Gateway, 로드 밸런서, Elastic IP는 쓰지 않는다. Gemini는 무료 등급.
