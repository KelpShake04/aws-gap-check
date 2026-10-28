# 컨테이너 단일 배포로 재구성 (설계)

작성일 2026-10-28. 상태: 초안, 사용자 승인 전. 원래 설계 `2026-10-28-aws-gap-check-design.md`의 목표·보안 원칙은 그대로이고, **배포 구조만** 바꾼다.

## 왜 바꾸나

지금 구현(PR #3)은 Cognito, CloudFront, S3 2개, HTTP API, Lambda 2개, DynamoDB, CodeBuild, EventBridge, SSM까지 서비스가 많다. 조원들이 배포·운영·설명을 어려워해서, 사용자가 "컨테이너 하나로 묶자"고 결정했다(2026-10-28). 역할을 나누면 배포를 조원이 맡을 수도 있으므로, **AWS 초보 조원이 문서만 보고 30분 안에 띄울 수 있는 것**이 이번 재구성의 성공 기준이다.

## 목표

- 이미지 하나에 웹 화면, API, 스캔 실행(Prowler), 결과 처리, Gemini 해설을 모두 넣는다.
- AWS에서 필요한 것은 **EC2 한 대 + IAM Role(인스턴스 프로파일) + Security Group**, 그리고 Gemini 키를 둘 SSM 파라미터 하나뿐이다.
- 배포는 CloudFormation 템플릿 하나를 콘솔에서 "스택 생성"으로 올리면 끝나게 한다(조원이 CLI를 몰라도 되게).
- 같은 이미지를 로컬 `docker run`으로도 띄울 수 있게 한다(배포가 막힐 때 발표 대체 경로).
- 핵심 보안 시연은 그대로 유지한다: 고객 계정의 읽기 전용 Role, 서버가 발급한 `ExternalId`로 `AssumeRole`, confused deputy 방지, 사용자별 데이터 격리, 프롬프트 인젝션 방어.

## 비목표

- 고가용성, 자동 확장, 무중단 배포.
- 실제 외부 사용자 대상 운영.
- 사용자 셀프 가입(관리자가 명령으로 만든다).

## 안티 목표

- 사용자 액세스 키나 Gemini 키를 이미지, 레포, 사용자 데이터(user data)에 넣는 것.
- 로그인 비밀번호가 평문 HTTP로 오가는 것.
- 조원이 따라 하기에 단계가 다시 많아지는 것(서비스를 하나씩 더 붙이고 싶어지면 이 문서로 돌아와 판단한다).

## 사용자가 정한 것

- 컨테이너 하나로 묶는다. 이유는 조원들이 지금 구조를 어려워해서다.
- AI는 Gemini API, 키는 사용자(또는 배포 담당 조원)가 직접 넣는다.
- 레포는 공개(조원 열람용).
- 구현은 사용자(1명)가 전담한다. 조원은 장표, 시연, 문서, 테스트 계정 등 구현 외 산출물을 맡는다.
- 팀은 2조 5명, 발표는 2026-12-01(14주차), 구현 시작은 11주차(11/9)로 하고 그 전까지 구현은 보류한다.

## 구조 (제안, 제 판단 포함)

```
[브라우저] ──HTTPS──> EC2 (Docker)
                       ├─ caddy 컨테이너: 443 TLS 종료(Let's Encrypt HTTP-01, <이름>.duckdns.org 도메인)
                       └─ app 컨테이너 (Prowler 공식 이미지 기반)
                            ├─ HTTP 서버: 정적 화면 + /api/*
                            ├─ SQLite (/data 볼륨): 사용자, 세션, 연결, 스캔, 결과, 해설 캐시
                            ├─ 스캔 작업자 스레드: 큐에서 하나씩 꺼내 Prowler 실행(동시 1개)
                            │     └─ 인스턴스 Role로 sts:AssumeRole + ExternalId
                            │           ──> [고객 계정] AwsGapCheckReadOnlyRole
                            └─ 결과 파싱 → Gemini 해설(기존 explain.py) → SQLite 저장
```

| 지금 | 바뀐 뒤 | 판단 |
|---|---|---|
| S3 + CloudFront (웹) | app 컨테이너가 정적 파일 제공 | 제 판단 |
| Cognito (PKCE) | 앱 자체 로그인: 이메일+비밀번호, `hashlib.scrypt` 해시, HttpOnly·Secure·SameSite=Strict 세션 쿠키, 로그인 시도 제한 | 제 판단 |
| API Gateway + Lambda 2개 | 표준 라이브러리 `http.server`(ThreadingHTTPServer) 하나 | 제 판단, 새 의존성 없음 |
| DynamoDB | SQLite(`/data/app.db`), 모든 쿼리에 사용자 ID 조건 | 제 판단 |
| CodeBuild + EventBridge | 컨테이너 안 작업자 스레드 + `subprocess`(셸 없이 인자 목록) | 제 판단 |
| 결과 S3 버킷 | `/data/raw/{user}/{scan}/`, 30일 지나면 시작 시·하루 1회 정리 | 제 판단 |
| SSM SecureString (Gemini 키) | 그대로 유지. 인스턴스 Role로 읽는다 | 제 판단 |
| HTTPS·도메인 | caddy + DuckDNS 무료 서브도메인(`<이름>.duckdns.org`), Let's Encrypt 자동 발급·갱신 | 사용자 결정(2026-10-29) |

## 그대로 쓰는 코드

`backend/gapcheck/`의 `connections`, `scans`(한도·DELETED 표시 포함), `findings`, `explain`, `llm`, `validate`, `ids`, 그리고 `scanner/run_scan.py`의 입력 검증·Prowler 인자 구성, `frontend/`의 화면(`textContent`만 쓰는 원칙)과 기존 테스트. 바뀌는 것은 저장소 계층(`store.py` → SQLite 구현), 진입점(Lambda 핸들러 → HTTP 서버), 로그인(`auth.js`), 인프라 템플릿이다.

## IAM과 계정 연결

- 인스턴스 Role 이름을 `aws-gap-check-app-role`로 고정한다. 권한: `sts:AssumeRole`(Resource `arn:aws:iam::*:role/AwsGapCheckReadOnlyRole`), `ssm:GetParameter`(Gemini 키와 DuckDNS 토큰 파라미터 두 개). 그 밖의 권한은 주지 않는다.
- 고객 템플릿(`infra/customer-role.yaml`)의 `aws:PrincipalArn` 허용 목록을 이 Role 하나로 바꾼다. `ExternalId` 조건은 그대로.
- EC2는 IMDSv2만 허용(`HttpTokens: required`, hop limit 2: 컨테이너에서 쓰기 위해).

## 네트워크와 접속

- Security Group: 80, 443만 연다(80은 인증서 발급과 HTTPS 리다이렉트용). SSH(22)는 열지 않고, 관리 명령은 EC2 콘솔의 **Session Manager 연결** 버튼으로 한다(SSM 에이전트 기본 포함, 인스턴스 Role에 `AmazonSSMManagedInstanceCore` 추가).
- 사용자 생성은 Session Manager 셸에서 `docker exec app python -m gapcheck.cli create-user <이메일>`(임시 비밀번호 출력, 첫 로그인 때 변경).

## 배포 흐름 (조원 기준)

1. Gemini 키를 SSM `/aws-gap-check/gemini-api-key`에 SecureString으로 저장한다(CloudShell 한 줄, 기존 `docs/deploy.md` 1단계 그대로).
2. CloudFormation 콘솔에서 `infra/ec2.yaml`로 스택을 만든다. 파라미터는 Gemini 모델 이름 하나(기본값 제공).
3. 인스턴스 user data가 Docker 설치 → 공개 레포 clone(태그 고정) → `docker compose up -d`를 한다. user data는 DuckDNS에 현재 공인 IP를 등록한다. 5~10분 뒤 `https://<이름>.duckdns.org` 로 접속한다.
4. Session Manager로 사용자를 만든다.
5. 고객 계정(조원 계정 또는 같은 계정)에 `customer-role.yaml`을 배포하고 웹에서 연결을 검증한다.

## 비용

- 상시 비용이 생긴다. 인스턴스를 켜 둔 동안만 과금되므로, 발표 준비·시연 때만 켜고 평소에는 중지한다.
- Prowler가 메모리를 많이 쓰므로 `t3.small`(2GB)을 기본으로 한다. 서울 리전 시간당 약 $0.03, 하루 8시간씩 2주면 약 $4 수준(제 추정, 가격 확인 필요). `t3.micro`(무료 티어, 1GB)는 swap을 붙여 시도해 볼 수 있지만 스캔이 메모리 부족으로 죽을 위험이 있다.
- Elastic IP를 쓰지 않는다. 중지된 인스턴스에는 IPv4 요금이 없고, 켜 둔 동안만 공인 IPv4 요금(시간당 약 $0.005)이 붙는다(제 추정, 가격 확인 필요). 재시작하면 IP가 바뀌지만 부팅 때 DuckDNS를 갱신한다.
- NAT Gateway, 로드 밸런서는 쓰지 않는다.

## 보안에서 달라지는 점 (발표에서 설명)

- 관리형 인증(Cognito)을 앱 자체 로그인으로 바꾸므로 비밀번호 해시, 세션, 시도 제한, CSRF(SameSite=Strict + 상태 변경 요청에 커스텀 헤더 요구)를 직접 책임진다. 테스트로 보장한다.
- 데이터가 EC2 디스크 한 곳에 모인다. EBS 암호화를 켠다. 인스턴스를 지우면 데이터도 사라진다(시연용이라 허용).
- 인스턴스 Role 자격 증명은 IMDSv2로만 얻게 해서 SSRF로 인한 탈취 위험을 줄인다.

## 제 판단 (리뷰어 점검에서 나온 항목)

- VPC: 템플릿이 전용 VPC(퍼블릭 서브넷 1개, 인터넷 게이트웨이)를 직접 만든다. NAT는 없다. 조원 계정에 기본 VPC가 없거나 삭제돼 있어도 스택이 실패하지 않게 하기 위해서다. 파라미터는 늘리지 않는다.
- 이미지: EC2 안에서 빌드한다. 기반 이미지는 `public.ecr.aws/prowler-cloud/prowler:<고정 버전>`(Docker Hub 요청 한도와 무관)이고, 앱 코드는 그 위에 복사만 해서 빌드가 가볍다. 루트 EBS는 30GB gp3(암호화). user data는 git 태그(또는 커밋 SHA)를 파라미터 기본값으로 고정해 clone한다. 레포가 공개라 나중에 GHCR 공개 이미지로 바꾸기 쉽다.
- 재시작: Elastic IP 대신 부팅 때마다 systemd 서비스가 DuckDNS에 새 공인 IP를 등록한다(DNS 반영까지 1분 안팎). 주소 `<이름>.duckdns.org`와 인증서(caddy 볼륨)는 그대로 유지된다. Docker는 systemd로 부팅 시 켜지고, 컨테이너는 `restart: unless-stopped`로 자동 기동한다. 인증서와 SQLite는 볼륨에 둬서 재시작 후에도 남는다.

## 교수님 과제 공지 반영 (2026-10-29)

공지 요약: 자유 주제 앱 개발 + AWS 적용, "EC2는 1개만, Route 53은 생략 가능", 발표 20분과 시연(브라우저 URL로 결과 확인), 소스(zip)와 PPT 제출. 일정은 9주차 S3+CloudFront, 10주차 자원 삭제 + 게시판 웹 서비스 배포, 11~13주차 팀 과제 실습, 14주차 발표, 15주차 기말이다.

### 평가 항목별 대응 (제 판단)

| 평가 항목 (배점) | 대응 | 산출물 | 담당(제안) |
|---|---|---|---|
| 프로젝트 개요 (5) | 선정 배경: 초보자가 보안 점검 결과를 읽기 어렵다. 목표: 점검 + 한국어 해설. 서버리스에서 컨테이너로 단순화한 과정과 이유도 "교훈"으로 넣는다 | 장표 | 조원 |
| 전체 시스템 구성도 (10) | EC2 1대 + Docker(app, caddy) + 고객 계정 Role 연결 흐름도, 서비스 흐름도 | 구성도 2장 | 조원(초안은 이 문서) |
| S/W·DBMS·AI 활용 (20) | Python 표준 라이브러리 서버, DBMS(아래 결정), Gemini API(AI API 활용), Prowler, Docker·CloudFormation, 배포 명령 | 장표 + `docs/deploy.md` | 사용자 + 조원 |
| 개발 소스·완성도 (20) | 동작하는 URL, 테스트(현재 99개), 제출용 zip | 레포, zip | 사용자 |
| 발표 장표 (25) | 20분 구성(아래), 시연 영상 포함 | PPT, 영상 | 조원 |
| 팀 역할 (10) | 역할표를 문서와 GitHub 이슈·PR 담당자로 남긴다 | `docs/ROLES.md`, 이슈 | 사용자 정리 |
| 가점 (10) | GitHub 이력, GitHub Actions CI(공개 레포라 무료), 선택으로 CD | 워크플로 파일 | 사용자 |

DBMS와 ERD가 평가 항목에 명시돼 있다. **결정(사용자, 2026-10-29): 10주차 수업에서 쓰는 DBMS가 있으면 그것을 따르고(MySQL/MariaDB 가능성), 없으면 PostgreSQL 컨테이너를 쓴다.** PostgreSQL을 기본으로 한 이유는 평가표의 DBMS·ERD 항목, EC2 1대 제약(`docker compose`에 서비스 하나 추가, RDS는 상시 과금), 앱 전용 DB 계정과 외래키로 사용자 격리를 설명할 수 있다는 점이다. 저장소 접근은 `store.py`의 한 인터페이스 뒤에 두어 구현이 DBMS 결정을 기다리지 않게 하고, 시간이 부족하면 SQLite로 시작해 나중에 바꾼다. PostgreSQL 드라이버(`psycopg` 등)는 표준 라이브러리에 없어 의존성 하나가 늘어나며, 이 경우만 정당한 예외로 둔다. 어느 쪽이든 ERD는 그린다.

### 일정 (구현은 11주차 시작)

| 주차 | 기간(추정) | 할 일 |
|---|---|---|
| 9~10 | ~11/6 | 설계 확정, 조원 역할 공유, 10주차 수업(게시판 배포) 확인 후 DBMS 결정, 장표 뼈대 |
| 11 | 11/9~ | MVP 구현: 로그인, 계정 연결, 스캔, 해설 (로컬 `docker compose`까지) |
| 12 | 11/16~ | EC2 배포(CloudFormation), HTTPS, DB 확정, CI 추가, 조원 계정 연결 시연 |
| 13 | 11/23~ | 시연 리허설, 시연 영상 촬영, 장표 완성, 제출 소스 정리, 최종 점검 |
| 14 | 11/30~ | 발표(12/1) |
| 발표 후 | | 스택·SSM 파라미터(Gemini 키, DuckDNS 토큰)·Gemini 키·DuckDNS 서브도메인 삭제(`docs/demo-runbook.md`) |

제출 마감일은 공지에 비어 있어(~O/OO) 확인이 필요하다. 마감이 발표 전이면 13주차 계획을 앞당긴다.

### 발표 20분 구성 (제안)

1. 문제와 목표 (2분) 2. 구성도와 흐름도 (4분) 3. 보안 설계: ExternalId, 최소 권한, 프롬프트 인젝션 방어 (4분) 4. 사용 기술: DBMS, ERD, AI 활용, 컨테이너·배포 명령 (4분) 5. 시연 (4분, 라이브 + 녹화 영상 대체) 6. 역할·교훈·질의 (2분)

## 설계 개선 (제 판단)

1. **범위를 MVP와 확장으로 나눈다.** 구현자가 한 명이라 MVP를 먼저 끝낸다.
   - MVP: 이메일 로그인, 계정 연결 검증(ExternalId), 스캔 1회(핵심 점검 항목), 결과 목록, Gemini 해설(실패 시 Prowler 원문), 삭제, 일일 한도.
   - 확장(시간이 남으면): 우선순위 요약, GitHub Actions 배포(CD), PostgreSQL 전환, 해설 캐시, 사용자 생성 CLI 개선.
2. **시연 실패에 대비한 3단계 대체 경로.** (a) EC2의 HTTPS 주소 (b) 로컬 `docker compose up` (c) 사전 녹화 영상. 사전 스캔 결과(`tests/fixtures/ocsf-sample.json`, `scripts/sanitize_ocsf.py`)로 Prowler 없이도 해설 화면을 보여 준다.
3. **저장소 접근을 한 인터페이스로 고정**해 DBMS 결정을 늦춰도 구현이 막히지 않게 한다. 기존 `Store`의 메서드 이름을 유지하고 SQLite 구현을 먼저 만든다.
4. **CI를 먼저 붙인다(가점).** 공개 레포는 GitHub Actions가 무료다. PR마다 `python -m unittest`, `cfn-lint infra/ec2.yaml`, `docker build`를 돌린다. CD는 확장 항목으로, 하려면 GitHub OIDC로 SSM `SendCommand`를 호출하고 장기 키는 두지 않는다.
5. **컨테이너 보안 기본값.** app은 비루트 사용자로 실행, `docker.sock`은 마운트하지 않음, `/data`만 쓰기 가능한 볼륨, 포트는 caddy만 공개, 이미지·Prowler 버전 고정. IMDS hop limit 2라서 컨테이너가 인스턴스 Role을 쓸 수 있다는 점을 위험으로 기록하고, 앱은 외부 URL을 서버에서 요청하는 기능을 두지 않아 SSRF 표면을 없앤다.
6. **서버리스 구현은 남겨 둔다.** main의 서버리스 코드와 `infra/service.yaml`은 지우지 않고 `legacy/`로 옮길지 빌더가 정한다. "서버리스에서 컨테이너로 바꾼 이유"를 발표 교훈으로 쓴다.
7. **리스크와 대응**

| 리스크 | 대응 |
|---|---|
| Prowler가 `t3.small`에서 메모리 부족 | 핵심 점검 항목만 실행(기존 `core-checks.json`), 안 되면 `t3.medium`으로 올리고 시연 때만 켠다 |
| DuckDNS·Let's Encrypt 장애나 발급 한도 | 자체 서명 인증서 대체, 또는 시연은 `http`와 로컬 `docker compose`. 발표 전 인증서를 미리 발급해 볼륨에 둔다 |
| DuckDNS 토큰 유출 | 레포·이미지·user data 평문에 넣지 않고 SSM SecureString에 둔다. 갱신 호출은 로그에 URL이 남지 않게 한다. 유출 의심 시 DuckDNS에서 토큰을 재발급한다 |
| Gemini 무료 한도 초과 | 호출 간격 제한, 해설 캐시, Prowler 원문 폴백 |
| 조원 계정에서 Role 생성이 막힘 | 서비스 계정 자기 자신을 고객 계정으로 연결하는 대체 경로(발표에서 밝힘) |
| 혼자 구현해 일정 지연 | MVP 우선, 확장은 11~12주차 진행 상황 보고 결정, 장표·영상은 조원에게 위임 |

- 인증서 발급은 HTTP-01 방식으로 한다. 80포트를 이미 열어 두므로 기본 caddy 이미지로 충분하고, DuckDNS DNS 플러그인을 넣은 커스텀 이미지는 필요 없다. 발급이 막힐 때만 DNS-01(플러그인 이미지)로 바꾼다.

## 빌더에게 남기는 결정

- HTTP 서버의 라우팅 구조, SQLite 스키마 세부, 작업자 스레드 구현.
- caddy 대신 앱이 직접 TLS를 처리할지(의존성·인증서 갱신 부담 비교).
- 기존 서버리스 템플릿(`infra/service.yaml`)과 Lambda 핸들러를 지울지, `legacy/`로 옮겨 남길지.

## 미정 (사용자 확인 필요)

- 제출 마감일(공지에 비어 있음).
- DBMS: 결정됨(수업 DBMS 우선, 없으면 PostgreSQL). 10주차 수업에서 쓰는 DBMS만 확인하면 된다.
- DuckDNS 계정 가입(소셜 로그인, 사용자 직접)과 서브도메인 이름 정하기. 토큰은 SSM에 직접 저장한다.
- 인스턴스 크기: `t3.small`(유료, 안정적)과 `t3.micro`(무료 티어, 메모리 위험).
- 배포 담당과 배포 계정(구현은 사용자 전담, 배포는 역할 분담 후 결정).
