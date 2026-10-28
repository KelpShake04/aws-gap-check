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

## 구조 (제안, 제 판단 포함)

```
[브라우저] ──HTTPS──> EC2 (Docker)
                       ├─ caddy 컨테이너: 443 TLS 종료(Let's Encrypt, <공인IP>.sslip.io 도메인)
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
| HTTPS | caddy + sslip.io로 공인 IP에 무료 인증서 | 제 판단, 아래 미정 참고 |

## 그대로 쓰는 코드

`backend/gapcheck/`의 `connections`, `scans`(한도·DELETED 표시 포함), `findings`, `explain`, `llm`, `validate`, `ids`, 그리고 `scanner/run_scan.py`의 입력 검증·Prowler 인자 구성, `frontend/`의 화면(`textContent`만 쓰는 원칙)과 기존 테스트. 바뀌는 것은 저장소 계층(`store.py` → SQLite 구현), 진입점(Lambda 핸들러 → HTTP 서버), 로그인(`auth.js`), 인프라 템플릿이다.

## IAM과 계정 연결

- 인스턴스 Role 이름을 `aws-gap-check-app-role`로 고정한다. 권한: `sts:AssumeRole`(Resource `arn:aws:iam::*:role/AwsGapCheckReadOnlyRole`), `ssm:GetParameter`(Gemini 키 파라미터 하나). 그 밖의 권한은 주지 않는다.
- 고객 템플릿(`infra/customer-role.yaml`)의 `aws:PrincipalArn` 허용 목록을 이 Role 하나로 바꾼다. `ExternalId` 조건은 그대로.
- EC2는 IMDSv2만 허용(`HttpTokens: required`, hop limit 2: 컨테이너에서 쓰기 위해).

## 네트워크와 접속

- Security Group: 80, 443만 연다(80은 인증서 발급과 HTTPS 리다이렉트용). SSH(22)는 열지 않고, 관리 명령은 EC2 콘솔의 **Session Manager 연결** 버튼으로 한다(SSM 에이전트 기본 포함, 인스턴스 Role에 `AmazonSSMManagedInstanceCore` 추가).
- 사용자 생성은 Session Manager 셸에서 `docker exec app python -m gapcheck.cli create-user <이메일>`(임시 비밀번호 출력, 첫 로그인 때 변경).

## 배포 흐름 (조원 기준)

1. Gemini 키를 SSM `/aws-gap-check/gemini-api-key`에 SecureString으로 저장한다(CloudShell 한 줄, 기존 `docs/deploy.md` 1단계 그대로).
2. CloudFormation 콘솔에서 `infra/ec2.yaml`로 스택을 만든다. 파라미터는 Gemini 모델 이름 하나(기본값 제공).
3. 인스턴스 user data가 Docker 설치 → 공개 레포 clone(태그 고정) → `docker compose up -d`를 한다. 5~10분 뒤 스택 출력의 `https://<IP>.sslip.io` 로 접속한다.
4. Session Manager로 사용자를 만든다.
5. 고객 계정(조원 계정 또는 같은 계정)에 `customer-role.yaml`을 배포하고 웹에서 연결을 검증한다.

## 비용

- 상시 비용이 생긴다. 인스턴스를 켜 둔 동안만 과금되므로, 발표 준비·시연 때만 켜고 평소에는 중지한다.
- Prowler가 메모리를 많이 쓰므로 `t3.small`(2GB)을 기본으로 한다. 서울 리전 시간당 약 $0.03, 하루 8시간씩 2주면 약 $4 수준(제 추정, 가격 확인 필요). `t3.micro`(무료 티어, 1GB)는 swap을 붙여 시도해 볼 수 있지만 스캔이 메모리 부족으로 죽을 위험이 있다.
- Elastic IP 요금(시간당 약 $0.005)이 인스턴스를 중지해도 계속 붙는다(월 약 $3.6). 발표가 끝나면 스택을 지워서 함께 없앤다.
- NAT Gateway, 로드 밸런서는 쓰지 않는다.

## 보안에서 달라지는 점 (발표에서 설명)

- 관리형 인증(Cognito)을 앱 자체 로그인으로 바꾸므로 비밀번호 해시, 세션, 시도 제한, CSRF(SameSite=Strict + 상태 변경 요청에 커스텀 헤더 요구)를 직접 책임진다. 테스트로 보장한다.
- 데이터가 EC2 디스크 한 곳에 모인다. EBS 암호화를 켠다. 인스턴스를 지우면 데이터도 사라진다(시연용이라 허용).
- 인스턴스 Role 자격 증명은 IMDSv2로만 얻게 해서 SSRF로 인한 탈취 위험을 줄인다.

## 제 판단 (리뷰어 점검에서 나온 항목)

- VPC: 템플릿이 전용 VPC(퍼블릭 서브넷 1개, 인터넷 게이트웨이)를 직접 만든다. NAT는 없다. 조원 계정에 기본 VPC가 없거나 삭제돼 있어도 스택이 실패하지 않게 하기 위해서다. 파라미터는 늘리지 않는다.
- 이미지: EC2 안에서 빌드한다. 기반 이미지는 `public.ecr.aws/prowler-cloud/prowler:<고정 버전>`(Docker Hub 요청 한도와 무관)이고, 앱 코드는 그 위에 복사만 해서 빌드가 가볍다. 루트 EBS는 30GB gp3(암호화). user data는 git 태그(또는 커밋 SHA)를 파라미터 기본값으로 고정해 clone한다. 레포가 공개라 나중에 GHCR 공개 이미지로 바꾸기 쉽다.
- 재시작: Elastic IP를 붙여 중지·시작 후에도 `<IP>.sslip.io` 주소와 인증서가 유지되게 한다. 중지 중에도 IPv4 요금(시간당 약 $0.005, 월 약 $3.6)이 붙는다. Docker는 systemd로 부팅 시 켜지고, 컨테이너는 `restart: unless-stopped`로 자동 기동한다. 인증서와 SQLite는 볼륨에 둬서 재시작 후에도 남는다.

## 빌더에게 남기는 결정

- HTTP 서버의 라우팅 구조, SQLite 스키마 세부, 작업자 스레드 구현.
- caddy 대신 앱이 직접 TLS를 처리할지(의존성·인증서 갱신 부담 비교).
- 기존 서버리스 템플릿(`infra/service.yaml`)과 Lambda 핸들러를 지울지, `legacy/`로 옮겨 남길지.

## 미정 (사용자 확인 필요)

- 배포 담당과 배포 계정(역할 분담 후 결정).
- sslip.io 같은 외부 무료 도메인 서비스를 써도 되는지. 안 되면 자체 서명 인증서(브라우저 경고)나 CloudFront(서비스 하나 추가) 중 골라야 한다.
- 인스턴스 크기(`t3.small` 비용 감수 vs `t3.micro` 메모리 위험).
