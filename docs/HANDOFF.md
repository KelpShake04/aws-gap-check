# 인수인계 (2026-11-12 기준)

## 한 줄 요약
AWS 계정을 연결하면 Prowler로 빈틈을 점검하고, Gemini가 한국어로 위험·영향·조치를 해설하고, 계정 비용을 보여 주며, 주기적으로 점검해 새 위험 항목을 이메일로 알리는 웹 서비스. 팀 5명(2조), 개발은 사용자 1명이 전담. 발표 12/1.

## 결정된 것 (사용자 확정)
- 형태: EC2 한 대에서 Docker Compose로 웹사이트 제공(앱 자체 로그인, HTTPS는 caddy + DuckDNS). 2026-10-28 사용자 결정으로 서버리스에서 변경.
- 계정 연결: 사용자 계정에 읽기 전용 Role(CloudFormation 템플릿 제공) → `sts:AssumeRole` + 사용자별 `ExternalId`. 액세스 키는 받지 않는다.
- AI: Gemini API를 앱에서 호출. Bedrock의 OpenAI GPT-6 Luna는 이 계정에서 `AccessDeniedException`(not available for this account)으로 확인됨. Claude는 Anthropic 용도 정보 제출이 필요해 보류. 호출부는 함수 하나로 분리해 나중에 교체 가능하게 한다.
- 테스트(고객) 계정: 조원 2명의 개인 계정. 단, 조원 연락이 안 돼 동의와 계정 종류는 미확인. Role 생성이 막히면 서비스 계정 안의 별도 Role로 시연을 대체한다.
- 점검 범위: 핵심 항목(S3 공개, Security Group, IAM, 암호화) 위주, 사전 스캔 결과도 준비.

## 이미 해 둔 AWS 작업
- AWS Budgets에 월 $10 예산 생성(85%, 100%, 예측 100% 알림).
- 수업 실습용 RDS(`dev-robby-rds`, ap-northeast-2)는 stopped. 자동 재시작되면 다시 중지해야 한다(삭제는 사용자 결정).
- 로컬 CLI 프로필 `cli-rds`는 RDS 실습용 권한뿐이라 Bedrock, NAT 조회, Budgets 권한이 없다. 구현용 배포 권한은 사용자가 별도로 준비해야 한다.

## 아직 모르는 것
- 평가 기준(IaC 필수 여부, 시연 시간), 비용 상한, 조원 참여 여부.
- 조원 계정 연결 동의와 계정 종류.

## 2026-11-11 변경 (요약)
- **CD 첫 자동 배포 성공**: 레포가 GitHub OIDC immutable subject를 써서 trust `sub`가 `repo:KelpShake04@128560649/aws-gap-check@1436024882:environment:production` 형식이다(PR #41, 스택 `aws-gap-check-github-deploy` 갱신 시 `GitHubRepo`를 이 값으로). SSM 문서 이름은 `aws` 접두어가 예약어라 `agc-deploy`. 원격 브랜치는 main만 남기고 정리.
- 운영 AI 상담 실호출 확인(도구 루프·`thoughtSignature` 정상). ISMS-P 질문에 도구 없이 답해 항목 이름을 지어내는 문제 → PR #42.
- **main 병합 완료(2026-11-11, 테스트 206 통과)**: #42 첫 걸음 도구 호출 강제, #43 FAILED 스캔의 pending 항목 무한 새로고침 수정, #44 core check 33→42·ISMS-P 대응 14→24, #45 `infra/backup.yaml`(DLM 일일 스냅샷 7개, 별도 스택) + 배포 전 `mysqldump`(`/opt/agc-backup`) + `uptime.yml`, #46 `SCAN_WORKERS`(기본 1) + Gemini `Pacer` 공유 + `queuePosition`, #47 Gemini 호출 메타데이터 로그 + `scripts/agent_eval.py`, #48 구성도·Dependabot.
- **운영 반영 대기**: Actions `deploy` run 42980011228이 production 승인 대기(2026-11-12 기준). 승인 전 사이트는 #41 시점 코드.
- Dependabot PR #49~#53(mysql 8.4.13, python 3.15-slim, caddy 2.11, setup-python 7, checkout 7)은 검토 대기. python 메이저 업은 로컬 테스트 후 병합.
- 할 일(관리자):
  0. 위 `deploy` 승인 후 사이트·AI 상담 확인(탭 새로고침).
  1. `aws cloudformation deploy --region ap-northeast-2 --stack-name aws-gap-check-backup --template-file infra/backup.yaml --capabilities CAPABILITY_IAM`, 그리고 `aws-gap-check-github-deploy` 스택 갱신(배포 전 덤프 반영).
  2. 운영 스캔 1건: 새 check 9개가 AccessDenied 없이 도는지, 스캔 시간, 앱 컨테이너 `memory.peak`. 여유 있으면 `.env`에 `SCAN_WORKERS=2`.
  3. `scripts/agent_eval.py`를 앱 컨테이너에서 실행(실행법은 파일 머리말), 결과를 시연 장표에.
  4. 레포 Settings에서 secret scanning·push protection 켜기.
  5. 시연용 사전 스캔 2회는 #44 배포 **후**(점검이 늘어 점수가 내려가므로 추이가 끊기지 않게).
- 확인한 것: 인스턴스 `AutoRecovery`는 `default`(복구 알람 불필요). 루트 EBS `DeleteOnTermination: true`라 #45 적용 전까지 데이터 백업 없음. git 히스토리의 AKIA/ASIA 패턴 3건은 sanitize 테스트 더미.

## 2026-11-10 변경 (요약)
- 팀원 4명 앱 계정 사용 시작. 조원 이슈(#31·#33·#34) → PR #32·#35(점수 추이, 심각도 필터, 취약 파트) 병합·배포(`bf745cf`).
- PR #30(SES `identity/*` + `ses:FromAddress` 조건, 보조 모델 유지) 병합. **운영 스택 `aws-gap-check-ec2` 반영 완료**: `LatestUbuntuAmiId`(SSM 타입)를 그대로 두면 새 AMI로 해석돼 Instance가 교체되므로, 현재 AMI에 고정된 Canonical 경로 `/aws/service/canonical/ubuntu/server/24.04/stable/20261023/amd64/hvm/ebs-gp3/ami-id`를 파라미터로 넣어 change set에서 `AppRole`만 바뀌는 것을 확인하고 실행했다. 이후 스택 업데이트도 이 값을 유지할 것. 팀원에게 메일을 보내려면 SES 샌드박스라 받는 주소도 SES에서 확인해야 한다.
- **main 병합(2026-11-10)**: PR #37 CD(GitHub OIDC → 고정 SSM 문서 `agc-deploy`), #36 ISMS-P 통제 항목 관점, #40 AI 보안 상담 Agent(#38이 base 브랜치 삭제로 자동으로 닫혀 다시 올림), #39 시연 런북 갱신. 운영 반영은 Actions `deploy` 승인 후. 쌓인 PR은 base 브랜치를 지우면 retarget되지 않고 닫히므로, 먼저 base를 main으로 바꾸고 병합한다.
- CD 준비 완료: 스택 `aws-gap-check-github-deploy` 생성, repo 변수 `AWS_DEPLOY_ROLE_ARN`·`DEPLOY_INSTANCE_ID` 등록, environment `production`에 required reviewer(관리자) 설정 — write 권한 팀원의 main push가 승인 없이 서버(root)에 배포되지 않게. SSM 문서 이름은 `aws`로 시작하면 예약어로 거부된다.

## 현재 상태 (2026-11-04, 배포 완료)
- 배포 구조는 EC2 한 대 + Docker Compose(app, mysql, caddy). 설계는 `docs/superpowers/specs/2026-10-28-container-redesign.md`, 실행·구조·한계는 `docs/container.md`, ERD는 `docs/erd.md`, 구성·보안은 `docs/architecture.md`·`docs/security-design.md`.
- **배포됨**: 스택 `aws-gap-check-ec2`(ap-northeast-2b, `c7i-flex.large`: Free Tier 계정이라 `t3.medium`이 거부됨), `https://agc-kelp04.duckdns.org`. SSM 파라미터 이름은 `/gapcheck/...`(`aws`·`ssm` 접두사는 예약어). 2026-11-04에 PR #27까지 main에 병합하고 EC2에 반영했다(`git pull` + `docker compose up -d --build`). 배포 전에 상태가 `DONE`/`FAILED`가 아닌 스캔이 0개인지 확인한다(`QUEUED`·`RUNNING`뿐 아니라 `PROCESSING`·`EXPLAINING`도 진행 중이라 재시작하면 끊긴다).
- **2026-11-04 반영(PR #26, #27)**
  - Prowler 5.46.0 → 5.47.0(보안그룹 CIDR을 `0.0.0.0/1` 두 개처럼 쪼개 열면 못 잡던 문제 수정). core check 33개 모두 5.47.0에 있다.
  - 리포트의 finding 카드마다 "공식 수정 예시 (Prowler 원문)": 콘솔 절차·AWS CLI·CloudFormation·Terraform. OCSF 결과에는 수정 코드가 없어서 이미지 안 Prowler의 `<check>.metadata.json`(`Remediation.Code`)을 check ID로 읽는다(`findings.remediation_code`). DB 변경 없음, 자동 적용 안 함. 운영 컨테이너에서 core 33개 모두 코드가 나오는 것 확인. Gemini가 자리표시자를 내 리소스 이름으로 채우는 기능은 아직 없다.
- **2026-11-03 추가 기능(PR #20, 설계 `docs/superpowers/specs/2026-11-03-billing-dashboard.md`, `2026-11-03-scheduled-alerts.md`)**
  - 대시보드 홈(`#/`): 계정별 카드(이번 달 비용·월말 예상·지난달, 최근 30일 일별 차트, 서비스별 도넛, 최신 스캔 심각도, 자동 점검 설정) + 전체 요약. UI는 사이드바 레이아웃, 다크 모드 지원.
  - 비용 조회(Cost Explorer): 고객 Role의 `ce:GetCostAndUsage`/`ce:GetCostForecast`. 호출당 $0.01이라 6시간 캐시, 새로고침 5분 제한. 크레딧·환불 제외 금액.
  - 자동 점검(끔/매일/매주) + 이메일 알림: 직전 스캔에 없던 치명·높음 항목이 생기면 로그인 이메일로 SES 메일. 테스트 메일 버튼.
  - DB: `connections.schedule` 열 추가. **EC2 DB에는 2026-11-03에 `db/migrations/2026-11-03-schedule.sql` 내용을 SSM으로 적용 완료**(기존 연결 3개 유지). 새로 만드는 DB는 `db/init`에 이미 포함. 이후 스키마 변경은 `db/migrations/`에 SQL을 추가하고 root로 한 번 실행한다.
- **AI 해설**: 주 모델 `gemini-3.1-flash-lite`(`.env`의 `GEMINI_MODEL`, 스택 파라미터 `GeminiModel`은 비어 있음). 5xx·타임아웃이면 10초, 20초 간격으로 3번 시도 후 보조 모델 `gemini-3.5-flash-lite`(`GEMINI_FALLBACK_MODEL`, compose 기본값)를 한 번 시도하고, 그래도 안 되면 Prowler 원문(영어)으로 대체한다. 해설 캐시(`explanations`)는 만료가 없다.
- main에 있는 것: 앱 전체, `infra/ec2.yaml`, CI(unittest 172개 + MySQL 서비스, cfn-lint), 재시도·폴백(PR #16, #17), 이메일 비ASCII 거부(PR #18), 대시보드·비용·알림(PR #20), 리뷰 반영(PR #24: 보조 모델 해설은 보조 모델 이름으로 캐시, 첫 점검 알림 문구, 비용 조회 연결별 잠금, 테스트 메일 제한 잠금), Prowler 5.47.0(PR #26), 공식 수정 예시(PR #27), 서버리스 코드는 `legacy/serverless/`.
- 확인한 것: EC2에서 본인 계정 실제 스캔(14개 항목) + Gemini 해설, 캐시로 재스캔 70초대. 로컬 데모 모드에서 대시보드, 자동 점검 → 스캔 자동 생성 → 알림 메일(로그) 흐름(PR #24 뒤 "첫 점검" 문구까지). 배포 후 사이트 200과 새 API 라우트 확인.
- **자동 점검 켬(2026-11-03)**: 운영에서 본인 계정 연결을 `daily`로 바꿨다. 마지막 스캔이 11-03 05:33 UTC라 첫 자동 스캔은 11-04 05:33 UTC(14:33 KST) 무렵이고, 직전 스캔에 없던 치명·높음 항목이 있을 때만 메일이 간다. **첫 자동 스캔은 2026-11-04 05:33:36 UTC에 생성돼 59초 만에 DONE**(Prowler 5.47.0, 실패 check 6개, 전날 수동 스캔은 12개). 새 치명·높음 항목이 없어 메일은 가지 않았다. 운영 DB에는 확인이 안 된 `PENDING` 연결 2개가 남아 있다(점검 대상 아님, 지우려면 대시보드에서 삭제).
- **비용(2026-11-03 Cost Explorer, 크레딧 제외 사용액)**: 10월 $24.04, 11월 1~2일 $1.64이고 모두 크레딧으로 상쇄돼 실제 청구는 $0. 11월분의 대부분은 ELB $1.04·RDS $0.16(11-03에 지운 수업 실습 리소스)이다. 17개 리전에 남은 ELB·RDS·스냅샷·EIP·NAT·미연결 EBS·VPC 엔드포인트는 없다. 지금 계속 나가는 비용은 이 EC2의 EBS와 공인 IPv4로 하루 약 $0.22(월 약 $6.6, 컴퓨팅은 Free Tier로 0). Budgets의 월말 예측 $26.14는 ELB가 있던 날 기준이라 과대 추정이며 며칠 지나면 내려간다. 자동 점검을 쓰려면 EC2를 켜 두어야 한다.
- **2026-11-03 비용·알림 켬**: 본인 계정 스택 `aws-gap-check-readonly-role`을 최신 템플릿으로 업데이트하고 `GetCostAndUsage` 호출 성공(아직 금액 0). SES(서울, 샌드박스)에 개발자 Gmail 주소를 이메일 ID로 확인, 스택 `aws-gap-check-ec2`에 `MailFrom` 파라미터를 넣어 앱 Role에 `ses:SendEmail` 추가, 서버 `.env`에 `MAIL_FROM`·`SITE_URL`을 넣고 `docker compose up -d`. 앱 컨테이너에서 테스트 메일 발송 성공(SES 전달 시도 1, 반송 0).
- **운영 스택 주의**: 스택에 올린 템플릿은 `infra/ec2.yaml`에서 UserData의 `MAIL_FROM`·`SITE_URL` 두 줄만 뺀 것이다(값은 `.env`에 직접 넣었다). main 템플릿 그대로 업데이트하면 UserData가 바뀌어 인스턴스가 중지·재시작되거나 교체될 수 있으니, change set에서 `Instance`가 바뀌지 않는지 먼저 본다. 또 이 스택의 `GetTemplate` 결과는 한글이 `?`로 나온다. 그걸 고쳐서 올리면 UserData가 바뀌므로 repo 파일(`--template-body file://...`)로 올린다.
- **아직 못 확인한 것**: 연결 계정의 실제 비용 금액 표시(현재 0), 알림 메일의 Gmail 수신 위치(보내는 주소가 `@gmail.com`인데 SES로 보내 DMARC 정렬이 안 되므로 스팸함에 갈 수 있다), 보조 모델 전환(503이 날 때만 발동).
- 사용자 몫(계정 설정이라 사용자 결정): 역할 배정(`docs/ROLES.md`), 제출 마감일 확인, 조원 계정 연결 여부 결정, 시연 후 EC2 중지·정리. 조원 계정을 연결하면 그 계정에도 최신 `infra/customer-role.yaml`(비용 권한)이 필요하고, SES 샌드박스라 알림을 받을 주소도 SES에서 확인해야 한다.
- 외부 공유 전 주의: 스캔 결과·대시보드 캡처에 계정 ID·이메일·인스턴스 ID가 보인다. 가린 뒤에 공유한다(데모 모드 화면은 가짜 값이라 안전).

## 이전 상태 (서버리스 버전, 2026-10-28, 보관)
서버리스 구현(PR #3)은 코드 완성까지 했고 실제 배포는 하지 않은 채 컨테이너 구성으로 전환했다. 관련 파일은 `legacy/serverless/`(README 참고)에 있다.

## 다음 단계 (권장 순서)
1. 대시보드에서 비용 표시와 "테스트 메일 보내기"를 확인한다. 메일이 스팸함에 있으면 "스팸 아님"으로 표시해 둔다.
2. 시연 직전에 스캔을 한 번 더 돌려 해설 캐시가 차 있는지 확인한다.
3. 조원 계정 연결 시연(가능하면), 시연 영상, 장표(역할은 `docs/ROLES.md`, 시연 순서는 `docs/demo-runbook.md`).
4. 사용하지 않는 동안 EC2를 중지해 비용을 줄인다(시연 전 시작 후 DuckDNS IP 갱신 확인). 자동 점검·알림은 서버가 켜져 있을 때만 돈다.
5. 발표(12/1) 후 `docs/demo-runbook.md`의 정리 절차로 스택, SSM 파라미터, IAM 사용자, DuckDNS, Gemini 키, SES 이메일 ID를 삭제한다.
