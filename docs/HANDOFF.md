# 인수인계 (2026-10-29 기준)

## 한 줄 요약
AWS 계정을 연결하면 Prowler로 빈틈을 점검하고, Gemini가 한국어로 위험·영향·조치를 해설하는 웹 서비스. 팀 5명(2조), 개발은 사용자 1명이 전담. 발표 12/1.

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
- Gemini API 무료 한도와 사용 가능한 모델(Flash 우선).
- 평가 기준(IaC 필수 여부, 시연 시간), 비용 상한, 조원 참여 여부.
- 서비스를 배포할 AWS 계정과 배포 권한(CI에서 쓸지, 사용자가 로컬에서 배포할지).

## 현재 상태 (2026-10-29, 컨테이너 버전)
- 배포 구조는 EC2 한 대 + Docker Compose(app, mysql, caddy). 설계는 `docs/superpowers/specs/2026-10-28-container-redesign.md`, 실행·구조·한계는 `docs/container.md`, ERD는 `docs/erd.md`, 구성·보안은 `docs/architecture.md`·`docs/security-design.md`.
- main에 있는 것: 앱 전체(PR #8), `infra/ec2.yaml`(PR #9, #10), CI(unittest 134개 + MySQL 서비스, cfn-lint), 후속 개선(PR #12), 서버리스 코드는 `legacy/serverless/`.
- 확인한 것: 앱 이미지 안에서 전체 테스트 통과, 로컬 `docker compose` 데모 모드 흐름(headless Chrome), 본인 계정 실제 스캔 성공(로컬 compose, 75초).
- **아직 안 한 것**: `infra/ec2.yaml` 실제 스택 배포(DuckDNS 토큰·Gemini 키 필요), Gemini 실호출, 조원 계정 연결 시연, 장표·시연 영상. `<details>` 유지는 브라우저로 확인 안 함.
- 사용자 몫: DuckDNS 서브도메인·토큰, Gemini 키를 SSM에 저장, 스택 `aws-gap-check-local-app-role` 삭제 후 `infra/ec2.yaml` 배포, 역할 배정(`docs/ROLES.md`), 제출 마감일 확인.

## 이전 상태 (서버리스 버전, 2026-10-28, 보관)
서버리스 구현(PR #3)은 코드 완성까지 했고 실제 배포는 하지 않은 채 컨테이너 구성으로 전환했다. 관련 파일은 `legacy/serverless/`(README 참고)에 있다.

## 다음 단계 (권장 순서)
1. 사용자: DuckDNS·Gemini 키 준비 → `infra/ec2.yaml` 배포 → `SiteUrl` 접속, Session Manager로 `create-user`. 오류가 나면 CloudFormation 이벤트·`/var/log/cloud-init-output.log`를 들고 고친다.
2. 서비스 계정 자신을 고객 계정으로 연결해 EC2에서 실제 스캔·Gemini 해설 확인.
3. 조원 계정 연결 시연, 시연 영상, 장표(역할은 `docs/ROLES.md`).
4. 발표(12/1) 후 `docs/demo-runbook.md`의 정리 절차로 삭제.
