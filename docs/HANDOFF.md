# 인수인계 (2026-10-28 기준)

## 한 줄 요약
AWS 계정을 연결하면 Prowler로 빈틈을 점검하고, Gemini가 한국어로 위험·영향·조치를 해설하는 웹 서비스. 팀 3명, 개발은 사용자 1명이 거의 전담. 발표 12월 초.

## 결정된 것 (사용자 확정)
- 형태: 서비스 화면을 웹사이트로 제공 (S3 + CloudFront, Cognito 로그인).
- 계정 연결: 사용자 계정에 읽기 전용 Role(CloudFormation 템플릿 제공) → `sts:AssumeRole` + 사용자별 `ExternalId`. 액세스 키는 받지 않는다.
- AI: Gemini API를 Lambda에서 호출. Bedrock의 OpenAI GPT-6 Luna는 이 계정에서 `AccessDeniedException`(not available for this account)으로 확인됨. Claude는 Anthropic 용도 정보 제출이 필요해 보류. 호출부는 함수 하나로 분리해 나중에 교체 가능하게 한다.
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

## 현재 상태 (2026-10-29, 컨테이너 버전 초안)
- 배포 구조를 EC2 한 대 + Docker Compose(app, mysql, caddy)로 바꾸는 설계(`docs/superpowers/specs/2026-10-28-container-redesign.md`)대로 **앱 초안을 구현**했다. 실행·구조·한계는 `docs/container.md`, ERD는 `docs/erd.md`.
- 로컬에서 확인한 것: 앱 이미지 안에서 전체 테스트 통과(실제 MySQL 8.4.9 포함), `docker compose up` 후 데모 모드로 로그인 → 비밀번호 변경 → 연결 → 스캔 → 리포트 → 삭제 → 로그아웃(HTTPS, headless Chrome 화면 확인), Prowler 5.46이 스캔 인자를 받는 것(자격 증명 단계까지).
- 아직 안 한 것: EC2 템플릿(`infra/ec2.yaml`)과 user data, 실제 AWS 계정 스캔, Gemini 실제 호출, CI(GitHub Actions), 서버리스 코드 정리.

## 이전 상태 (2026-10-28, 서버리스 버전)
- 구현 계획 승인됨: `docs/superpowers/plans/2026-10-28-aws-gap-check-implementation.md`(D1~D8 제안대로).
- **배포 직전까지 코드 완성**(PR #3): 백엔드(`backend/gapcheck`, `backend/handlers`), 전체 스택 템플릿(`infra/service.yaml`, cfn-lint 통과), 고객 Role 템플릿, 스캐너, 프런트엔드(`frontend/`, Chromium 렌더링 확인), 배포·사용자 생성 스크립트, 발표 문서(`docs/architecture.md`, `docs/security-design.md`, `docs/demo-runbook.md`). unittest 전체 통과.
- **아직 실제 AWS에서 확인한 것은 없다.** 다음은 사용자가 `docs/deploy.md` 1~6단계를 실행하고 7단계 양식으로 결과를 남기는 것. 문제가 나오면 로그를 들고 다음 세션에서 고친다.
- 계획에서 뺀 것: SNS 알림(P2), `warm_cache.py`(발표 전 사전 스캔이 캐시를 채우므로 불필요).
- GitHub Actions: 비공개 레포 무료 시간을 다 써서 CI job이 시작되지 않는다. 시간이 다시 생길 때까지 push 전에 로컬에서 `python -m unittest`와 `cfn-lint infra/*.yaml`로 확인한다.
- 크레딧(사용자 언급): 남은 크레딧이 적다. AWS 예상 비용은 월 $1~2이며 상시 과금 리소스는 없다.

## 다음 단계 (권장 순서)
1. 설계 문서를 읽고 구현 계획(`docs/superpowers/plans/`)을 먼저 작성해 사용자 승인을 받는다. → 완료(위 현재 상태).
2. 구현 첫 주에 확인: Gemini 호출 가능 여부, 배포 권한, Prowler를 CodeBuild/Fargate 중 어디서 돌릴지(비용·시간 제한 비교).
3. IaC는 CloudFormation(D2), 시크릿은 SSM Parameter Store SecureString(D6, 무료)으로 한다.
4. 발표 자료용으로 아키텍처 설명과 보안 설계(ExternalId, 최소 권한, 프롬프트 인젝션 방어)를 문서로 남긴다.
