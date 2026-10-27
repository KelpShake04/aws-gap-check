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

## 현재 상태 (2026-10-28)
- 구현 계획 승인됨: `docs/superpowers/plans/2026-10-28-aws-gap-check-implementation.md`(D1~D8 제안대로. CodeBuild, CloudFormation, CloudShell 배포, Gemini에는 메타데이터만, vanilla JS, SSM SecureString, 관리자만 가입, 핵심 check 33개).
- Phase 0 코드 작성 완료(unittest, cfn-lint 통과): Gemini 호출부 `backend/gapcheck/llm.py`, 고객 Role 템플릿, 스캐너 스택(`infra/service.yaml`), `scanner/run_scan.py`, 배포·스파이크 스크립트, 합성 OCSF fixture.
- **사용자 실행 대기:** `docs/deploy.md`의 1~4단계(Gemini 스파이크, 스택 배포, 자체 테스트 Role, 테스트 스캔). 결과는 같은 문서의 양식으로 여기에 적는다. 결과를 보고 CodeBuild 확정 여부를 정한 뒤 Phase 1로 간다.

## 다음 단계 (권장 순서)
1. 설계 문서를 읽고 구현 계획(`docs/superpowers/plans/`)을 먼저 작성해 사용자 승인을 받는다. → 완료(위 현재 상태).
2. 구현 첫 주에 확인: Gemini 호출 가능 여부, 배포 권한, Prowler를 CodeBuild/Fargate 중 어디서 돌릴지(비용·시간 제한 비교).
3. IaC는 CloudFormation(D2), 시크릿은 SSM Parameter Store SecureString(D6, 무료)으로 한다.
4. 발표 자료용으로 아키텍처 설명과 보안 설계(ExternalId, 최소 권한, 프롬프트 인젝션 방어)를 문서로 남긴다.
