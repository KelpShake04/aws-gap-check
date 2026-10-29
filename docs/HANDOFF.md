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
- 평가 기준(IaC 필수 여부, 시연 시간), 비용 상한, 조원 참여 여부.
- 조원 계정 연결 동의와 계정 종류.

## 현재 상태 (2026-10-29, 배포 완료)
- 배포 구조는 EC2 한 대 + Docker Compose(app, mysql, caddy). 설계는 `docs/superpowers/specs/2026-10-28-container-redesign.md`, 실행·구조·한계는 `docs/container.md`, ERD는 `docs/erd.md`, 구성·보안은 `docs/architecture.md`·`docs/security-design.md`.
- **배포됨**: 스택 `aws-gap-check-ec2`(ap-northeast-2b, `c7i-flex.large`: Free Tier 계정이라 `t3.medium`이 거부됨), `https://agc-kelp04.duckdns.org`. SSM 파라미터 이름은 `/gapcheck/...`(`aws`·`ssm` 접두사는 예약어).
- **AI 해설**: 주 모델 `gemini-3.1-flash-lite`(`.env`의 `GEMINI_MODEL`, 스택 파라미터 `GeminiModel`은 비어 있음). 5xx·타임아웃이면 10초, 20초 간격으로 3번 시도 후 보조 모델 `gemini-3.5-flash-lite`(`GEMINI_FALLBACK_MODEL`, compose 기본값)를 한 번 시도하고, 그래도 안 되면 Prowler 원문(영어)으로 대체한다. 해설 캐시(`explanations`)는 만료가 없다.
- main에 있는 것: 앱 전체, `infra/ec2.yaml`, CI(unittest 140개 + MySQL 서비스, cfn-lint), 재시도·폴백(PR #16, #17), 서버리스 코드는 `legacy/serverless/`.
- 확인한 것: EC2에서 본인 계정 실제 스캔(14개 항목) + Gemini 해설, 캐시로 재스캔 70초대. 보조 모델 전환은 503이 날 때만 발동해서 실제 전환은 아직 못 봤다.
- 열린 PR: #18(이메일 비ASCII 거부). 깨진 이메일이 계정에 저장돼 로그인이 막힌 적이 있다.
- 사용자 몫: 역할 배정(`docs/ROLES.md`), 제출 마감일 확인, 조원 계정 연결 여부 결정, 시연 후 EC2 중지·정리.
- 외부 공유 전 주의: 스캔 결과 캡처에 계정 ID·이메일·인스턴스 ID가 보인다. 가린 뒤에 공유한다.

## 이전 상태 (서버리스 버전, 2026-10-28, 보관)
서버리스 구현(PR #3)은 코드 완성까지 했고 실제 배포는 하지 않은 채 컨테이너 구성으로 전환했다. 관련 파일은 `legacy/serverless/`(README 참고)에 있다.

## 다음 단계 (권장 순서)
1. 시연 직전에 스캔을 한 번 더 돌려 해설 캐시가 차 있는지 확인한다.
2. 조원 계정 연결 시연(가능하면), 시연 영상, 장표(역할은 `docs/ROLES.md`).
3. 사용하지 않는 동안 EC2를 중지해 비용을 줄인다(시연 전 시작 후 DuckDNS IP 갱신 확인).
4. 발표(12/1) 후 `docs/demo-runbook.md`의 정리 절차로 스택, SSM 파라미터, IAM 사용자, DuckDNS, Gemini 키를 삭제한다.
