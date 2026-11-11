# aws-gap-check

AWS 계정을 연결하면 설정상 빈틈을 점검하고, AI(Gemini)가 한국어로 위험·영향·조치 방법을 해설해 주는 웹 서비스. 수업 팀 프로젝트(2조 5인, 12/1 발표).

- 최초 설계(서버리스, 보관): [specs/2026-10-28-aws-gap-check-design.md](docs/superpowers/specs/2026-10-28-aws-gap-check-design.md), 구현 계획: [plans/2026-10-28-aws-gap-check-implementation.md](docs/superpowers/plans/2026-10-28-aws-gap-check-implementation.md)
- 기능: 계정 연결(읽기 전용 Role + ExternalId), Prowler 점검 + Gemini 한국어 해설, **공식 수정 예시**(Prowler 메타데이터의 콘솔 절차·CLI·CloudFormation·Terraform, 자동 적용 안 함), **대시보드 홈**(계정별 비용·보안 요약), **계정 비용 조회**(Cost Explorer), **자동 점검(매일/매주) + 새 위험 항목 이메일 알림**(SES), **ISMS-P 통제 항목 관점**(KISA 2023 매핑), **AI 보안 상담**(Gemini function calling, 읽기 전용 도구로 내 스캔에 근거해 답변), **CI/CD**(GitHub Actions 테스트 → OIDC + SSM 자동 배포, 관리자 승인).
- 구성: EC2 한 대 + Docker Compose(app, MySQL 8.4, caddy). 배포 완료: https://agc-kelp04.duckdns.org (템플릿 [infra/ec2.yaml](infra/ec2.yaml), 계정 로그인은 관리자가 만든다). 현재 상태·다음 단계: [docs/HANDOFF.md](docs/HANDOFF.md).
- 문서: [실행 방법](docs/container.md), [아키텍처](docs/architecture.md), [보안 설계](docs/security-design.md), [ERD](docs/erd.md), [시연 런북](docs/demo-runbook.md), [팀 역할](docs/ROLES.md), [재설계 문서](docs/superpowers/specs/2026-10-28-container-redesign.md), [대시보드·비용](docs/superpowers/specs/2026-11-03-billing-dashboard.md), [자동 점검·알림](docs/superpowers/specs/2026-11-03-scheduled-alerts.md). 이전 서버리스 구성: [legacy/serverless](legacy/serverless/README.md).
- 테스트: `scripts/test_with_db.sh` (앱 이미지 + 임시 MySQL로 전체 실행). `python -m unittest`만 돌리면 DB가 필요한 테스트는 건너뛴다.
- 스캔 대상은 팀 소유 테스트 계정만. 액세스 키는 받지 않고 읽기 전용 Role(`AssumeRole` + `ExternalId`)만 사용.
