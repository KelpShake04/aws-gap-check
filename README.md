# aws-gap-check

AWS 계정을 연결하면 설정상 빈틈을 점검하고, AI(Gemini)가 한국어로 위험·영향·조치 방법을 해설해 주는 웹 서비스. 수업 팀 프로젝트(3인, 12월 초 발표).

- 설계 문서(초안): [docs/superpowers/specs/2026-10-28-aws-gap-check-design.md](docs/superpowers/specs/2026-10-28-aws-gap-check-design.md)
- 구현 계획: [docs/superpowers/plans/2026-10-28-aws-gap-check-implementation.md](docs/superpowers/plans/2026-10-28-aws-gap-check-implementation.md)
- 상태: EC2 한 대 + Docker Compose(app, MySQL 8.4, caddy) 구성으로 바꾸는 중([재설계](docs/superpowers/specs/2026-10-28-container-redesign.md)). 앱은 로컬 `docker compose`로 동작 확인, EC2 배포 템플릿은 아직 없음. 실행 방법은 [docs/container.md](docs/container.md), ERD는 [docs/erd.md](docs/erd.md). 이전 서버리스 버전 문서: [deploy](docs/deploy.md), [아키텍처](docs/architecture.md), [보안 설계](docs/security-design.md), [시연 런북](docs/demo-runbook.md).
- 테스트: `scripts/test_with_db.sh` (앱 이미지 + 임시 MySQL로 전체 실행). `python -m unittest`만 돌리면 DB가 필요한 테스트는 건너뛴다.
- 스캔 대상은 팀 소유 테스트 계정만. 액세스 키는 받지 않고 읽기 전용 Role(`AssumeRole` + `ExternalId`)만 사용.
