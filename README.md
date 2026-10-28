# aws-gap-check

AWS 계정을 연결하면 설정상 빈틈을 점검하고, AI(Gemini)가 한국어로 위험·영향·조치 방법을 해설해 주는 웹 서비스. 수업 팀 프로젝트(3인, 12월 초 발표).

- 설계 문서(초안): [docs/superpowers/specs/2026-10-28-aws-gap-check-design.md](docs/superpowers/specs/2026-10-28-aws-gap-check-design.md)
- 구현 계획: [docs/superpowers/plans/2026-10-28-aws-gap-check-implementation.md](docs/superpowers/plans/2026-10-28-aws-gap-check-implementation.md)
- 상태: 배포 직전까지 구현 완료, AWS 배포·확인 전. 실행 방법은 [docs/deploy.md](docs/deploy.md), 발표 자료는 [아키텍처](docs/architecture.md), [보안 설계](docs/security-design.md), [시연 런북](docs/demo-runbook.md).
- 테스트: 레포 루트에서 `python -m unittest -v` (표준 라이브러리만 사용)
- 스캔 대상은 팀 소유 테스트 계정만. 액세스 키는 받지 않고 읽기 전용 Role(`AssumeRole` + `ExternalId`)만 사용.
