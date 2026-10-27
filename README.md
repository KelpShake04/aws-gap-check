# aws-gap-check

AWS 계정을 연결하면 설정상 빈틈을 점검하고, AI(Gemini)가 한국어로 위험·영향·조치 방법을 해설해 주는 웹 서비스. 수업 팀 프로젝트(3인, 12월 초 발표).

- 설계 문서(초안): [docs/superpowers/specs/2026-10-28-aws-gap-check-design.md](docs/superpowers/specs/2026-10-28-aws-gap-check-design.md)
- 상태: 설계 단계. 구현은 설계 승인 후 시작.
- 스캔 대상은 팀 소유 테스트 계정만. 액세스 키는 받지 않고 읽기 전용 Role(`AssumeRole` + `ExternalId`)만 사용.
