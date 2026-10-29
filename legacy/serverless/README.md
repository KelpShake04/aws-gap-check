# 서버리스 구성 (보관용, 유지보수 안 함)

2026-10-28 이전의 Cognito, CloudFront, Lambda, DynamoDB, CodeBuild 구성이다. 설계가 EC2 한 대 + Docker로 바뀌어 지금 배포 경로가 아니다. 프런트엔드가 컨테이너 로그인으로 바뀌어 이 구성은 그대로 배포되지 않고, 파일을 옮기면서 안의 상대 경로(`$ROOT/backend`, `CodeUri: ../backend/` 등)도 고치지 않았다.

| 파일 | 원래 위치 |
|---|---|
| `handlers/` | `backend/handlers/` (공용 로직 `backend/gapcheck/`를 import. `tests/test_handlers.py`가 CI에서 계속 검증) |
| `infra/service.yaml` | `infra/service.yaml` |
| `scripts/` | `scripts/` (`deploy.sh`, `start_test_scan.sh`, `create_user.sh`) |
| `scanner/buildspec.yml` | `scanner/buildspec.yml` |
| `docs/deploy.md` | `docs/deploy.md` |

발표에서는 "서버리스에서 컨테이너로 단순화한 과정"의 근거 자료로 쓴다.
