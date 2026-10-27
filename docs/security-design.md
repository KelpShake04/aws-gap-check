# 보안 설계

이 서비스는 남의 AWS 계정을 들여다보는 도구라서, 서비스 자체가 공격 경로가 되지 않게 설계했다. 발표에서 강조할 항목을 위협별로 정리한다.

## 위협과 대응

| 위협 | 대응 | 코드·설정 위치 | 확인 방법 |
|---|---|---|---|
| 고객 액세스 키 유출 | 액세스 키를 받지 않는다. 고객 계정의 읽기 전용 Role을 임시 자격 증명으로만 맡는다 | `infra/customer-role.yaml` | 설계상 키 입력 화면이 없음 |
| Confused deputy: 다른 사용자가 남의 계정 ID를 등록해 스캔 | 연결마다 서버가 ExternalId를 발급하고 사용자는 바꿀 수 없다. 고객 Role은 그 값만 받는다 | `gapcheck/connections.py`, 템플릿 `sts:ExternalId` 조건 | `tests/test_core.py`의 confused deputy 테스트, 시연(사용자 2명) |
| 서비스 계정 안의 다른 주체가 고객 Role을 맡음 | 신뢰 정책에 `aws:PrincipalArn`으로 scanner, api 역할만 허용 | `infra/customer-role.yaml` | 콘솔 관리자로 AssumeRole 시도 시 거부 |
| 과도한 권한 | 고객 쪽은 읽기 전용 관리형 정책. 서비스 쪽은 역할마다 필요한 리소스만(예: Gemini 키는 처리 Lambda만) | `infra/service.yaml` | `docs/architecture.md` IAM 표 |
| IDOR: 남의 스캔 결과 조회 | DynamoDB 키에 JWT의 `sub`를 넣고, 요청 값으로는 키를 만들지 않는다 | `gapcheck/store.py`, `handlers/api.py` | `tests/test_handlers.py`의 다른 사용자 404 테스트 |
| 저장형 XSS: 리소스 이름·태그에 HTML을 심음 | 화면은 `textContent`/DOM API만 쓰고 HTML 해석 API를 금지. CSP로 인라인 스크립트 차단 | `frontend/app.js`, CloudFront 보안 헤더 | `tests/test_frontend.py`, 브라우저 렌더링 확인 |
| 프롬프트 인젝션: 태그에 "이전 지시를 무시하라" | Gemini에는 Prowler 메타데이터와 개수만 보내고 고객 문자열은 보내지 않는다. 출력은 스키마로 재검증하고 해설은 아무 동작도 일으키지 않는다 | `gapcheck/explain.py`, `gapcheck/validate.py` | `tests/test_analysis.py`(프롬프트에 고객 문자열 없음) |
| 고객 데이터의 외부(Google) 전송 | 위와 같음. 계정 ID, 리소스 이름, 정책 원문이 Google로 가지 않는다 | `explanation_input()` | 같은 테스트 |
| 빌드 명령 주입 | CodeBuild 입력을 정규식으로 다시 검증하고 Prowler를 셸 없이 인자 목록으로 실행 | `scanner/run_scan.py` | `tests/test_run_scan.py` |
| 비용 공격(스캔 남발) | 관리자만 사용자 생성, 사용자당 동시 1개·하루 10회, API throttling, CodeBuild 동시 1개, Budgets 알림 | `gapcheck/scans.py`, 템플릿 | `tests/test_core.py` 한도 테스트 |
| 시크릿 유출 | Gemini 키는 SSM SecureString. 헤더로만 보내고 오류 메시지·로그에서 가림 | `gapcheck/llm.py` | `tests/test_llm.py` |
| 결과 데이터 장기 보관 | 30일 후 자동 삭제(S3 수명주기, DynamoDB TTL), 즉시 삭제 버튼, 버킷 비공개·TLS 강제 | 템플릿, `gapcheck/scans.py` | 삭제 테스트 |

## 알려진 한계와 개선안

- `SecurityAudit` + `ViewOnlyAccess`는 Prowler 전체를 위한 범위라 핵심 check 33개에는 넓다. 직접 만든 최소 권한 정책이 개선안이다.
- Lambda 실행 역할 신뢰 정책에는 `aws:SourceAccount` 조건을 넣지 않았다(실행 실패 위험). CodeBuild 역할에는 넣었다.
- CSP의 `connect-src`는 스택 순환 참조를 피하려고 리전의 `execute-api` 와일드카드를 쓴다. 사용자 지정 도메인을 쓰면 좁힐 수 있다.
- Cognito MFA는 꺼 두었다(시연 편의). 실제 서비스라면 켠다.
- ExternalId는 비밀값이 아니다(AWS 안내). CodeBuild 환경 변수로 평문 전달되며, 보안은 "서버만 발급하고 사용자는 바꿀 수 없다"는 점에서 나온다.
