# 보안 설계

이 서비스는 남의 AWS 계정을 들여다보는 도구라서, 서비스 자체가 공격 경로가 되지 않게 설계했다. 발표에서 강조할 항목을 위협별로 정리한다(EC2 + Docker 구성 기준).

## 위협과 대응

| 위협 | 대응 | 코드·설정 위치 | 확인 방법 |
|---|---|---|---|
| 고객 액세스 키 유출 | 액세스 키를 받지 않는다. 고객 계정의 읽기 전용 Role을 임시 자격 증명으로만 맡는다 | `infra/customer-role.yaml` | 설계상 키 입력 화면이 없음 |
| Confused deputy: 다른 사용자가 남의 계정 ID를 등록해 스캔 | 연결마다 서버가 ExternalId를 발급하고 사용자는 바꿀 수 없다. 고객 Role은 그 값만 받는다 | `gapcheck/connections.py`, 템플릿 `sts:ExternalId` 조건 | `tests/test_core.py`의 confused deputy 테스트, 시연(사용자 2명) |
| 서비스 계정 안의 다른 주체가 고객 Role을 맡음 | 신뢰 정책에 `aws:PrincipalArn`으로 인스턴스 Role만 허용 | `infra/customer-role.yaml` | 콘솔 관리자로 AssumeRole 시도 시 거부 |
| 과도한 권한 | 고객 쪽은 읽기 전용 관리형 정책. 서비스 쪽 인스턴스 Role은 AssumeRole(고객 Role 이름 고정)과 SSM 파라미터 2개 읽기만 | `infra/ec2.yaml` | `docs/architecture.md` IAM 표 |
| 인스턴스 자격 증명 탈취(SSRF) | IMDSv2 필수, 앱은 사용자 입력 URL을 서버에서 요청하는 기능이 없다 | `infra/ec2.yaml`(`MetadataOptions`) | 템플릿 |
| 비밀번호 대입·탈취 | scrypt 해시, 10자 이상, 5회 실패 시 15분 잠금, 실패 응답이 모두 같음 | `gapcheck/auth.py` | `tests/test_server.py` 로그인 테스트 |
| 세션 탈취·CSRF | 세션 토큰은 SHA-256만 저장, 쿠키는 HttpOnly·Secure·SameSite=Strict, 상태 변경 요청은 `X-Requested-With` 헤더 요구 | `gapcheck/server.py`, `gapcheck/auth.py` | `test_csrf_header_required_for_writes` |
| IDOR: 남의 스캔 결과 조회 | 모든 사용자 데이터 쿼리에 `user_id` 조건, 키는 세션에서 얻고 요청 값으로 만들지 않는다. 외래키로 사용자 삭제 시 함께 삭제 | `gapcheck/db.py`, `db/init/01-schema.sql` | `test_full_flow_and_user_isolation` |
| SQL 인젝션 | 모든 쿼리는 파라미터 바인딩. 앱 DB 계정은 SELECT/INSERT/UPDATE/DELETE만(DDL 불가) | `gapcheck/db.py`, `db/init/01-schema.sql` | `tests/test_db.py` |
| 저장형 XSS: 리소스 이름·태그에 HTML을 심음 | 화면은 `textContent`/DOM API만 쓰고 HTML 해석 API를 금지. CSP(`default-src 'none'`, `script-src 'self'`)와 `nosniff` | `frontend/app.js`, `gapcheck/server.py` | `tests/test_frontend.py`, `test_static_files_and_headers` |
| 프롬프트 인젝션: 태그에 "이전 지시를 무시하라" | Gemini에는 Prowler 메타데이터와 개수만 보내고 고객 문자열은 보내지 않는다. 출력은 스키마로 재검증하고 해설은 아무 동작도 일으키지 않는다 | `gapcheck/explain.py`, `gapcheck/validate.py` | `tests/test_analysis.py`(프롬프트에 고객 문자열 없음) |
| 고객 데이터의 외부(Google) 전송 | 위와 같음. 계정 ID, 리소스 이름, 정책 원문이 Google로 가지 않는다 | `explanation_input()` | 같은 테스트 |
| 스캔 명령 주입 | 작업자가 입력을 정규식으로 다시 검증하고 Prowler를 셸 없이 인자 목록으로 실행. Prowler 프로세스에는 DB 비밀번호·Gemini 키를 넘기지 않는다 | `gapcheck/worker.py`, `scanner/run_scan.py` | `tests/test_run_scan.py`, `tests/test_worker.py` |
| 컨테이너 탈출·권한 | app은 비루트 실행, `cap_drop: ALL`, `no-new-privileges`, `docker.sock` 미마운트, 공개 포트는 caddy(80, 443)뿐, 이미지·Prowler 버전 고정 | `compose.yaml`, `Dockerfile` | 파일 |
| 비용 공격(스캔 남발) | 로그인 사용자만, 사용자당 동시 1개·하루 10회, Budgets 알림. 스캔을 지워도 기록은 `DELETED`로 남아 하루 한도에서 빠지지 않는다 | `gapcheck/scans.py` | `tests/test_core.py` 한도 테스트 |
| 시크릿 유출 | Gemini 키·DuckDNS 토큰은 SSM SecureString. user data와 레포에는 값이 없고, DB 비밀번호는 부팅 때 랜덤 생성해 `.env`(권한 600)에만 둔다. Gemini 키는 헤더로만 보내고 오류 메시지·로그에서 가림 | `infra/ec2.yaml`, `gapcheck/llm.py` | `tests/test_llm.py` |
| 결과 데이터 장기 보관 | 30일 후 DB 기록 자동 삭제, 즉시 삭제 버튼, 디스크는 EBS 암호화 | `gapcheck/worker.py`, `infra/ec2.yaml` | 삭제 테스트 |
| 관리 접속 | SSH(22) 미개방, 관리는 Session Manager만 | `infra/ec2.yaml` | Security Group |

## 알려진 한계와 개선안

- `SecurityAudit` + `ViewOnlyAccess`는 Prowler 전체를 위한 범위라 핵심 check 33개에는 넓다. 직접 만든 최소 권한 정책이 개선안이다.
- 비밀번호 5회 실패 잠금은 남이 일부러 계정을 잠글 수 있다(시연용으로 허용). 로그인 MFA는 없다.
- 데이터가 EC2 디스크 한 곳에 모인다. 인스턴스를 지우면 데이터도 사라진다(시연용). 백업은 하지 않는다.
- 인스턴스 Role 자격 증명은 hop limit 2라서 같은 호스트의 컨테이너가 쓸 수 있다. 앱이 서버에서 외부 URL을 요청하지 않는 것으로 SSRF 표면을 없앴다.
- MySQL 연결은 TLS지만 인증서를 검증하지 않는다(같은 호스트의 Docker 네트워크 안).
- 인증서가 DuckDNS·Let's Encrypt에 의존한다. 막히면 로컬 `docker compose`와 녹화 영상으로 대체한다.
- Gemini API 무료 등급은 보낸 내용이 Google의 제품 개선에 쓰일 수 있다(약관 확인 필요). 보내는 것은 Prowler의 공개 점검 메타데이터와 개수·리전뿐이라 위험은 낮지만, 실제 서비스라면 유료 등급이나 AWS 안의 모델(Bedrock)을 쓴다.
- 스캔 리전은 `ap-northeast-2` 하나로 고정했다(`scanner/run_scan.py`의 `SCAN_REGION`). 다른 리전의 리전 리소스는 점검하지 않는다.
- 같은 사용자가 거의 동시에 스캔 시작을 두 번 누르면 한도 확인을 둘 다 통과할 수 있다. 작업자가 하나라서 실제 실행은 한 번에 하나다.
- ExternalId는 비밀값이 아니다(AWS 안내). 보안은 "서버만 발급하고 사용자는 바꿀 수 없다"는 점에서 나온다.
