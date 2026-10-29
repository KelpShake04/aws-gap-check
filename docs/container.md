# 컨테이너 버전 실행 안내

설계: `docs/superpowers/specs/2026-10-28-container-redesign.md`. 이 문서는 지금 구현된 것을 로컬에서 띄우고 확인하는 방법이다. EC2 배포는 `infra/ec2.yaml`(아래 "실제 스캔 (EC2)").

## 구성

```
[브라우저] ──HTTPS──> caddy (80/443, 인증서 자동)
                        └─> app:8080  (Python 표준 라이브러리 HTTP 서버 + 스캔 작업자 스레드)
                               ├─ mysql:3306  (MySQL 8.4.9, 앱 계정은 SELECT/INSERT/UPDATE/DELETE만)
                               ├─ Prowler 5.46 (같은 이미지 안, 셸 없이 인자 목록으로 실행)
                               └─ Gemini API  (키는 SSM에서 읽음, 없으면 Prowler 원문)
```

| 파일 | 역할 |
|---|---|
| `Dockerfile` | Prowler 공식 이미지 위에 앱 코드만 복사. PyMySQL은 해시 고정(`requirements.txt`) |
| `compose.yaml` | mysql, app, caddy 세 서비스. 공개 포트는 caddy뿐 |
| `Caddyfile` | HTTPS, 도메인일 때만 HSTS |
| `db/init/01-schema.sql` | 테이블 6개와 앱 계정 권한. ERD는 `docs/erd.md` |
| `backend/gapcheck/server.py` | 라우팅, 정적 파일, 쿠키 세션, CSRF 헤더 확인, 보안 헤더 |
| `backend/gapcheck/auth.py` | scrypt 비밀번호, 세션 토큰(해시만 저장), 5회 실패 시 15분 잠금 |
| `backend/gapcheck/db.py` | MySQL 저장소. 메서드 이름이 이전 DynamoDB 저장소와 같다 |
| `backend/gapcheck/worker.py` | QUEUED 스캔을 하나씩 실행, 결과 저장·해설, 30일 지난 데이터 정리 |
| `backend/gapcheck/cli.py` | 사용자 만들기 |

## 로컬에서 띄우기 (데모 모드)

AWS 자격 증명 없이 화면 흐름 전체(로그인 → 연결 → 스캔 → 해설 화면)를 볼 수 있다. 데모 모드는 계정 검증을 건너뛰고 미리 준비한 결과(`tests/fixtures/ocsf-sample.json`)를 쓴다. 화면 오른쪽 위에 "(데모 모드)"가 표시된다.

1. 레포 폴더에 `.env`를 만든다(레포에 올라가지 않는다).

   ```bash
   cat > .env <<EOF
   MYSQL_ROOT_PASSWORD=$(openssl rand -hex 16)
   MYSQL_PASSWORD=$(openssl rand -hex 16)
   SITE_ADDRESS=localhost
   HTTP_PORT=8080
   HTTPS_PORT=8443
   DEMO_FIXTURE=/app/demo/ocsf-sample.json
   EOF
   chmod 600 .env
   ```

2. 띄운다(처음에는 Prowler 이미지 4GB를 받느라 오래 걸린다).

   ```bash
   docker compose up -d --build
   docker compose ps          # mysql이 healthy, app·caddy가 running이면 된다
   ```

3. 사용자를 만든다. 임시 비밀번호가 한 번만 출력된다.

   ```bash
   docker compose exec app python -m gapcheck.cli create-user me@example.com
   ```

4. `https://localhost:8443` 에 접속한다. 로컬 인증서라 브라우저 경고가 뜨면 "고급 → 계속"을 누른다. 임시 비밀번호로 로그인하면 새 비밀번호(10자 이상)로 바꾸는 화면이 나온다.

5. 끄기: `docker compose down` (데이터 유지), 데이터까지 지우기: `docker compose down -v`.

MySQL 스키마를 바꾸면 `docker compose down -v`로 볼륨을 지워야 새 스키마가 적용된다(마이그레이션 도구 없음).

## 실제 스캔 (로컬 PC, EC2 없이)

2026-10-29 서비스 계정 자신을 고객 계정으로 연결해 확인했다(핵심 점검 50개, 약 75초).

1. 관리자(콘솔 로그인 CLI 세션)로 `infra/local-app-role.yaml`을 스택 `aws-gap-check-local-app-role`로 배포한다.
2. 앱 Role만 맡을 수 있는 IAM 사용자(예: `aws-gap-check-local`, 정책 `sts:AssumeRole` on `aws-gap-check-app-role`)와 액세스 키를 만들어 프로필(`agc-local`)에 저장한다. root는 AssumeRole을 못 해서 필요하다.
3. `scripts/local_aws_creds.sh agc-local` → `.env.aws`(1시간짜리 앱 Role 자격 증명). `.env`에서 `DEMO_FIXTURE`를 빼고 `docker compose up -d`.
4. 웹에서 연결을 만들고, 발급된 ExternalId로 `infra/customer-role.yaml`을 스택 `aws-gap-check-readonly-role`로 배포한 뒤 검증·스캔한다.
5. 정리: 두 스택 삭제, IAM 사용자의 액세스 키와 사용자 삭제. EC2 템플릿이 같은 Role 이름을 쓰므로 EC2로 옮기기 전에 1번 스택을 지운다.

## 실제 스캔 (EC2)

EC2에서는 `.env`에 `DEMO_FIXTURE`를 넣지 않는다. 그러면 앱이 인스턴스 Role(`aws-gap-check-app-role`)로 고객 계정의 `AwsGapCheckReadOnlyRole`을 `ExternalId`와 함께 맡아 Prowler를 실행한다. 고객 템플릿 `infra/customer-role.yaml`은 이 Role을 허용하도록 바꿔 두었다. AI 해설을 쓰려면 `.env`에 `GEMINI_MODEL=<모델 이름>`을 넣고 키를 SSM `/aws-gap-check/gemini-api-key`에 둔다. 

배포 순서(템플릿은 `cfn-lint`와 user data 셸 문법만 확인했고, 실제 스택 생성은 아직 실행하지 않았다):

1. [duckdns.org](https://www.duckdns.org)에서 서브도메인을 만든다. CloudShell에서 토큰과 Gemini 키를 SSM에 저장한다.
   ```bash
   read -rs T; aws ssm put-parameter --name /aws-gap-check/duckdns-token --type SecureString --value "$T"; unset T
   ```
   Gemini 키는 `docs/deploy.md` 1단계와 같다(`/aws-gap-check/gemini-api-key`).
2. 로컬 실행용 스택 `aws-gap-check-local-app-role`이 있으면 먼저 지운다(Role 이름이 같다).
3. CloudFormation 콘솔에서 `infra/ec2.yaml`로 스택을 만든다. 파라미터는 `DuckDnsSubdomain`, `GeminiModel`. 마지막 화면의 IAM 확인란을 체크한다.
4. 5~10분 뒤 출력의 `SiteUrl`로 접속한다. EC2 콘솔 **Session Manager 연결** 후 `cd /opt/aws-gap-check && sudo docker compose exec app python -m gapcheck.cli create-user <이메일>`.
5. 안 쓸 때는 인스턴스를 **중지**한다. 재시작하면 부팅 때 DuckDNS에 새 IP를 등록한다.

user data 로그는 `/var/log/cloud-init-output.log`.

## 테스트

```bash
scripts/test_with_db.sh            # 전체(앱 이미지 + 임시 MySQL 8.4), 약 1분
scripts/test_with_db.sh tests.test_server -v
python3 -m unittest                # DB·scrypt가 필요한 테스트는 건너뛴다
```

맥 기본 `python3`(LibreSSL)에는 `hashlib.scrypt`가 없어서 로그인 테스트는 앱 이미지 안에서만 돈다.

## 구현하며 정한 것 (설계서의 "빌더에게 남기는 결정")

- **라우팅**: `server.py`의 `ROUTES` 표 하나(메서드, 정규식 경로, 처리 함수, 접근 수준). 접근 수준은 public(로그인·로그아웃), session(비밀번호 변경 전에도 허용), user(일반).
- **스키마**: `utf8mb4`, 사용자 데이터 테이블은 모두 `user_id`가 기본 키 앞자리. 외래키로 사용자 삭제 시 함께 삭제, 결과는 스캔 삭제 시 함께 삭제. 스캔 큐는 `(status, id)` 인덱스.
- **작업자**: 스레드 하나. 스캔 시작 요청이 깨우고, 아니면 30초마다 확인. 서버가 재시작되면 진행 중이던 스캔은 실패로 표시.
- **TLS**: caddy가 맡는다(앱은 HTTP만, 외부에 포트를 열지 않음).
- **서버리스 코드**: 지우지 않고 그대로 둔다(`backend/handlers`, `infra/service.yaml`). 공용 로직(`scans.create`, `results.store_and_explain`, `views.py`)은 두 구성이 같이 쓴다. 다만 프런트엔드는 컨테이너 로그인으로 바뀌어 서버리스 배포 경로는 더 이상 맞지 않는다. 정리(`legacy/`로 이동 또는 삭제)는 따로 한다.

## 알려진 한계

- 같은 계정에 비밀번호를 5번 틀리면 15분 잠긴다. 남이 일부러 잠글 수 있다(시연용으로 허용).
- MySQL 연결은 TLS지만 인증서를 검증하지 않는다(같은 호스트의 Docker 네트워크 안).
- 같은 사용자가 거의 동시에 스캔 시작을 두 번 누르면 한도 확인을 둘 다 통과할 수 있다(작업자는 어차피 하나씩 실행).
- 요청마다 DB 연결을 새로 연다(연결 풀 없음). 시연 규모에서는 문제없다.
