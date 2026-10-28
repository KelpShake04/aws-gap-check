#!/usr/bin/env bash
# 전체 테스트를 운영과 같은 환경에서 돌린다: 앱 이미지(Python 3.12, PyMySQL) + 테스트용 MySQL 8.4.
# MySQL은 db/init 스키마를 적용해 잠깐 띄우고 끝나면 지운다.
# 사용: scripts/test_with_db.sh [unittest 인자...]   예) scripts/test_with_db.sh tests.test_server -v
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -q -t aws-gap-check-app . >/dev/null

name="agc-testdb-$$"
password="$(openssl rand -hex 16)"
docker network create "$name" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1; docker network rm "$name" >/dev/null 2>&1' EXIT
docker run -d --rm --name "$name" --network "$name" \
  -e MYSQL_RANDOM_ROOT_PASSWORD=yes -e MYSQL_DATABASE=gapcheck \
  -e MYSQL_USER=gapcheck -e MYSQL_PASSWORD="$password" \
  -v "$PWD/db/init:/docker-entrypoint-initdb.d:ro" mysql:8.4.9 >/dev/null

# 초기화용 임시 서버(port: 0)가 스키마를 만든 뒤 3306으로 다시 뜬다
for _ in $(seq 90); do
  docker logs "$name" 2>&1 | grep -q "ready for connections.*port: 3306" && break
  sleep 2
done

docker run --rm --network "$name" -v "$PWD:/src:ro" -w /src \
  -e TEST_DB_HOST="$name" -e TEST_DB_PORT=3306 -e TEST_DB_PASSWORD="$password" \
  --entrypoint /home/prowler/.venv/bin/python aws-gap-check-app -m unittest "$@"
