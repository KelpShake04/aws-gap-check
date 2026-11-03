-- 이미 배포된 DB에 자동 점검 주기 열을 더한다(새로 만드는 DB는 db/init/01-schema.sql에 이미 있다).
-- 앱 계정은 ALTER 권한이 없으므로 root로 실행한다. 서버 안에서:
--   cd /opt/aws-gap-check && set -a && . ./.env && set +a
--   sudo docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql mysql -uroot gapcheck < db/migrations/2026-11-03-schedule.sql
-- 한 번만 실행한다(두 번째는 "Duplicate column name"으로 실패하고 데이터는 그대로다).
ALTER TABLE connections
  ADD COLUMN schedule VARCHAR(8) NOT NULL DEFAULT 'off' AFTER message;
