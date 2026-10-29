-- aws-gap-check 스키마 (MySQL 8.4). mysql 컨테이너가 데이터 볼륨을 처음 만들 때 한 번만 실행한다.
-- 스키마를 바꾸면 볼륨을 지우고 다시 만든다(시연용, 마이그레이션 도구 없음).
-- 시각은 모두 UTC. 사용자 데이터 테이블은 모두 user_id를 키에 포함한다(IDOR 방지).

CREATE TABLE users (
  id                   CHAR(36)     NOT NULL,
  email                VARCHAR(254) NOT NULL,
  password_hash        VARCHAR(255) NOT NULL,
  must_change_password BOOLEAN      NOT NULL DEFAULT TRUE,
  failed_logins        INT          NOT NULL DEFAULT 0,
  locked_until         DATETIME     NULL,
  created_at           DATETIME     NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email)
) DEFAULT CHARSET = utf8mb4;

-- 세션 토큰 원문은 저장하지 않고 SHA-256만 둔다(DB가 새도 쿠키를 만들 수 없게)
CREATE TABLE sessions (
  token_hash CHAR(64) NOT NULL,
  user_id    CHAR(36) NOT NULL,
  created_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL,
  PRIMARY KEY (token_hash),
  KEY ix_sessions_user (user_id),
  KEY ix_sessions_expires (expires_at),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) DEFAULT CHARSET = utf8mb4;

CREATE TABLE connections (
  user_id     CHAR(36)     NOT NULL,
  id          CHAR(16)     NOT NULL,
  external_id CHAR(36)     NOT NULL,
  account_id  CHAR(12)     NULL,
  status      VARCHAR(16)  NOT NULL,
  message     VARCHAR(500) NOT NULL DEFAULT '',
  created_at  DATETIME     NOT NULL,
  verified_at DATETIME     NULL,
  PRIMARY KEY (user_id, id),
  UNIQUE KEY uq_connections_external_id (external_id),
  CONSTRAINT fk_connections_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) DEFAULT CHARSET = utf8mb4;

-- 연결을 지워도 스캔 기록은 남긴다(일일 한도 계산). 그래서 connections로 가는 외래키는 두지 않는다.
CREATE TABLE scans (
  user_id       CHAR(36)     NOT NULL,
  id            CHAR(23)     NOT NULL,
  connection_id CHAR(16)     NOT NULL,
  account_id    CHAR(12)     NOT NULL,
  status        VARCHAR(16)  NOT NULL,
  counts        JSON         NOT NULL,
  summary       JSON         NULL,
  error         VARCHAR(500) NOT NULL DEFAULT '',
  created_at    DATETIME     NOT NULL,
  updated_at    DATETIME     NOT NULL,
  expires_at    BIGINT       NOT NULL,
  PRIMARY KEY (user_id, id),
  KEY ix_scans_queue (status, id),
  KEY ix_scans_expires (expires_at),
  CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) DEFAULT CHARSET = utf8mb4;

CREATE TABLE findings (
  user_id        CHAR(36)     NOT NULL,
  scan_id        CHAR(23)     NOT NULL,
  check_id       VARCHAR(120) NOT NULL,
  severity_rank  TINYINT      NOT NULL,
  severity       VARCHAR(20)  NOT NULL,
  title          VARCHAR(300) NOT NULL,
  service        VARCHAR(60)  NOT NULL,
  resource_type  VARCHAR(100) NOT NULL,
  description    TEXT         NOT NULL,
  risk           TEXT         NOT NULL,
  recommendation TEXT         NOT NULL,
  reference_urls JSON         NOT NULL,
  resources      JSON         NOT NULL,
  regions        JSON         NOT NULL,
  total_count    INT          NOT NULL,
  explanation    JSON         NULL,
  explain_source VARCHAR(10)  NOT NULL,
  expires_at     BIGINT       NOT NULL,
  PRIMARY KEY (user_id, scan_id, check_id),
  CONSTRAINT fk_findings_scan FOREIGN KEY (user_id, scan_id) REFERENCES scans (user_id, id) ON DELETE CASCADE
) DEFAULT CHARSET = utf8mb4;

-- 고객 데이터가 없는 일반 해설이라 사용자 사이에 공유한다(Gemini 호출 절약)
CREATE TABLE explanations (
  check_id       VARCHAR(120) NOT NULL,
  prompt_version VARCHAR(16)  NOT NULL,
  model          VARCHAR(100) NOT NULL,
  explanation    JSON         NOT NULL,
  PRIMARY KEY (check_id, prompt_version, model)
) DEFAULT CHARSET = utf8mb4;

-- 앱 계정(gapcheck)은 데이터 읽기·쓰기만 한다. 테이블 생성·삭제·권한 변경은 못 한다.
REVOKE ALL PRIVILEGES ON gapcheck.* FROM 'gapcheck'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON gapcheck.* TO 'gapcheck'@'%';
