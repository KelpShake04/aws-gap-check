# 대시보드 홈 + 계정 비용 조회 (2026-11-03)

교수님 의견: 사이트에서 계정 과금도 확인하면 좋겠다. 홈을 대시보드로 바꿔 "AWS 계정 관리" 도구에 가깝게 만든다.

## 범위
- 홈(`#/`)이 대시보드. 연결된 계정(ACTIVE)마다 카드 하나: 이번 달 사용액, 월말 예상, 지난달, 최근 30일 일별 막대, 서비스별 상위 5개, 최신 스캔 요약(심각도 개수)과 스캔 시작 버튼.
- 기존 화면(계정 연결, 스캔 목록·리포트)은 그대로. 상단 메뉴에 "대시보드" 추가.
- 안 한 것: 예산 알림 설정, 비용 이상 탐지, 리소스 시작·중지 같은 쓰기 기능(Role은 읽기 전용 유지).

## 설계
- API: `GET /api/connections/{id}/cost`(캐시), `POST /api/connections/{id}/cost/refresh`(새로고침, CSRF 헤더 필요). 소유자의 ACTIVE 연결만, 남의 연결은 404.
- `billing.py`: 스캔과 같은 방식으로 고객 Role을 AssumeRole(ExternalId) → Cost Explorer(us-east-1) 호출 2번(`GetCostAndUsage` DAILY·SERVICE별 + `GetCostForecast`).
- **비용 주의**: Cost Explorer API는 호출당 $0.01(조회 대상 계정에 청구). 결과를 메모리에 6시간 캐시하고, 새로고침은 5분에 한 번만 실제 호출한다. 오류 결과도 5분 캐시. 서버를 재시작하면 캐시가 비워진다.
- 금액은 크레딧·환불을 뺀 사용액(`RECORD_TYPE` 필터). 크레딧이 있는 계정도 실제 사용량이 보이게 하려는 선택이다.
- DB 스키마 변경 없음(기존 배포 볼륨 그대로).
- 권한: `infra/customer-role.yaml`에 인라인 정책 `ce:GetCostAndUsage`, `ce:GetCostForecast`(Resource `*`, 읽기 전용). 이미 연결된 계정은 **스택을 새 템플릿으로 업데이트**해야 비용이 보인다. 업데이트 전에는 화면에 안내 문구가 나온다(`NO_PERMISSION`). Cost Explorer를 한 번도 켜지 않은 계정은 콘솔 Billing에서 먼저 켜야 한다.
- 데모 모드(`DEMO_FIXTURE`)는 날짜에서 계산한 가짜 비용을 보여 준다.
- 프런트: 차트는 인라인 SVG(의존성 없음, CSP `style-src 'self'`라 인라인 style 없이 속성만 사용). 서버·스캔 값은 계속 textContent로만 넣는다.

## 알려진 한계
- 조회 한 번에 서버 전체가 한 줄로 기다린다(전역 잠금). 사용자 5명 규모 가정, 늘면 연결별 잠금.
- 비용 데이터는 AWS 쪽에서 최대 하루 정도 지연된다.
