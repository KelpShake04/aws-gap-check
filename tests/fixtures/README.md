# 테스트 fixture

- `ocsf-sample.json`: 합성 Prowler OCSF 결과(Prowler 5.46.0 `lib/outputs/ocsf/ocsf.py` 매핑 기준). 계정 ID와 리소스 이름은 가짜다. 태그(`resources[].labels`)에 프롬프트 인젝션 문구와 HTML 조각을 넣어, 이 값들이 Gemini 프롬프트나 화면 HTML로 흘러가지 않는지 테스트하는 데 쓴다.
- 실제 스캔 결과를 추가할 때는 `scripts/sanitize_ocsf.py`로 익명화하고, 사람이 내용을 직접 확인한 뒤 커밋한다.
