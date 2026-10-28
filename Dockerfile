# 앱 이미지: Prowler 공식 이미지(버전 고정) 위에 앱 코드만 얹는다. Prowler와 boto3는 그 이미지의 venv에 있다.

# 1단계: Prowler 이미지에는 pip가 없어서, PyMySQL만 해시를 확인해 따로 받아 둔다
FROM python:3.12-slim AS deps
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --no-deps --target /vendor -r /tmp/requirements.txt

FROM public.ecr.aws/prowler-cloud/prowler:5.46.0
USER root
RUN mkdir -p /data && chown prowler /data
COPY --from=deps /vendor /app/vendor
COPY backend/gapcheck /app/gapcheck
COPY scanner/run_scan.py scanner/core-checks.json /app/scanner/
COPY frontend/index.html frontend/app.js frontend/api.js frontend/auth.js frontend/style.css /app/frontend/
COPY infra/customer-role.yaml /app/customer-role.yaml
# 데모 모드(DEMO_FIXTURE)용 사전 스캔 결과. 실제 계정 정보는 없다(scripts/sanitize_ocsf.py로 정리한 표본).
COPY tests/fixtures/ocsf-sample.json /app/demo/ocsf-sample.json

# 앱 코드는 root 소유(읽기 전용)이고, 프로세스는 비루트 사용자로 /data에만 쓴다
USER prowler
WORKDIR /app
ENV PATH=/home/prowler/.venv/bin:$PATH PYTHONPATH=/app:/app/scanner:/app/vendor \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
ENTRYPOINT ["/home/prowler/.venv/bin/python", "-m", "gapcheck.app"]
