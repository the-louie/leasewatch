FROM python:3.12-alpine
# fixed ids, so a bind-mounted data/ can be chowned before the first start (chown 10001:10001 data/)
RUN apk add --no-cache tzdata && addgroup -S -g 10001 app && adduser -S -u 10001 -G app -h /app app && mkdir -p /data && chown 10001:10001 /data
WORKDIR /app
# the only non-stdlib dependency: pysnmp (SNMPv3 to the switch) and its crypto backend
COPY requirements.txt /app/
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt
COPY leasewatch/ /app/leasewatch/
USER 10001:10001
ENV DATA_DIR=/data LISTEN_HOST=0.0.0.0 LISTEN_PORT=8080 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
# liveness only, not /healthz: fw1 being unreachable is not a reason to call the container unhealthy.
# 200 or 401 (AUTH_USER set) both mean the server answers
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=5 CMD ["python", "-c", "import sys,urllib.request as r,urllib.error as e\ntry: r.urlopen('http://127.0.0.1:8080/api/stats',timeout=4)\nexcept e.HTTPError as x: sys.exit(x.code!=401)\nexcept Exception: sys.exit(1)"]
CMD ["python", "-m", "leasewatch"]
