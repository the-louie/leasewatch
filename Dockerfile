FROM python:3.12-alpine
RUN apk add --no-cache tzdata && addgroup -S app && adduser -S -G app -h /app app && mkdir -p /data && chown app:app /data
WORKDIR /app
# the only non-stdlib dependency: pysnmp (SNMPv3 to the switch) and its crypto backend
COPY requirements.txt /app/
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt
COPY leasewatch/ /app/leasewatch/
USER app
ENV DATA_DIR=/data LISTEN_HOST=0.0.0.0 LISTEN_PORT=8080 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
# liveness only, not /healthz: fw1 being unreachable is not a reason to call the container unhealthy
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=5 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/stats', timeout=4).status==200 else 1)" || exit 1
CMD ["python", "-m", "leasewatch"]
