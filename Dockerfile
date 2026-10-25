FROM docker.io/library/python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server/app ./app
RUN useradd --system --uid 10001 --no-create-home hostdeck && mkdir -p /data /run/secrets && chown hostdeck /data
USER hostdeck
VOLUME /data
ENV HOSTDECK_DB=/data/hostdeck.db
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/static/style.css',timeout=4)"
# --proxy-headers: схема https берётся от обратного прокси (нужна для Secure-cookie)
CMD ["python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--proxy-headers"]
