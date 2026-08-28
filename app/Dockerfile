FROM python:3.12-slim-bookworm

RUN groupadd --gid 10001 app \
    && useradd \
       --uid 10001 \
       --gid 10001 \
       --no-create-home \
       --shell /usr/sbin/nologin \
       app

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install \
    --no-cache-dir \
    -r requirements.txt

COPY --chown=10001:10001 app.py .

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

USER 10001:10001

CMD ["python", "app.py"]
