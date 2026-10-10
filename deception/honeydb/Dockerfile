FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt \
    && useradd --create-home --uid 10002 honey
COPY app.py .
RUN chown -R honey:honey /app
USER honey
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "10", "--limit-request-line", "2048", "--limit-request-fields", "50", "--limit-request-field_size", "4096", "app:app"]
