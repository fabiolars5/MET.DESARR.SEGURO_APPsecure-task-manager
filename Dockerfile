FROM python:3.12-slim

WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 3000

CMD ["python", "app.py"]