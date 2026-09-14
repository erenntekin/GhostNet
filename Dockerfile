FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ api/
COPY ingestion/ ingestion/

# Command is supplied per-service in docker-compose.yml (api vs live-replay
# run the same image, different entrypoint) -- no CMD here on purpose.
