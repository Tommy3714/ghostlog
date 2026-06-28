FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (cache layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[prod]"

# Copy source
COPY ghostlog/ ghostlog/

# Create data directory
RUN mkdir -p /data
ENV GHOSTLOG_DB=/data/ghostlog.db

EXPOSE 8000

CMD ["uvicorn", "ghostlog.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
