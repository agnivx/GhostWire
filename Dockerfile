# Production Dockerfile for GhostWire
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and assets
COPY server.py .
COPY index.html .
COPY moderator.html .
COPY static/ ./static/

# Expose server port
EXPOSE 8000

# Start GhostWire server with Uvicorn (binds to dynamic $PORT provided by cloud hosts)
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000}"]
