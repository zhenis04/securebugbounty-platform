FROM python:3.11-slim

# Security: run as non-root
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Install dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py database.py ./
COPY dist/ ./dist/

# Create data directory for DB
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

# Environment
ENV DB_PATH=/app/data/database.db
ENV SECRET_KEY=change-me-in-production
ENV DEBUG=false
ENV JWT_EXPIRY_HOURS=24

EXPOSE 5000

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "app:app"]
