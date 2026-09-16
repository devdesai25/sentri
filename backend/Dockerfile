# Build stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Install poetry
RUN pip install --no-cache-dir poetry==1.5.1

# Copy poetry configuration
COPY pyproject.toml poetry.lock* /app/

# Configure poetry
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-dev --no-root

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN addgroup --system app \
    && adduser --system --group app

# Install production dependencies
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY ./app /app/app
# COPY ./alembic /app/alembic
# COPY ./alembic.ini /app/

# Set ownership to non-root user
RUN chown -R app:app /app

# Switch to non-root user
USER app

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]