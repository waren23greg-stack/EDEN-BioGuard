# Multi-stage build for EDEN-BioGuard
# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gdal-bin \
    libgdal-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

LABEL maintainer="EDEN-BioGuard Team <weren23greg@example.com>"
LABEL description="Autonomous AI ecosystem for planetary-scale biodiversity restoration"

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdal-bin \
    libgdal32 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Set PATH to include user site packages
ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    GDAL_DATA=/usr/share/gdal

# Create non-root user
RUN useradd -m -u 1000 eden && chown -R eden:eden /app

# Copy application code
COPY --chown=eden:eden . .

# Switch to non-root user
USER eden

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose ports
EXPOSE 8000 8080 9000

# Default command: run communications API
CMD ["python", "-m", "uvicorn", "src.api.communications_api:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
