# MIT License
#
# Copyright (c) 2024-2026 Journey of Life
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# =============================================================================
# Multi-stage build for jol-auth
# Stage 1: Build dependencies in a full image
# Stage 2: Run in a minimal image as non-root user
# =============================================================================

# --- Stage 1: Builder ---
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md alembic.ini ./
COPY app/ ./app/
COPY src/ ./src/

RUN pip install --no-cache-dir --user -e .

# --- Stage 2: Runtime ---
FROM python:3.12-slim AS runtime

# Install only runtime dependencies (no gcc)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r jolauth && useradd -r -g jolauth -d /app -s /sbin/nologin jolauth

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/jolauth/.local

# Copy application code
COPY --from=builder /build/pyproject.toml /build/README.md /build/alembic.ini ./
COPY --from=builder /build/app/ ./app/
COPY --from=builder /build/src/ ./src/

# Copy entrypoint script
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set ownership
RUN chown -R jolauth:jolauth /app

# Switch to non-root user
USER jolauth

# Add local packages to PATH
ENV PATH=/home/jolauth/.local/bin:$PATH
ENV PYTHONPATH=/app

EXPOSE 8000

# Health check (non-root compatible)
HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Entrypoint: run migrations then start server
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
