#!/usr/bin/env bash
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

# Bootstrap the local development environment.
set -euo pipefail

echo "==> Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "==> Installing development dependencies..."
pip install -e ".[dev]"

echo "==> Installing pre-commit hooks..."
pre-commit install

echo "==> Copying .env.example to .env (if not present)..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "    .env created — please populate secrets before starting the service."
else
    echo "    .env already exists, skipping."
fi

echo "==> Starting Docker services..."
docker compose up -d

echo "==> Running database migrations..."
alembic upgrade head

echo ""
echo "Bootstrap complete. Start the development server with:"
echo "  uvicorn app.main:app --reload"
