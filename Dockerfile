# syntax=docker/dockerfile:1
# ---------- kairo-krl CLI container ----------
# Lightweight image with all Python deps pre-installed so every
# maintainer gets an identical environment for signing / revoking.

FROM python:3.11-slim AS base

# ---- system deps (for PyNaCl) ----
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- Python deps ----
COPY cli/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ---- project files ----
COPY . .

# Default entrypoint – pass CLI args after `docker run ...`
ENTRYPOINT ["python", "-m", "cli"]