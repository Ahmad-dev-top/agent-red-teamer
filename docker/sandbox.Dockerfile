# Hardened sandbox for running an UNTRUSTED target agent + its mock tools.
# Build:  docker build -t rfa-sandbox:latest -f docker/sandbox.Dockerfile .
#
# Runtime isolation (no network by default or an internal-only bridge, dropped
# caps, non-root, read-only rootfs, resource caps) is applied by SandboxRunner at
# `docker run` time. The image just carries the runtime to host demo agents and
# mock tool services.

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Runtime for demo agents + mock FastAPI tool services.
RUN pip install --no-cache-dir fastapi uvicorn httpx pydantic

# Non-root runtime user (UID/GID match SandboxRunner --user=1000:1000).
RUN groupadd -g 1000 sbx && useradd -m -u 1000 -g 1000 sbx
USER 1000:1000
WORKDIR /work

CMD ["bash"]
