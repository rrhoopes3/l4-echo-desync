FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    tcpdump \
    iptables \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# The generator and any helper scripts live in /app
# We also bind-mount ./scripts at runtime for easy iteration
COPY generator.py /app/generator.py
COPY raw_tcp.py   /app/raw_tcp.py

ENV PYTHONUNBUFFERED=1

# Run as root so we can do raw sockets + iptables + tc in Phase 2+
USER root

CMD ["python", "-u", "/app/generator.py", "--help"]