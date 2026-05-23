FROM python:3.12-slim

WORKDIR /app

# Install minimal tools for debugging inside container if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY logger.py /app/logger.py

# Run unbuffered so logs appear immediately in `docker compose logs`
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "-u", "/app/logger.py"]