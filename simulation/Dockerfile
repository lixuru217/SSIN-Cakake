FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pyyaml

COPY protocols /app/protocols
COPY simulation/app /app/app

ENV PYTHONPATH=/app:/app/protocols

CMD ["sleep", "infinity"]
