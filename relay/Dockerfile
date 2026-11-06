# Muse-Link relay (MVP). NOT deployed yet: staged for the owner's
# separate deployment go (design doc section 15, item 2).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends gnupg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY common/ /app/common/
COPY relay/server.py /app/relay/server.py
COPY relay/link /app/relay/link

ENV MUSELINK_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8931

# Server state (identities, token hashes, ledger, ciphertext queue, and
# the relay's own keypair) lives only in /data. Agent private keys never
# enter this image or container.
# Layout mirrors the repo (relay/ beside common/) because server.py and
# link locate gpgutil at ../common relative to their own directory.
CMD ["python3", "/app/relay/server.py", "--host", "0.0.0.0", "--port", "8931"]
