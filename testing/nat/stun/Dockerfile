# Pinned by digest (python:3.12-slim as of 2026-11-16); testing/base-images.env
# says why, and how to move a pin.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

WORKDIR /app
COPY stun_server.py /app/stun_server.py

EXPOSE 3478/udp

CMD ["python3", "/app/stun_server.py"]
