FROM python:3.12-slim

WORKDIR /app
COPY stun_server.py /app/stun_server.py

EXPOSE 3478/udp

CMD ["python3", "/app/stun_server.py"]
