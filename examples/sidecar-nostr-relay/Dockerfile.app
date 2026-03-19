# strfry: official multi-arch image (linux/amd64 + linux/arm64)
# replaces the nostr-rs-relay source build which was amd64-only.
#
# IMPORTANT: use alpine (same musl-based libc as the strfry source image) as
# the final stage.  Copying the strfry binary into a glibc-based image such as
# debian:bookworm-slim causes "not found" at exec time because the musl dynamic
# linker (/lib/ld-musl-*.so.1) and its shared libraries are absent there.
FROM ghcr.io/hoytech/strfry:latest AS strfry

FROM alpine:3.18

RUN apk add --no-cache nginx

# nginx: reverse proxy port 80 (IPv4 + IPv6) → strfry 127.0.0.1:7777
RUN printf 'server {\n\
    listen 80;\n\
    listen [::]:80;\n\
    location / {\n\
        proxy_pass http://127.0.0.1:7777;\n\
        proxy_http_version 1.1;\n\
        proxy_read_timeout 1d;\n\
        proxy_send_timeout 1d;\n\
        proxy_set_header Upgrade $http_upgrade;\n\
        proxy_set_header Connection "Upgrade";\n\
        proxy_set_header Host $host;\n\
    }\n\
}\n' > /etc/nginx/http.d/nostr-relay.conf && \
    rm -f /etc/nginx/http.d/default.conf

COPY --from=strfry /app/strfry /usr/local/bin/strfry
# Copy musl shared libraries that strfry depends on from the source image.
COPY --from=strfry \
    /usr/lib/liblmdb.so.0 \
    /usr/lib/libcrypto.so.50 \
    /usr/lib/libssl.so.53 \
    /usr/lib/libsecp256k1.so.2 \
    /usr/lib/libzstd.so.1 \
    /usr/lib/libstdc++.so.6 \
    /usr/lib/libgcc_s.so.1 \
    /usr/lib/
COPY --from=strfry /lib/libz.so.1 /lib/

WORKDIR /usr/src/app
RUN mkdir -p strfry-db

RUN printf '#!/bin/sh\nnginx\nexec strfry relay\n' > /entrypoint-app.sh && \
    chmod +x /entrypoint-app.sh

ENTRYPOINT ["/entrypoint-app.sh"]
