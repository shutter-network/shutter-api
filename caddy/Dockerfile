FROM caddy:2.10.0-builder AS builder

RUN xcaddy build \
    --with github.com/lucaslorentz/caddy-docker-proxy/v2 \
    --with github.com/mholt/caddy-ratelimit


FROM caddy:2.10.0

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

ENTRYPOINT /usr/bin/caddy

CMD ["docker-proxy"]
