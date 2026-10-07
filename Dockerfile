# Build with `just images`.

ARG COMPONENT

FROM alpine AS chmodder
ARG TARGETARCH
ARG COMPONENT
ARG FEATURE
COPY /artifacts/binaries-$TARGETARCH$FEATURE/$COMPONENT /app/$COMPONENT
RUN chmod +x /app/*

FROM samply/beam-proxy:develop AS proxy

FROM gcr.io/distroless/cc-debian12 AS runtime-central
COPY --from=chmodder /app/central /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/central"]

FROM gcr.io/distroless/cc-debian13:debug AS runtime-local
COPY --from=proxy /usr/local/bin/beam-proxy /usr/local/bin/proxy
COPY --from=chmodder /app/local /usr/local/bin/

ENV APP_secret-sync_KEY=NotSecret
ENV RUST_LOG=warn
ENTRYPOINT ["sh", "-c", "/usr/local/bin/proxy & /usr/local/bin/local $@", "_"]

FROM runtime-${COMPONENT}
