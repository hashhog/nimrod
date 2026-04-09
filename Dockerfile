# Stage 1: Build
FROM nimlang/nim:2.0.2 AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    librocksdb-dev && \
    rm -rf /var/lib/apt/lists/*
COPY . .
RUN nimble setup -y && nimble build -d:release

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates librocksdb-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/bin/nimrod /usr/local/bin/nimrod
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["nimrod"]
CMD ["-d", "/data", "-n", "mainnet", "start"]
