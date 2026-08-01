# Stage 1: Build
FROM nimlang/nim:2.2.8 AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsecp256k1-dev librocksdb-dev libsnappy-dev liblz4-dev \
    libsqlite3-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*
COPY . .
RUN nimble setup -y && nimble build -d:release

# Stage 2: Runtime
# Must match the builder's Debian release (nimlang/nim:2.2.8 is trixie-based);
# bookworm ships libsecp256k1.so.1 while trixie links libsecp256k1.so.2.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libsecp256k1-dev librocksdb-dev libsnappy-dev liblz4-dev \
    libsqlite3-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/bin/nimrod /usr/local/bin/nimrod
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["nimrod"]
CMD ["-d", "/data", "-n", "mainnet", "start"]
