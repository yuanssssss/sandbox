FROM rust:bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        make \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY configs ./configs
COPY examples ./examples
COPY scripts ./scripts
COPY README.md ./

RUN cargo build --release -p sandbox-cli

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
    PATH=/opt/sandbox/bin:${PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        make \
        openjdk-17-jdk-headless \
        pkg-config \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && mkdir -p /opt/sandbox/bin /app

COPY --from=builder /build/target/release/sandbox-cli /opt/sandbox/bin/sandbox-cli
COPY configs /app/configs
COPY examples /app/examples
COPY README.md /app/README.md

WORKDIR /app

EXPOSE 3000

ENTRYPOINT ["tini", "--", "sandbox-cli"]
CMD ["serve", "--listen", "0.0.0.0:3000"]
