FROM rust:bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        bash-completion \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        file \
        gdb \
        git \
        make \
        openjdk-17-jdk-headless \
        pkg-config \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy rustfmt \
    && ln -sf /usr/bin/python3 /usr/local/bin/python

USER root

WORKDIR /workspace

CMD ["bash"]
