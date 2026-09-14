# 多阶段构建：Rust 编译 → 精简运行镜像
FROM rust:1.82-slim AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY protocol-kit ./protocol-kit
COPY server ./server
RUN cargo build --release -p hypercast-rendezvous

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/hypercast-rendezvous /usr/local/bin/hypercast-rendezvous
# 默认监听 8443（容器内），对外地址与端口由环境变量覆盖
ENV HYPERCAST_RELAY_BIND=0.0.0.0:8443
EXPOSE 8443
ENTRYPOINT ["hypercast-rendezvous"]
