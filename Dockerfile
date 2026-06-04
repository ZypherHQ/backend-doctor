# syntax=docker/dockerfile:1

FROM rust:1.93.0-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --locked --release -p backend-doctor-cli

FROM debian:bookworm-slim AS runtime

RUN groupadd --system backend-doctor \
  && useradd --system --gid backend-doctor --home-dir /nonexistent --shell /usr/sbin/nologin backend-doctor

COPY --from=builder /app/target/release/backend-doctor /usr/local/bin/backend-doctor

USER backend-doctor:backend-doctor
WORKDIR /work

ENTRYPOINT ["backend-doctor"]
CMD ["--help"]
HEALTHCHECK --interval=5m --timeout=10s --start-period=5s --retries=1 CMD backend-doctor --help >/dev/null || exit 1
