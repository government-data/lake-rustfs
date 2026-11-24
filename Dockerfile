# The lake admin adapter's image (core decision 0078, step 13, moved here
# with the adapter): `lake-rustfs-admin` serving lake-admin/1 with mTLS, on a
# distroless, non-root base. CI builds it and does not push it; a `v*` tag
# pushes it to quality-data/lake-rustfs/admin (release.yml).
#
# Build context is the repository's root:
#   docker build -t lake-rustfs-admin .
#
# It keeps no state or secret: its only files are the node agent's `ca.crt`
# and `machine.pem`, mounted read-only at QD_LAKE_ADMIN_TLS_DIR
# (/run/qd-node). It listens on QD_LAKE_ADMIN_ADDR (0.0.0.0:9020).

FROM rust:1.90-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json -p lake-rustfs-admin
COPY . .
RUN cargo build --release --locked -p lake-rustfs-admin

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=builder /app/target/release/lake-rustfs-admin /usr/local/bin/lake-rustfs-admin
USER nonroot
EXPOSE 9020
ENTRYPOINT ["/usr/local/bin/lake-rustfs-admin"]
