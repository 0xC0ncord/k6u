FROM alpine:latest@sha256:8a1f59ffb675680d47db6337b49d22281a139e9d709335b492be023728e11715 AS builder
COPY --chmod=0755 . /k6u
RUN apk upgrade && \
    apk add curl clang lld && \
    ( curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y ) && \
    source ~/.cargo/env && \
    cd /k6u && \
    RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=lld" cargo build --release

FROM alpine:latest@sha256:8a1f59ffb675680d47db6337b49d22281a139e9d709335b492be023728e11715
RUN apk upgrade --no-cache && \
    apk del --purge apk-tools
COPY --chown=0:0 --chmod=0755 --from=builder /k6u/target/release/k6u /k6u

ENV LC_ALL=C
LABEL org.opencontainers.image.authors=me@concord.sh

USER 1000:1000

ENTRYPOINT ["/k6u"]
