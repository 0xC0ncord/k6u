FROM docker.io/library/rust:1.99.0-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627 AS builder
COPY --chmod=0755 . /build
RUN apk update && \
    apk add clang lld && \
    export RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=lld" && \
    cd /build && \
    cargo build --release
RUN mkdir -p /out/libs && \
    mkdir -p /out/libs-root && \
    ldd /build/target/release/k6u && \
    ldd /build/target/release/k6u | grep -v 'linux-vdso.so' | awk '{print $(NF-1) " " $1}' | sort -u -k 1,1 | awk '{print "install", "-D", $1, (($2 ~ /^\//) ? "/out/libs-root" $2 : "/out/libs/" $2)}' | xargs -I {} sh -c {} && \
    ls -Rla /out/libs && \
    ls -Rla /out/libs-root

FROM scratch
COPY --chown=0:0 --chmod=0755 --from=builder /build/target/release/k6u /k6u
COPY --from=builder /out/libs-root/ /
COPY --from=builder /out/libs/ /lib/
ENV LD_LIBRARY_PATH=/lib

ENV LC_ALL=C
LABEL org.opencontainers.image.authors=me@concord.sh

USER 1000:1000

ENTRYPOINT ["/k6u"]
