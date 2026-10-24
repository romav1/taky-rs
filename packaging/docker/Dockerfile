# syntax=docker/dockerfile:1
# taky-rs multi-arch image (ADR-007): built from ready-made musl binaries, no compiling under qemu.
#
# Build context: dist/docker/ as produced by scripts/build-all.sh for the musl targets:
#   dist/docker/amd64/   <- x86_64-unknown-linux-musl
#   dist/docker/arm64/   <- aarch64-unknown-linux-musl
#   dist/docker/armv7/   <- armv7-unknown-linux-musleabihf
# Example:
#   docker buildx build -f packaging/docker/Dockerfile \
#     --platform linux/amd64,linux/arm64,linux/arm/v7 -t taky-rs:dev dist/docker
#
# Run (the default command is the CoT server; DPS and CLI override the command):
#   docker run -v taky-etc:/etc/taky -v taky-var:/var/taky IMAGE                 # taky-rs
#   docker run -v taky-etc:/etc/taky -v taky-var:/var/taky IMAGE taky_dps-rs     # DPS
#   docker run --rm -v taky-etc:/etc/taky IMAGE takyctl-rs setup ...              # CLI

# Directory skeleton owned by the non-root user (distroless has no shell to mkdir/chown).
# Runs on the build platform: nothing here is architecture-specific.
FROM --platform=$BUILDPLATFORM busybox:1.36.1-musl AS skel
RUN mkdir -p /out/etc/taky /out/var/taky \
 && chown -R 65532:65532 /out/etc/taky /out/var/taky \
 && chmod 0750 /out/etc/taky /out/var/taky

# distroless/static: CA certificates, tzdata, /etc/passwd with nonroot (65532); no shell.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETARCH
ARG TARGETVARIANT
LABEL org.opencontainers.image.title="taky-rs" \
      org.opencontainers.image.description="TAK server (CoT router + Data Package Server), Rust port of taky" \
      org.opencontainers.image.licenses="MIT"
COPY --from=skel --chown=65532:65532 /out/ /
COPY --chown=0:0 --chmod=0755 ${TARGETARCH}${TARGETVARIANT}/taky-rs ${TARGETARCH}${TARGETVARIANT}/taky_dps-rs ${TARGETARCH}${TARGETVARIANT}/takyctl-rs /usr/local/bin/
COPY --chown=0:0 --chmod=0644 ${TARGETARCH}${TARGETVARIANT}/LICENSE /usr/share/doc/taky-rs/LICENSE
ENV TZ=UTC
USER 65532:65532
WORKDIR /var/taky
VOLUME ["/etc/taky", "/var/taky"]
# CoT 8087 (TCP) / 8089 (TLS), DPS 8443 (taky defaults; the effective ports come from taky.conf).
EXPOSE 8087 8089 8443
# CMD (not ENTRYPOINT) so that `taky_dps-rs` / `takyctl-rs` can be given as the command.
CMD ["taky-rs"]
