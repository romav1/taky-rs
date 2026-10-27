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
# Run (the default command is the CoT server; DPS and CLI override the command).
# compose.yaml next to this file is the full example; packaging/docker/README.md has first-run steps.
#   docker run --rm -v taky-etc:/etc/taky -v taky-var:/var/taky IMAGE takyctl-rs setup ...  # CLI (once)
#   docker run -v taky-etc:/etc/taky -v taky-var:/var/taky -p 8089:8089 IMAGE                # taky-rs
#   docker run -v taky-etc:/etc/taky -v taky-var:/var/taky -p 8443:8443 IMAGE taky_dps-rs    # DPS
# (`setup` needs both volumes: it writes /etc/taky and creates /var/taky/dp-user.)

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
# One COPY per parent: COPY copies the *children* of the source directory with their metadata, so
# `/out/ /` would also re-own /etc and /var. This way only /etc/taky and /var/taky change.
COPY --from=skel --chown=65532:65532 /out/etc/ /etc/
COPY --from=skel --chown=65532:65532 /out/var/ /var/
COPY --chown=0:0 --chmod=0755 ${TARGETARCH}${TARGETVARIANT}/taky-rs ${TARGETARCH}${TARGETVARIANT}/taky_dps-rs ${TARGETARCH}${TARGETVARIANT}/takyctl-rs /usr/local/bin/
COPY --chown=0:0 --chmod=0644 ${TARGETARCH}${TARGETVARIANT}/LICENSE /usr/share/doc/taky-rs/LICENSE
ENV TZ=UTC
USER 65532:65532
WORKDIR /var/taky
VOLUME ["/etc/taky", "/var/taky"]
# CoT 8087 (TCP, or the TLS-mode monitor) / 8089 (TLS), DPS 8443 (TLS) / 8080 (plain): taky
# defaults; the effective ports come from taky.conf. No HEALTHCHECK here: one image runs three
# different commands and has no shell or HTTP client; compose.yaml checks the CoT server.
EXPOSE 8087 8089 8443 8080
# CMD (not ENTRYPOINT) so that `taky_dps-rs` / `takyctl-rs` can be given as the command.
CMD ["taky-rs"]
