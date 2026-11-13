# The binary is built outside the image with `just build-linux`, so the
# image holds one static file and no build toolchain.
# Base: gcr.io/distroless/static-debian13:nonroot, pinned by digest.
FROM gcr.io/distroless/static-debian13@sha256:1a64f46364620465ef9e9a8f5413757dfdf22695e050bbfd7303eeaf17a59383
COPY --chmod=0555 bin/tripline-linux-amd64 /tripline
USER 65532:65532
ENTRYPOINT ["/tripline"]
