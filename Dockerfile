# The binary is built outside the image with `just build-linux`, so the
# image holds one static file and no build toolchain.
# Base: gcr.io/distroless/static-debian13:nonroot, pinned by digest.
FROM gcr.io/distroless/static-debian13@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a
COPY --chmod=0555 bin/tripline-linux-amd64 /tripline
USER 65532:65532
ENTRYPOINT ["/tripline"]
