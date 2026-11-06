# The binary is built outside the image with `just build-linux`, so the
# image holds one static file and no build toolchain.
# Base: gcr.io/distroless/static-debian13:nonroot, pinned by digest.
FROM gcr.io/distroless/static-debian13@sha256:448810357cc8e67b7208988abdba0f5ec3d3aebee0a5b13eb624979792cffc0f
COPY --chmod=0555 bin/tripline-linux-amd64 /tripline
USER 65532:65532
ENTRYPOINT ["/tripline"]
