# The binary is built outside the image with `just build-linux`, so the
# image holds one static file and no build toolchain.
# Base: gcr.io/distroless/static-debian13:nonroot, pinned by digest.
FROM gcr.io/distroless/static-debian13@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
COPY --chmod=0555 bin/tripline-linux-amd64 /tripline
USER 65532:65532
ENTRYPOINT ["/tripline"]
