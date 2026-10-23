# The binary is built outside the image with `just build-linux`, so the
# image holds one static file and no build toolchain.
# Base: gcr.io/distroless/static-debian13:nonroot, pinned by digest.
FROM gcr.io/distroless/static-debian13@sha256:034df5c1737e8241f6ed6423a12e720ee0f6d6f088609ee172f98f6f2166ef5d
COPY --chmod=0555 bin/tripline-linux-amd64 /tripline
USER 65532:65532
ENTRYPOINT ["/tripline"]
