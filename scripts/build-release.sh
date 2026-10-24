#!/usr/bin/env bash
# Reproducible release build. Usage: scripts/build-release.sh VERSION [OUTDIR]
# Writes tripline-<os>-<arch> binaries and SHA256SUMS to OUTDIR (default dist).
# CI and `just build-release` both call this script, so there is one build command.
set -euo pipefail

version=${1:?usage: build-release.sh VERSION [OUTDIR]}
out=${2:-dist}

rm -rf "$out"
mkdir -p "$out"
for target in linux/amd64 linux/arm64 darwin/arm64; do
  os=${target%/*}
  arch=${target#*/}
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X github.com/Parthkomalwad/tripline/internal/version.Version=${version}" \
    -o "$out/tripline-$os-$arch" ./cmd/tripline
done
(cd "$out" && sha256sum --text tripline-* > SHA256SUMS)
