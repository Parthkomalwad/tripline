# 3. Release signing and provenance

Date: 2026-10-24
Status: accepted

## Context

A release is the main path by which an attacker could reach every user. Users must be able to check who built a file, from which source, and that a second person approved it.

## Decision

- Build releases only in CI, in `.github/workflows/release.yml`, on a pushed `v*` tag.
- Split the work in two jobs. The `build` job has `contents: read`. The `release` job runs in the `release` environment. A second maintainer must approve it.
- Build with one script, `scripts/build-release.sh`. It sets `CGO_ENABLED=0`, `-trimpath` and `-buildvcs=false`. `just build-release` and CI both call it.
- Prove reproducibility in CI. Two jobs on separate runners build the binaries. A third job fails if the `SHA256SUMS` files differ.
- Sign each binary with `cosign sign-blob` (keyless, GitHub OIDC) and write a `.sigstore.json` bundle.
- Push the image to `ghcr.io` with the plain `docker` CLI. Sign it by digest with `cosign sign`. Never sign a tag.
- Attest build provenance with `actions/attest-build-provenance`, pinned to a full commit SHA. It is first-party GitHub code. Verify with `gh attestation verify`.
- Write an SBOM for each binary. A stdlib-only Go program, `internal/tools/sbom`, reads the module list from the binary with `debug/buildinfo` and writes SPDX 2.3 JSON. No third-party SBOM tool is used.
- Allow only these actions: checkout, setup-go, upload-artifact, download-artifact, cosign-installer and attest-build-provenance. Do not use `docker/*` actions.
- Give the token only to `docker login`, `gh release create` and the first-party attest action.
- Tell users in `docs/release.md` to verify, deploy by digest and wait 3 days unless the release is a security fix.

## Consequences

- An attacker needs to push a tag and also get approval from a second maintainer.
- Users can verify a file with the certificate identity of `release.yml` and the GitHub OIDC issuer. They need no key.
- Signatures and attestations use the public Sigstore log. They show the repository name and workflow path.
- Image builds are not bit-for-bit reproducible. The binary inside is. Users compare binary checksums.
- The SBOM lists modules only. License fields are `NOASSERTION`. Add license data later if users ask.
- The owner must configure the `release` environment reviewers and tag protection in the repository settings.
