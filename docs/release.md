# Release and verification

Every release is built in CI from a version tag. Every binary and the image are signed with Sigstore cosign. Every release has an SBOM and a build provenance attestation.

## Build command

The release binaries are reproducible. This command builds them:

```sh
just build-release v1.2.3
```

`just` calls `scripts/build-release.sh v1.2.3 dist`. For each of linux/amd64, linux/arm64 and darwin/arm64, the script runs this command:

```sh
CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build -trimpath -buildvcs=false \
  -ldflags="-s -w -X github.com/Parthkomalwad/tripline/internal/version.Version=v1.2.3" \
  -o dist/tripline-<os>-<arch> ./cmd/tripline
```

The script then writes `dist/SHA256SUMS`. The Go version comes from `go.mod`. Use the same Go toolchain as the release, or the checksums differ.

CI job `reproducible` builds twice on two clean runners and fails if the two `SHA256SUMS` files differ.

## Cut a release (maintainers)

1. Merge all changes to `main`. Wait for CI to pass.
2. Create a signed tag on the commit: `git tag -s v1.2.3 -m v1.2.3`.
3. Push the tag: `git push origin v1.2.3`.
4. The `release` workflow runs the `build` job. Then the `release` job waits for approval.
5. A second maintainer opens the workflow run and reviews it. The tag creator cannot approve their own run. The second maintainer approves the `release` environment.
6. The job signs the files, pushes the image and creates the GitHub release.
7. Check that the release notes show the image digest.

## Verify a release (users)

Set these values first:

```sh
TAG=v1.2.3
REPO=Parthkomalwad/tripline
IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"
ISSUER=https://token.actions.githubusercontent.com
```

Check the checksums. Download the binaries and `SHA256SUMS`, then run:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

Verify the signature of a binary:

```sh
cosign verify-blob tripline-linux-amd64 \
  --bundle tripline-linux-amd64.sigstore.json \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
```

Verify the build provenance of a binary:

```sh
gh attestation verify tripline-linux-amd64 --repo "$REPO"
```

Verify the image. Use the digest from the release notes:

```sh
IMAGE=ghcr.io/parthkomalwad/tripline@sha256:<digest>
cosign verify "$IMAGE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
gh attestation verify "oci://$IMAGE" --repo "$REPO"
```

Read the SBOM in `tripline-<os>-<arch>.spdx.json`. It is an SPDX 2.3 JSON document. It lists the Go modules that are in the binary.

## Reproduce the build

1. Check out the release tag: `git checkout v1.2.3`.
2. Install the Go version that `go.mod` names.
3. Run `just build-release v1.2.3 /tmp/repro`.
4. Compare: `diff /tmp/repro/SHA256SUMS SHA256SUMS`.

The files must be identical. If they differ, do not deploy the release and report it as in `SECURITY.md`.

## Deploy

- Deploy the image by digest, never by tag. A tag can move. A digest cannot.
- Wait 3 days before you adopt a new release. Use the delay to let others find problems.
- Do not wait if the release is a security fix.

## Repository settings (owner)

- Create the environment `release`. Add at least two required reviewers. Turn on "Prevent self-review".
- Limit the `release` environment to deployment tags that match `v*`.
- Add a tag protection rule (a ruleset) for `v*`. Block deletion and force updates. Allow only maintainers to create these tags.
- Keep the default workflow token permission at read-only.
- Make the `tripline` package public after the first push, or keep it private and grant read access to users.
