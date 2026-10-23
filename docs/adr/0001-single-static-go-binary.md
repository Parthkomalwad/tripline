# 1. Single static Go binary in a distroless image

Date: 2026-10-24
Status: accepted

## Context

tripline is a security tool. A large dependency tree or a heavy image would make it a supply-chain target.

## Decision

- Write tripline in Go as one binary with subcommands.
- Build with `CGO_ENABLED=0 -trimpath -buildvcs=false`, so the binary is static and the build does not depend on the local path.
- Build the binary outside the image. Copy it into `gcr.io/distroless/static-debian13`, pinned by digest, with user 65532. The image has no shell and no build toolchain.
- Use the standard library by default. Only `gopkg.in/yaml.v3` is pre-approved.
- Use `just` for all project commands, not `make`.
- Sign CI test artifacts keyless with cosign, only on pushes to `main`. Pull requests from forks get no OIDC token.

## Consequences

- The image cannot be debugged with a shell. Use the `version` command and the logs.
- The CI double build that checks reproducibility comes in M4.
