# Contributing

## Before you start

- Read `aiwatch-build-spec.md` and the decisions in `docs/adr/`.
- Open an issue before a large change.

## Build and test

You need Go (see the version in `go.mod`), [just](https://github.com/casey/just) and Docker.

```sh
just test          # go mod verify, go vet, go test
just build         # static binary in bin/
just image-check   # build the image and run it non-root on a read-only filesystem
```

## Rules for changes

- Use the Go standard library. Ask in an issue before you add a dependency. Only `gopkg.in/yaml.v3` is pre-approved.
- Never log or store secret values, prompts or responses. Store metadata and fingerprints only.
- Never commit a credential, including a test key that looks real. Generate test values at runtime.
- Pin every GitHub Action to a full commit SHA. Give each workflow job the minimum permissions.
- Add tests with the code.
- Keep each commit to one concern. Use Conventional Commits: `type(scope): summary`.

## Security problems

Do not open a public issue. See `SECURITY.md`.
