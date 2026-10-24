# tripline

> Assume something gets in. Make sure it leaves with nothing.

tripline is an open-source monitor for self-hosted AI systems: AI gateways, agents, MCP servers and coding agents. It watches for the steps that every attack must take after it gets in: secret access, data leaving the system and stolen key use. It places decoy files that nobody should use, and it checks its own rules with scheduled self-tests. It runs watch-only by default.

**Status:** pre-release. There is no tagged release and no published image. The CLI and the config format can change. Do not rely on it as your only control.

## Quickstart (Level 1)

Level 1 runs the watcher, plants decoys and serves a trap. It does not sit in your traffic path.

You need Go (see `go.mod` for the version) and [just](https://github.com/casey/just).

```sh
git clone https://github.com/Parthkomalwad/tripline.git
cd tripline
just build
export PATH="$PWD/bin:$PATH"
mkdir ~/tripline-demo
tripline init -dir ~/tripline-demo
cd ~/tripline-demo
tripline watcher -config tripline.yaml &
sleep 2   # let the watcher open its ports
tripline status -config tripline.yaml
```

`tripline init` prints a sensor token once, and the decoy paths. Store the token. The status screen shows the bundle version, the sources and the coverage. Coverage marks each sensor type that is not watched yet as `NOT WATCHED`.

Next, trip a decoy and read the alert. `docs/quickstart.md` shows the steps. It also covers Level 2.

<!-- Status page screenshot goes here. It is not captured yet. -->
*Status page screenshot: not yet added.*

The container image comes from `just image`. A published image, referenced by digest, comes with the first release. Until then, build from source.

## Documentation

- [Quickstart](docs/quickstart.md): Level 1, Level 2 and the plan for Level 3.
- [Threat model](docs/threat-model.md): what tripline does, and every limit.
- [Rules](docs/rules.md): rule format, signed bundles, floor rules, incident packs.
- [Operations](docs/operations.md): failure modes, break-glass, retention, key rotation.
- [Replay lab](replays/litellm-2026-10/README.md): a harmless re-creation of the October 2026 LiteLLM attack. Levels 1 and 2 today.
- [Build spec](aiwatch-build-spec.md) and [decisions](docs/adr/).
- [Security policy](SECURITY.md) and [contributing](CONTRIBUTING.md).

## What exists today

| Level | Part | State |
|---|---|---|
| 1 | Watcher, decoys, trap, audit log, status page, Slack and webhook sinks | Built |
| 2 | Egress sensor (CONNECT proxy), lookalike detection, monitor and enforce | Built |
| 2 | Signed rule bundles, floor rules, correlation rules | Built |
| 3 | Node sensor (Falco), hooks for coding agents | Planned |
| 2 | Provider mode (key injection) | Planned |
| 1 | Key-usage connectors, weekly digest | Planned |

## License

Apache-2.0. See `LICENSE`.
