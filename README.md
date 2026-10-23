# tripline

> Assume something gets in. Make sure it leaves with nothing.

tripline is an open-source monitor for self-hosted AI systems: AI gateways, agents, MCP servers and coding agents. It watches for the steps that every attack must take after it gets in: secret access, data leaving the system and stolen key use. It proves with self-tests that its own protections still work.

**Status:** early development. There is no release yet. See `aiwatch-build-spec.md` for the design.

## Build

```sh
just build
./bin/tripline version
```

## License

Apache-2.0. See `LICENSE`.
