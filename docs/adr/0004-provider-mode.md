# 4. Provider mode

Date: 2026-10-24
Status: accepted

## Context

An attacker inside the AI gateway can steal provider keys. The attacker can also send their own key or organization to a real provider, for example to move data out through an allowed host. CONNECT mode cannot see this, because it does not read the request.

## Decision

- The gateway sends provider traffic to the sensor over plain HTTP on a separate listener (`provider_listen`, default `127.0.0.1:8081`). Paths are `/anthropic/...` and `/openai/...`. The sensor removes the prefix and forwards the rest to a fixed host over TLS: `https://api.anthropic.com` and `https://api.openai.com`. It never uses the client Host header.
- The gateway holds no provider key. The sensor reads each key once at start, from `key_file` or `key_env`, and keeps it in memory only. A key file readable by group or others gets a warning on Unix.
- Tenant pinning is always on. A request that carries any credential or tenant header gets HTTP 403 and an `egress.provider_request` event with `decision: deny`, `reason: foreign credential` and a `fingerprint` (first 4 characters plus a SHA-256 prefix). There is no monitor mode for this check. Legitimate traffic in this mode never carries a key, so a key is a sign of compromise. Forwarding it would also send an attacker key to the provider. The floor rule `floor-foreign-credential` raises a critical alert and a page.
- Rejected headers: `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Api-Key`, `OpenAI-Organization`, `OpenAI-Project`, `Anthropic-Workspace-Id`. Rejected query names: `key`, `api_key`, `api-key`, `apikey`, `x-api-key`, `access_token`, `token`.
- The sensor injects `Authorization: Bearer <key>` for both providers. For OpenAI it also sets `OpenAI-Organization` and `OpenAI-Project` when configured. The client keeps `anthropic-version`, which Anthropic requires.
- Each request makes one event with provider, method, path (no query), model, status, latency and token counts. The sensor reads at most 1 MiB of the request body to find `model`, then replays the bytes. It reads a non-streaming JSON response (at most 8 MiB) to find `usage`. Streams pass through unread, so their token counts are absent and their latency is the time to response headers. Bodies are never logged or stored.

## Verified provider facts

Read from the official docs on 2026-10-24.

- Anthropic, https://platform.claude.com/docs/en/api/overview: base URL `https://api.anthropic.com`. Headers `Authorization: Bearer <token>`, `x-api-key` (legacy fallback), `anthropic-workspace-id`, `anthropic-version` (required). Usage fields `input_tokens` and `output_tokens` (https://platform.claude.com/docs/en/api/messages/create).
- OpenAI, https://platform.openai.com/docs/api-reference/authentication (403 to the fetcher; same text at https://developers.openai.com/api/reference/overview): `Authorization: Bearer ...`, `OpenAI-Organization`, `OpenAI-Project`. Base URL `https://api.openai.com/v1/`. Usage fields `prompt_tokens` and `completion_tokens` (chat completions), `input_tokens` and `output_tokens` (responses).

## Consequences

- A client SDK that always sends a dummy key (for example `Authorization: Bearer x`) is rejected. Configure the gateway to send no auth header.
- Token counts are missing for streams. OpenAI streams report usage only with `stream_options.include_usage`, and the sensor does not parse them.
- The check covers the headers and query names above. A credential hidden in the body is out of scope.
