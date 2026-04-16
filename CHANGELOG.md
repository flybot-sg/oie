# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/flybot-sg/oie/tree/0.2.0) - 2026-04-16

### Added
- **`wrap-authenticate` `:allow-anonymous?` option**: Pass requests through with no identity when no strategy matches, enabling mixed public/authenticated routes
- **`session-strategy` `:verify` option**: Optional fn to re-validate session identity per request; returning nil skips the strategy (stale session)
- **`logout-handler` `:response-fn` option**: Zero-arg fn returning a custom Ring response instead of the default 302 redirect, enabling SPA clients to receive meaningful responses from `fetch` calls. Session is always cleared regardless

## [0.1.0](https://github.com/flybot-sg/oie/tree/0.1.0) - 2026-04-13

### Added
- **Strategy-based authentication**: `wrap-authenticate` middleware tries strategies in order, first `{:authenticated data}` wins
- **Bearer token strategy**: Extracts `Authorization: Bearer` header, hashes token (SHA-256), delegates verification to injected lookup function
- **Session strategy**: Reads identity from Ring session for authenticated subsequent requests
- **OAuth2/OIDC login flow**: `wrap-oauth2` wraps ring-oauth2 with landing page interception and session creation
- **OIDC id_token decoding**: `decode-id-token` utility for extracting JWT claims without signature verification
- **Magic link login flow**: `wrap-magic-link` with HMAC-signed tokens, storage-backed single-use nonces, and constant-time comparison
- **Token utilities**: `generate-token` (prefixed, URL-safe), `hash-token` (SHA-256), `token-active?` (expiry + revocation check)
- **SensitiveToken record**: Custom `print-method`/`print-dup`/`toString` to prevent secret leakage in REPL and logs
- **Session helpers**: POST-only `logout-handler`, `session-timeout-handler` with redirect hint
- **Role-based authorization**: `has-role?` predicate on identity data
- **Config validation**: Malli schemas for all middleware configs with `validate-config` for startup validation
- **Integration tests**: Full flow tests for OAuth2+bearer, OAuth2-only, bearer-only, and magic-link scenarios
