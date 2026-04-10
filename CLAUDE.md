# oie

Ring-based authentication and authorization library for Clojure. Strategy-based architecture where each auth mechanism is composable middleware.

- **GitLab**: https://github.com/flybot-sg/oie

## Architecture

```
wrap-authenticate (core)     ← orchestrates strategies in sequence
├── bearer-token-strategy    ← stateless: Authorization header → token hash → lookup
├── session-strategy         ← stateful: session cookie → identity
└── (custom strategies)      ← any fn returning {:authenticated data} | {:error ...} | nil

wrap-oauth2                  ← ring-oauth2 + landing page interception + session creation
wrap-magic-link              ← HMAC-signed token creation (POST) + verification (GET) + session
```

**Authentication** (`core`): `wrap-authenticate` tries strategies in order, assocs identity into request.

**Session-based entry points** (`oauth2`, `magic-link`): Handle login flows, create sessions. Compose as outer middleware around `wrap-authenticate`.

**Authorization** (`authz`): Pure predicate on identity data. Caller decides error format.

## Namespace Map

| Namespace | Public API | Purpose |
|-----------|-----------|---------|
| `flybot.oie.core` | `get-identity`, `wrap-authenticate` | Multi-strategy authentication middleware |
| `flybot.oie.authz` | `has-role?` | Role membership check on identity |
| `flybot.oie.token` | `generate-token`, `hash-token`, `token-active?` | Secure token generation, hashing, lifecycle |
| `flybot.oie.session` | `logout-handler`, `session-timeout-handler` | Session logout and timeout handlers |
| `flybot.oie.magic-link` | `create-magic-link-token`, `wrap-magic-link` | Passwordless email authentication |
| `flybot.oie.oauth2` | `decode-id-token`, `wrap-oauth2` | OAuth2/OIDC with session creation |
| `flybot.oie.strategy.bearer` | `bearer-token-strategy` | Bearer token strategy for `wrap-authenticate` |
| `flybot.oie.schema` | `validate-config`, `*-schema` | Malli config schemas for consumer-side validation |
| `flybot.oie.strategy.session` | `session-strategy` | Session strategy for `wrap-authenticate` |

## Internal Dependencies

```
flybot.oie.strategy.bearer → flybot.oie.token
flybot.oie.oauth2          → cheshire, ring.middleware.oauth2
flybot.oie.schema          → malli
```

All other namespaces have no internal dependencies.

## Tasks

- `bb dev` — start nREPL with CIDER middleware
- `bb rct` — run rich comment tests
- `bb test` — run Kaocha + RCT
- `bb fmt-check` — check code format
- `bb fmt-fix` — fix code format

## Project State

- **Build tool**: deps.edn
- **Root namespace**: `flybot.oie`
- **Test**: Kaocha + RCT
- **Dev**: nREPL + cider-nrepl
- **External deps**: cheshire (JSON), malli (schema validation), ring-oauth2 (OAuth2 flow)
