# oie

[![Clojars](https://img.shields.io/clojars/v/sg.flybot/oie.svg)](https://clojars.org/sg.flybot/oie)
![CI](https://github.com/flybot-sg/oie/actions/workflows/ci.yml/badge.svg)
![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)

Ring-based authentication and authorization library for Clojure. Strategy-based, composable middleware with pluggable storage.

## Rationale

Authentication in Ring apps typically means either a heavyweight framework that imposes its own session/user model, or ad-hoc middleware scattered across your codebase. oie takes a different approach:

- **Strategies as data**: each auth mechanism is a plain map with an `:authenticate` function, not a class hierarchy or protocol implementation
- **Composable middleware**: login flows (OAuth2, magic link) compose as outer middleware around a single `wrap-authenticate` that tries strategies in order
- **Pluggable storage**: all persistence is injected via callbacks (`verify-token`, `consume-nonce`, `login-fn`), so the library never touches your database
- **Single session key**: all session-aware middleware agrees on one namespace-qualified key, eliminating misconfiguration between components

**By design**: oie handles authentication (who are you?) and provides a predicate for authorization (can you do this?). It does not manage users, hash passwords, or send emails. Those are your app's concerns, injected via callbacks.

## Installation

```clojure
;; deps.edn
{:deps {sg.flybot/oie {:mvn/version "RELEASE"}}}
```

## Quick Start

```clojure
(ns my-app.core
  (:require [flybot.oie.core :as oie]
            [flybot.oie.oauth2 :as oauth2]
            [flybot.oie.magic-link :as magic-link]
            [flybot.oie.strategy.bearer :as bearer]
            [flybot.oie.strategy.session :as session-strat]
            [ring.middleware.params :refer [wrap-params]]
            [ring.middleware.session :refer [wrap-session]]))

;; Middleware ordering matters — outermost wraps first:
(-> app-handler
    ;; 3. Innermost: check auth on every request
    (oie/wrap-authenticate [(bearer/bearer-token-strategy {:verify-token my-verify-fn})
                            (session-strat/session-strategy)])
    ;; 2. Login flows: intercept specific URIs, create sessions
    (magic-link/wrap-magic-link {:verify-uri "/auth/magic-link" ...})
    (oauth2/wrap-oauth2 {:google {...}})
    ;; 1. Outermost: Ring basics (params, session) must be available to everything above
    (wrap-params)
    (wrap-session {:store my-session-store}))
```

## Authentication Strategies

Strategies are data maps passed to `wrap-authenticate`. Each strategy's `:authenticate` fn returns:
- `{:authenticated data}` — success, identity assoc'd into request
- `{:error error}` — auth attempted but failed
- `nil` — not applicable, try next strategy

First `{:authenticated ...}` wins. Strategies are tried in order.

### Bearer Token

Reads `Authorization: Bearer <token>` header. Hashes the raw token (SHA-256) before calling the injected lookup function.

```clojure
(bearer/bearer-token-strategy
 {:verify-token (fn [token-hash] ...)  ;; -> token-data | nil
  :clock        (fn [] ...)})          ;; -> epoch-ms (optional, defaults to System/currentTimeMillis)
```

`verify-token` receives a SHA-256 hex hash (64 chars), returns token data or nil. Token data must include `:revoked-at` (epoch-ms or nil) and `:expires-at` (epoch-ms), checked by `token-active?`.

### Session

Reads identity from the Ring session under key `::session/user`. No configuration.

```clojure
(session-strat/session-strategy)
```

## Login Flows

Login flow middleware composes as outer middleware around `wrap-authenticate`. They intercept specific URIs, authenticate the user, and create a session. Subsequent requests are then authenticated by `session-strategy`.

### OAuth2

Wraps `ring.middleware.oauth2/wrap-oauth2` and intercepts the landing URI to create a session.

```clojure
(oauth2/wrap-oauth2 handler
 {:google {:authorize-uri       "https://accounts.google.com/o/oauth2/v2/auth"
           :access-token-uri    "https://oauth2.googleapis.com/token"
           :client-id           (System/getenv "GOOGLE_CLIENT_ID")
           :client-secret       (System/getenv "GOOGLE_CLIENT_SECRET")
           :scopes              [:openid :email :profile]
           :launch-uri          "/oauth2/google"
           :redirect-uri        "/oauth2/google/callback"
           :landing-uri         "/oauth2/google/success"
           ;; oie-specific keys:
           :fetch-profile-fn    (fn [tokens] ...)  ;; -> profile map
           :login-fn            (fn [profile] ...)  ;; -> identity | nil
           :success-redirect-uri "/"}})             ;; string or (fn [req] -> uri)
```

For OIDC providers, use `decode-id-token` to extract claims from the JWT instead of making an HTTP call:

```clojure
:fetch-profile-fn (fn [tokens] (oauth2/decode-id-token (:id-token tokens)))
```

### Magic Link

Intercepts two URIs: verification (GET) and token request (POST).

```clojure
(magic-link/wrap-magic-link handler
 {:verify-uri           "/auth/magic-link"
  :request-uri          "/auth/magic-link/request"
  :secret               (System/getenv "MAGIC_LINK_SECRET")
  :token-ttl            600000  ;; 10 minutes in ms
  :consume-nonce        (fn [nonce] ...)        ;; -> truthy if consumed, nil if already used
  :store-nonce          (fn [nonce email expires-at] ...)
  :send-fn              (fn [email token] ...)  ;; deliver token to user (email, SMS, etc.)
  :login-fn             (fn [profile] ...)      ;; -> identity | nil
  :success-redirect-uri "/"                     ;; string or (fn [req] -> uri)
  ;; optional:
  :token-param          "token"   ;; query param name for verification
  :request-param        "email"   ;; param name for token request
  :clock                (fn [] ...)})           ;; -> epoch-ms
```

## Session Helpers

### Logout

POST-only handler that clears the session and redirects. Apply `wrap-anti-forgery` to protect against CSRF.

```clojure
(session/logout-handler {:redirect-uri "/"})
```

### Session Timeout

Returns 401 with a redirect hint for client-side re-auth. For use with `ring.middleware.session-timeout/wrap-idle-session-timeout`.

```clojure
(session/session-timeout-handler {:redirect-uri "/login"})
;; => {:status 401, :body {:type :session-timeout, :redirect "/login"}}
```

## Authorization

```clojure
(oie/get-identity request)              ;; => {:email "..." :roles #{:admin}} or nil
(authz/has-role? identity :admin)        ;; => true | false
```

`has-role?` checks the `:roles` key on the identity. Works with sets, vectors, or any seq.

## Ring Middleware Dependencies

| oie component | Requires upstream | Why |
|---|---|---|
| `session-strategy` | `wrap-session` | Reads identity from `:session` |
| `wrap-oauth2` | `wrap-params`, `wrap-session` | ring-oauth2 reads `:query-params` for state/code; stores tokens in `:session` |
| `wrap-magic-link` | `wrap-params`, `wrap-session` | Reads `:query-params` (verify) and `:params` (request); stores identity in `:session` |
| `logout-handler` | `wrap-session`, `wrap-anti-forgery` | Clears `:session`; POST-only needs CSRF protection |
| `bearer-token-strategy` | — | Reads from `:headers` (always present in Ring requests) |

## Token Utilities

For bearer token management:

```clojure
(token/generate-token "hb_live_")       ;; => SensitiveToken (prefix + 32 base64url chars)
(token/hash-token raw-or-sensitive)     ;; => 64-char SHA-256 hex string
(token/token-active? token-data now)    ;; => true if non-nil, not revoked, not expired
```

`SensitiveToken` prints as `#<sensitive-token>` in REPL and logs to prevent secret leakage. Store only the hash — never the raw token.

## Config Validation

Malli schemas for all middleware configs. Call at system startup for early error detection:

```clojure
(require '[flybot.oie.schema :as schema])

(schema/validate-config schema/wrap-oauth2-schema my-config "wrap-oauth2")
;; => my-config if valid, throws ex-info with humanized errors if not
```

Available schemas: `strategy-schema`, `wrap-authenticate-schema`, `bearer-token-strategy-schema`, `logout-handler-schema`, `session-timeout-handler-schema`, `wrap-magic-link-schema`, `wrap-oauth2-schema`.

## Development

Start nREPL:

```sh
bb dev
```

## Testing

Run all tests:

```sh
bb test
```

Run only rich comment tests:

```sh
bb rct
```

## Formatting

Check:

```sh
bb fmt-check
```

Fix:

```sh
bb fmt-fix
```
