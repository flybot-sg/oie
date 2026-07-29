(ns ^:no-doc flybot.oie.oauth2
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [flybot.oie.session :as session]
            [ring.middleware.oauth2 :as ring-oauth2])
  (:import [java.util Base64]))

(defn- pad-base64url
  "Adds padding to a base64url string. JWT tokens strip padding per RFC 7515."
  [s]
  (case (rem (count s) 4)
    2 (str s "==")
    3 (str s "=")
    s))

(defn decode-id-token
  "Decodes the payload of an OIDC id_token (JWT).
   Returns the claims map with keyword keys, or nil if `id-token` is nil/malformed.
   No signature verification — safe when the token comes directly from
   the token endpoint over HTTPS (server-to-server)."
  [id-token]
  (some-> id-token
          (str/split #"\.")
          second
          pad-base64url
          (->> (.decode (Base64/getUrlDecoder)))
          (String. "UTF-8")
          (json/parse-string keyword)))

^:rct/test
(comment
  (let [claims       {"sub" "12345" "email" "alice@example.com" "email_verified" true}
        payload-b64  (-> (Base64/getUrlEncoder)
                         (.withoutPadding)
                         (.encodeToString (.getBytes (json/generate-string claims) "UTF-8")))
        jwt          (str "eyJhbGciOiJSUzI1NiJ9." payload-b64 ".fake-sig")]
    (decode-id-token jwt))
  ;; => {:sub "12345", :email "alice@example.com", :email_verified true}

  ;; handles padded base64url
  (let [claims       {"sub" "1"}
        payload-b64  (-> (Base64/getUrlEncoder)
                         (.encodeToString (.getBytes (json/generate-string claims) "UTF-8")))
        jwt          (str "h." payload-b64 ".s")]
    (decode-id-token jwt))
  ;; => {:sub "1"}
  )

(defn- handle-landing
  [{:keys [session] :as request}
   {:keys [provider-key fetch-profile-fn login-fn success-redirect-uri]}]
  (if-let [tokens (get-in request [:oauth2/access-tokens provider-key])]
    (let [ident     (login-fn (fetch-profile-fn tokens))
          return-to (get session session/return-to-key)
          sess      (dissoc session ::ring-oauth2/access-tokens session/return-to-key)]
      (if ident
        {:status  302
         :headers {"Location" (or return-to
                                  (if (fn? success-redirect-uri)
                                    (success-redirect-uri request)
                                    success-redirect-uri))}
         :session (assoc sess session/session-key ident)}
        {:status  403
         :session sess}))
    {:status 401
     :body   {:type :missing-token :message "OAuth2 access token not found."}}))

(defn- wrap-return-to
  "Stores a validated `?return-to` query param in the session on launch
   requests, clearing any stale value from an earlier login."
  [handler profiles]
  (let [launch-uris (into #{} (map :launch-uri) (vals profiles))]
    (fn [{:keys [uri session query-params] :as req}]
      (handler
       (if (contains? launch-uris uri)
         (assoc req :session
                (if-let [path (session/safe-return-path (get query-params "return-to"))]
                  (assoc session session/return-to-key path)
                  (dissoc session session/return-to-key)))
         req)))))

(defn- build-landing-configs [profiles]
  (reduce-kv
   (fn [m provider-key profile]
     (assoc m (:landing-uri profile)
            (-> profile
                (select-keys [:fetch-profile-fn :login-fn :success-redirect-uri])
                (assoc :provider-key provider-key))))
   {}
   profiles))

(defn wrap-oauth2
  "Ring middleware that handles the full OAuth2 login flow.
   Delegates to ring.middleware.oauth2/wrap-oauth2 for the authorization code
   exchange, then intercepts the landing-uri to create a session and redirect.

   `profiles` is a map of provider-key to profile config.
   Each profile requires ring-oauth2 keys:
     :authorize-uri, :access-token-uri, :client-id, :client-secret,
     :scopes, :launch-uri, :redirect-uri, :landing-uri
   Plus oie keys:
     :fetch-profile-fn     — `(fn [token-map] -> profile)`
     :login-fn             — `(fn [profile] -> identity | nil)`
     :success-redirect-uri — string or `(fn [req] -> uri)`
   Identity is stored in session under `::session/user`.

   A `?return-to` query param on the launch URI that passes
   `session/safe-return-path` overrides `:success-redirect-uri` after login."
  [handler profiles]
  (let [landing-configs (build-landing-configs profiles)
        interceptor     (fn [request]
                          (if-let [config (get landing-configs (:uri request))]
                            (handle-landing request config)
                            (handler request)))]
    (-> interceptor
        (ring-oauth2/wrap-oauth2 profiles)
        (wrap-return-to profiles))))

^:rct/test
(comment
  (def ^:private test-profile
    {:authorize-uri       "https://example.com/authorize"
     :access-token-uri    "https://example.com/token"
     :redirect-uri        "/oauth2/test/callback"
     :launch-uri          "/oauth2/test"
     :landing-uri         "/oauth2/test/success"
     :scopes              [:openid]
     :client-id           "test-id"
     :client-secret       "test-secret"
     :fetch-profile-fn    (fn [_tokens]
                            {:email "alice@example.com"
                             :name  "Alice"})
     :login-fn            (fn [profile]
                            {:user-id 1 :email (:email profile)})
     :success-redirect-uri "/"})

  (defn- make-handler [overrides]
    (wrap-oauth2 (constantly {:status 200 :body "ok"})
                 {:test (merge test-profile overrides)}))

  (defn- landing-request
    ([tokens] (landing-request tokens {}))
    ([tokens session-extra]
     {:uri            "/oauth2/test/success"
      :request-method :get
      :session        (merge {::ring-oauth2/access-tokens {:test tokens}}
                             session-extra)}))

  ;; success flow: tokens → 302 redirect with session, tokens cleaned
  (let [handler (make-handler {})
        resp    (handler (landing-request {:token "access-tok"}))]
    [(:status resp)
     (get-in resp [:headers "Location"])
     (get-in resp [:session ::session/user])
     (contains? (:session resp) ::ring-oauth2/access-tokens)])
  ;; => [302 "/" {:user-id 1, :email "alice@example.com"} false]

  ;; fetch-profile-fn receives the correct token map
  (let [received (atom nil)
        handler  (make-handler {:fetch-profile-fn (fn [tokens] (reset! received tokens) {:email "bob@example.com"})})
        tokens   {:token "ghp_abc" :id-token "jwt"}]
    (handler (landing-request tokens))
    @received)
  ;; => {:token "ghp_abc", :id-token "jwt"}

  ;; preserves existing session data (minus tokens)
  (let [handler (make-handler {})
        resp    (handler (landing-request {:token "tok"} {:other-key "keep-me"}))]
    (get-in resp [:session :other-key]))
  ;; => "keep-me"

  ;; success-redirect-uri as function uses request context
  (let [handler (make-handler {:success-redirect-uri
                               (fn [req] (get-in req [:session :return-to] "/"))})
        resp    (handler (landing-request {:token "tok"} {:return-to "/dashboard"}))]
    (get-in resp [:headers "Location"]))
  ;; => "/dashboard"

  ;; login-fn returns nil → 403, tokens still cleaned
  (let [handler (make-handler {:login-fn (constantly nil)})
        resp    (handler (landing-request {:token "tok"}))]
    [(:status resp)
     (contains? (:session resp) ::ring-oauth2/access-tokens)])
  ;; => [403 false]

  ;; landing-uri without tokens → 401
  (let [handler (make-handler {})]
    (:status (handler {:uri "/oauth2/test/success" :request-method :get :session {}})))
  ;; => 401

  ;; non-landing-uri → pass through
  (let [handler (make-handler {})]
    (:status (handler {:uri "/hello" :request-method :get})))
  ;; => 200

  ;; launch URI triggers redirect to authorize-uri
  (let [handler (make-handler {})]
    (:status (handler {:uri            "/oauth2/test"
                       :request-method :get
                       :scheme         :https
                       :server-name    "example.com"
                       :server-port    443})))
  ;; => 302

  (defn- launch-request
    ([query-params] (launch-request query-params {}))
    ([query-params session]
     {:uri            "/oauth2/test"
      :request-method :get
      :scheme         :https
      :server-name    "example.com"
      :server-port    443
      :query-params   query-params
      :session        session}))

  ;; launch captures a safe ?return-to in the session
  (let [handler (make-handler {})
        resp    (handler (launch-request {"return-to" "/reports/42"}))]
    (get-in resp [:session session/return-to-key]))
  ;; => "/reports/42"

  ;; hostile ?return-to is ignored and a stale value is cleared
  (let [handler (make-handler {})
        resp    (handler (launch-request {"return-to" "//evil.com"}
                                         {session/return-to-key "/stale"}))]
    (contains? (:session resp) session/return-to-key))
  ;; => false

  ;; launch without ?return-to clears a stale value
  (let [handler (make-handler {})
        resp    (handler (launch-request {} {session/return-to-key "/stale"}))]
    (contains? (:session resp) session/return-to-key))
  ;; => false

  ;; landing redirects to return-to over success-redirect-uri and clears it
  (let [handler (make-handler {})
        resp    (handler (landing-request {:token "tok"}
                                          {session/return-to-key "/reports/42"}))]
    [(get-in resp [:headers "Location"])
     (contains? (:session resp) session/return-to-key)])
  ;; => ["/reports/42" false]

  ;; rejected login also drops return-to from the session
  (let [handler (make-handler {:login-fn (constantly nil)})
        resp    (handler (landing-request {:token "tok"}
                                          {session/return-to-key "/reports/42"}))]
    [(:status resp) (contains? (:session resp) session/return-to-key)])
  ;; => [403 false]
  )
