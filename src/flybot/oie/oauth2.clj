(ns ^:no-doc flybot.oie.oauth2
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [flybot.oie.session :as session]
            [ring.middleware.oauth2 :as ring-oauth2])
  (:import [java.net URI]
           [java.util Base64]))

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
  (let [sess (dissoc session ::ring-oauth2/access-tokens session/return-to-key)]
    (if-let [tokens (get-in request [:oauth2/access-tokens provider-key])]
      (if-let [ident (login-fn (fetch-profile-fn tokens))]
        {:status  302
         :headers {"Location" (or (get session session/return-to-key)
                                  (if (fn? success-redirect-uri)
                                    (success-redirect-uri request)
                                    success-redirect-uri))}
         :session (assoc sess session/session-key ident)}
        {:status  403
         :session sess})
      {:status  401
       :body    {:type :missing-token :message "OAuth2 access token not found."}
       :session sess})))

(defn- launch-uri-set [profiles]
  (into #{} (map :launch-uri) (vals profiles)))

(defn- wrap-return-to
  "Stores a validated `?return-to` query param in the session on launch
   requests, clearing any stale value from an earlier login."
  [handler profiles]
  (let [launch-uris (launch-uri-set profiles)]
    (fn [{:keys [uri session query-params] :as req}]
      (handler
       (if (contains? launch-uris uri)
         (assoc req :session
                (if-let [path (session/safe-return-path (get query-params "return-to"))]
                  (assoc session session/return-to-key path)
                  (dissoc session session/return-to-key)))
         req)))))

(defn- redirect-path [{:keys [redirect-uri]}]
  (.getPath (URI/create redirect-uri)))

(defn- state-cookie-name [state]
  (str "__Host-oauth2-state-" state))

(defn- add-state-cookie
  "Mirrors the launch response's OAuth2 state into a per-flow `__Host-` cookie.
   Value is the PKCE code verifier, or `\"1\"` without PKCE."
  [{:keys [session] :as resp}]
  (assoc-in resp [:cookies (state-cookie-name (::ring-oauth2/state session))]
            {:value     (or (::ring-oauth2/code-verifier session) "1")
             :max-age   300
             :http-only true
             :secure    true
             :same-site :lax
             :path      "/"}))

(defn- handle-callback
  "Restores the state (and PKCE verifier) from the per-flow cookie into the
   session before ring-oauth2's state check, then expires the cookie."
  [handler req]
  (let [state       (get-in req [:query-params "state"])
        cookie-name (state-cookie-name state)]
    (if-let [verifier (when state (get-in req [:cookies cookie-name :value]))]
      (-> req
          (update :session assoc ::ring-oauth2/state state)
          (cond-> (not= verifier "1")
            (update :session assoc ::ring-oauth2/code-verifier verifier))
          handler
          (assoc-in [:cookies cookie-name]
                    {:value "" :max-age 0 :path "/" :secure true}))
      (handler req))))

(defn- wrap-state-cookie
  "Mirrors the OAuth2 state into a per-flow `__Host-oauth2-state-<state>`
   cookie so the callback state check survives concurrent launches and
   racing session writes."
  [handler profiles]
  (let [launch-uris    (launch-uri-set profiles)
        callback-paths (into #{} (map redirect-path) (vals profiles))]
    (fn [{:keys [uri] :as req}]
      (cond
        (contains? launch-uris uri)    (add-state-cookie (handler req))
        (contains? callback-paths uri) (handle-callback handler req)
        :else                          (handler req)))))

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
   `session/safe-return-path` overrides `:success-redirect-uri` after login.

   The OAuth2 state is mirrored into a short-lived `__Host-oauth2-state-<state>`
   cookie so concurrent launches or racing session writes cannot break the
   callback state check."
  [handler profiles]
  (let [landing-configs (build-landing-configs profiles)
        interceptor     (fn [request]
                          (if-let [config (get landing-configs (:uri request))]
                            (handle-landing request config)
                            (handler request)))]
    (-> interceptor
        (ring-oauth2/wrap-oauth2 profiles)
        (wrap-state-cookie profiles)
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
     :success-redirect-uri "/"
     :state-mismatch-handler (fn [_] {:status 400 :body :state-mismatch})
     :no-auth-code-handler   (fn [_] {:status 400 :body :state-check-passed})})

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

  ;; landing without tokens clears flow state, keeps the rest of the session
  (let [handler (make-handler {})
        resp    (handler {:uri            "/oauth2/test/success"
                          :request-method :get
                          :session        {session/return-to-key "/stale"
                                           :other-key            "keep-me"}})]
    [(:status resp) (:session resp)])
  ;; => [401 {:other-key "keep-me"}]

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

  (defn- callback-request [state cookies session]
    {:uri            "/oauth2/test/callback"
     :request-method :get
     :query-params   {"state" state}
     :cookies        cookies
     :session        session})

  ;; launch mirrors the OAuth2 state into a per-flow __Host- cookie
  (let [handler (make-handler {})
        resp    (handler (launch-request {}))
        state   (get-in resp [:session ::ring-oauth2/state])]
    (get-in resp [:cookies (str "__Host-oauth2-state-" state)]))
  ;; => {:value "1", :max-age 300, :http-only true, :secure true, :same-site :lax, :path "/"}

  ;; callback with matching cookie passes the state check and expires the cookie
  ;; (no code param, so the flow stops at the no-auth-code sentinel)
  (let [handler     (make-handler {})
        launch      (handler (launch-request {}))
        state       (get-in launch [:session ::ring-oauth2/state])
        cookie-name (state-cookie-name state)
        resp        (handler (callback-request state
                                               {cookie-name {:value "1"}}
                                               (:session launch)))]
    [(:body resp) (get-in resp [:cookies cookie-name])])
  ;; => [:state-check-passed {:value "", :max-age 0, :path "/", :secure true}]

  ;; two launches overwrite the session state — completing the FIRST still
  ;; passes because both cookies coexist
  (let [handler (make-handler {})
        launch1 (handler (launch-request {}))
        state1  (get-in launch1 [:session ::ring-oauth2/state])
        launch2 (handler (launch-request {} (:session launch1)))
        state2  (get-in launch2 [:session ::ring-oauth2/state])
        resp    (handler (callback-request state1
                                           {(state-cookie-name state1) {:value "1"}
                                            (state-cookie-name state2) {:value "1"}}
                                           (:session launch2)))]
    (:body resp))
  ;; => :state-check-passed

  ;; hostile callback: state param without a matching cookie fails the check
  (let [handler (make-handler {})
        resp    (handler (callback-request "forged" {} {}))]
    [(:body resp) (contains? resp :cookies)])
  ;; => [:state-mismatch false]

  ;; PKCE: launch cookie carries the verifier, callback restores it into the
  ;; session ring-oauth2 sees (observed via a custom redirect-handler)
  (let [handler  (make-handler {:pkce? true
                                :redirect-handler
                                (fn [req]
                                  {:status 200
                                   :body   (select-keys (:session req)
                                                        [::ring-oauth2/state
                                                         ::ring-oauth2/code-verifier])})})
        launch   (handler (launch-request {}))
        state    (get-in launch [:session ::ring-oauth2/state])
        verifier (get-in launch [:session ::ring-oauth2/code-verifier])
        resp     (handler (callback-request state
                                            {(state-cookie-name state) {:value verifier}}
                                            {}))]
    [(= verifier (get-in launch [:cookies (state-cookie-name state) :value]))
     (= {::ring-oauth2/state state ::ring-oauth2/code-verifier verifier}
        (:body resp))])
  ;; => [true true]
  )
