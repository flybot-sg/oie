(ns flybot.oie.oauth2
  (:require [cheshire.core :as json]
            [clojure.string :as str]
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

(defn make-oauth-success-handler
  "Ring handler for the OAuth2 success callback (landing URI).
   Extracts tokens for `provider-key`, calls `fetch-profile-fn` and `login-fn`,
   stores the identity in session under `session-key`, and redirects.
   `success-redirect-uri` can be a string or a `(fn [request])` for dynamic redirects."
  [{:keys [provider-key session-key fetch-profile-fn login-fn success-redirect-uri]}]
  (fn [request]
    (if-let [token-map (get-in request [:oauth2/access-tokens provider-key])]
      (let [profile  (fetch-profile-fn token-map)
            ident    (login-fn profile)
            redirect (if (fn? success-redirect-uri)
                       (success-redirect-uri request)
                       success-redirect-uri)]
        (if ident
          {:status  302
           :headers {"Location" redirect}
           :session (assoc (:session request) session-key ident)}
          {:status 403}))
      {:status 403})))

^:rct/test
(comment
  ;; success flow: fetches profile, logs in, stores in session, redirects
  (let [handler (make-oauth-success-handler
                 {:provider-key     :google
                  :session-key      :oie/user
                  :fetch-profile-fn (fn [tokens]
                                      {:email "alice@example.com"
                                       :name  "Alice"})
                  :login-fn         (fn [profile]
                                      {:user-id 1 :email (:email profile)})
                  :success-redirect-uri "/"})
        request {:oauth2/access-tokens {:google {:token    "access-tok"
                                                 :id-token "jwt-string"}}
                 :session {}}
        resp    (handler request)]
    [(:status resp)
     (get-in resp [:headers "Location"])
     (get-in resp [:session :oie/user])])
  ;; => [302 "/" {:user-id 1, :email "alice@example.com"}]

  ;; fetch-profile-fn receives the correct token map
  (let [received (atom nil)
        handler  (make-oauth-success-handler
                  {:provider-key     :github
                   :session-key      :oie/user
                   :fetch-profile-fn (fn [tokens] (reset! received tokens) {:email "bob@example.com"})
                   :login-fn         identity
                   :success-redirect-uri "/home"})
        tokens   {:token "ghp_abc" :id-token "jwt"}
        request  {:oauth2/access-tokens {:github tokens} :session {}}]
    (handler request)
    @received)
  ;; => {:token "ghp_abc", :id-token "jwt"}

  ;; preserves existing session data
  (let [handler (make-oauth-success-handler
                 {:provider-key     :google
                  :session-key      :oie/user
                  :fetch-profile-fn (constantly {:email "alice@example.com"})
                  :login-fn         identity
                  :success-redirect-uri "/"})
        request {:oauth2/access-tokens {:google {:token "tok"}}
                 :session {:other-key "keep-me"}}
        resp    (handler request)]
    (get-in resp [:session :other-key]))
  ;; => "keep-me"

  ;; success-redirect-uri as function uses request to determine redirect
  (let [handler (make-oauth-success-handler
                 {:provider-key     :google
                  :session-key      :oie/user
                  :fetch-profile-fn (constantly {:email "alice@example.com"})
                  :login-fn         identity
                  :success-redirect-uri (fn [req] (get-in req [:session :return-to] "/"))})
        request {:oauth2/access-tokens {:google {:token "tok"}}
                 :session {:return-to "/dashboard"}}
        resp    (handler request)]
    (get-in resp [:headers "Location"]))
  ;; => "/dashboard"

  ;; login-fn returns nil → 403
  (let [handler (make-oauth-success-handler
                 {:provider-key     :google
                  :session-key      :oie/user
                  :fetch-profile-fn (constantly {:email "banned@example.com"})
                  :login-fn         (constantly nil)
                  :success-redirect-uri "/"})]
    (:status (handler {:oauth2/access-tokens {:google {:token "tok"}}
                       :session {}})))
  ;; => 403

  ;; missing tokens returns 403
  (let [handler (make-oauth-success-handler
                 {:provider-key     :google
                  :session-key      :oie/user
                  :fetch-profile-fn (constantly {:email "alice@example.com"})
                  :login-fn         identity
                  :success-redirect-uri "/"})]
    (:status (handler {:session {}})))
  ;; => 403
  )

(defn wrap-oauth2
  "Ring middleware that handles the OAuth2 authorization code flow.
   Delegates to ring.middleware.oauth2/wrap-oauth2.
   `profiles` is a map of provider-key to profile config.
   Each profile requires at minimum:
     :authorize-uri, :access-token-uri, :client-id, :client-secret,
     :scopes, :launch-uri, :redirect-uri, :landing-uri"
  [handler profiles]
  (ring-oauth2/wrap-oauth2 handler profiles))

^:rct/test
(comment
  ;; non-OAuth request passes through
  (let [profile {:authorize-uri    "https://example.com/authorize"
                 :access-token-uri "https://example.com/token"
                 :redirect-uri     "/oauth2/test/callback"
                 :launch-uri       "/oauth2/test"
                 :landing-uri      "/"
                 :scopes           [:openid]
                 :client-id        "test-id"
                 :client-secret    "test-secret"}
        handler (wrap-oauth2 (constantly {:status 200}) {:test profile})]
    (:status (handler {:uri "/hello" :request-method :get})))
  ;; => 200

  ;; launch URI triggers redirect to authorize-uri
  (let [profile {:authorize-uri    "https://example.com/authorize"
                 :access-token-uri "https://example.com/token"
                 :redirect-uri     "/oauth2/test/callback"
                 :launch-uri       "/oauth2/test"
                 :landing-uri      "/"
                 :scopes           [:openid]
                 :client-id        "test-id"
                 :client-secret    "test-secret"}
        handler (wrap-oauth2 (constantly {:status 200}) {:test profile})
        resp    (handler {:uri            "/oauth2/test"
                          :request-method :get
                          :scheme         :https
                          :server-name    "example.com"
                          :server-port    443})]
    (:status resp))
  ;; => 302
  )
