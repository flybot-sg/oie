(ns flybot.oie.integration-test
  (:require [clojure.test :refer [deftest is testing]]
            [flybot.oie.core :as core]
            [flybot.oie.magic-link :as magic-link]
            [flybot.oie.session :as session]
            [flybot.oie.strategy.bearer :as bearer]
            [flybot.oie.oauth2 :as oauth2]
            [flybot.oie.strategy.session :as session-strat]
            [flybot.oie.token :as token]
            [ring.middleware.oauth2 :as ring-oauth2]))

(defn- api-handler [req]
  {:status 200
   :body   (core/get-identity req)})

(def ^:private clock (constantly 1000))

(deftest oauth2-and-bearer-token-flow
  (let [token-store     (atom {})
        bearer-strat    (bearer/bearer-token-strategy
                         {:verify-token #(get @token-store %)
                          :clock        clock})
        sess-strat      (session-strat/session-strategy)
        app             (-> api-handler
                            (core/wrap-authenticate [bearer-strat sess-strat])
                            (oauth2/wrap-oauth2
                             {:google {:authorize-uri       "https://example.com/authorize"
                                       :access-token-uri    "https://example.com/token"
                                       :redirect-uri        "/oauth2/google/callback"
                                       :launch-uri          "/oauth2/google"
                                       :landing-uri         "/oauth2/google/success"
                                       :scopes              [:openid]
                                       :client-id           "test-id"
                                       :client-secret       "test-secret"
                                       :fetch-profile-fn    (fn [_tokens]
                                                              {:email "alice@example.com"
                                                               :name  "Alice"})
                                       :login-fn            (fn [profile]
                                                              {:user-id 1
                                                               :email   (:email profile)
                                                               :roles   #{:user}})
                                       :success-redirect-uri "/"}}))
        logout-handler  (session/logout-handler {:redirect-uri "/"})
        timeout-handler (session/session-timeout-handler {:redirect-uri "/oauth/google/login"})]

    (testing "unauthenticated request returns 401"
      (is (= 401 (:status (app {:uri "/api" :headers {} :session {}})))))

    (testing "OAuth2 success creates session with identity"
      (let [resp (app {:uri            "/oauth2/google/success"
                       :request-method :get
                       :session        {::ring-oauth2/access-tokens
                                        {:google {:token "access-tok"}}}})]
        (is (= 302 (:status resp)))
        (is (= "/" (get-in resp [:headers "Location"])))
        (is (= {:user-id 1 :email "alice@example.com" :roles #{:user}}
               (get-in resp [:session ::session/user])))
        (is (not (contains? (:session resp) ::ring-oauth2/access-tokens)))))

    (testing "session-authenticated request succeeds"
      (let [session {::session/user {:user-id 1 :email "alice@example.com" :roles #{:user}}}
            resp    (app {:uri "/api" :headers {} :session session})]
        (is (= 200 (:status resp)))
        (is (= {:user-id 1 :email "alice@example.com" :roles #{:user}}
               (:body resp)))))

    (testing "bearer token authenticates"
      (let [raw        (token/generate-token "test_")
            hash       (token/hash-token raw)
            token-data {:username "bob" :roles #{:admin} :expires-at 2000 :revoked-at nil}
            _          (swap! token-store assoc hash token-data)
            resp       (app {:uri "/api" :headers {"authorization" (str "Bearer " (:value raw))} :session {}})]
        (is (= 200 (:status resp)))
        (is (= token-data (:body resp)))))

    (testing "bearer token takes priority over session"
      (let [raw        (token/generate-token "test_")
            hash       (token/hash-token raw)
            token-data {:username "bob" :roles #{:admin} :expires-at 2000 :revoked-at nil}
            _          (swap! token-store assoc hash token-data)
            session    {::session/user {:user-id 1 :email "alice@example.com"}}
            resp       (app {:uri "/api" :headers {"authorization" (str "Bearer " (:value raw))}
                             :session session})]
        (is (= token-data (:body resp)))))

    (testing "logout clears session and redirects"
      (let [resp (logout-handler {:request-method :post
                                  :session        {::session/user {:user-id 1}}})]
        (is (= 302 (:status resp)))
        (is (= "/" (get-in resp [:headers "Location"])))
        (is (nil? (:session resp)))))

    (testing "SPA logout with response-fn returns custom response"
      (let [spa-logout (session/logout-handler
                        {:response-fn (fn [] {:status 200 :body {:authenticated false}})})
            resp       (spa-logout {:request-method :post
                                    :session        {::session/user {:user-id 1}}})]
        (is (= 200 (:status resp)))
        (is (= {:authenticated false} (:body resp)))
        (is (nil? (:session resp)))))

    (testing "SPA logout with non-POST returns 405"
      (let [spa-logout (session/logout-handler
                        {:response-fn (fn [] {:status 200 :body {:ok true}})})]
        (is (= 405 (:status (spa-logout {:request-method :get}))))))

    (testing "GET logout returns 405"
      (is (= 405 (:status (logout-handler {:request-method :get})))))

    (testing "session timeout returns 401 with redirect hint"
      (let [resp (timeout-handler {})]
        (is (= 401 (:status resp)))
        (is (= {:type :session-timeout :redirect "/oauth/google/login"}
               (:body resp)))))))

(deftest oauth2-only-flow
  (let [sess-strat     (session-strat/session-strategy)
        google-profile {:authorize-uri       "https://example.com/authorize"
                        :access-token-uri    "https://example.com/token"
                        :redirect-uri        "/oauth2/google/callback"
                        :launch-uri          "/oauth2/google"
                        :landing-uri         "/oauth2/google/success"
                        :scopes              [:openid]
                        :client-id           "test-id"
                        :client-secret       "test-secret"
                        :fetch-profile-fn    (constantly {:email "alice@example.com"})
                        :login-fn            (fn [profile]
                                               {:user-id 1 :email (:email profile)})
                        :success-redirect-uri "/home"}
        app            (-> api-handler
                           (core/wrap-authenticate [sess-strat])
                           (oauth2/wrap-oauth2 {:google google-profile}))
        logout-handler (session/logout-handler {:redirect-uri "/"})]

    (testing "unauthenticated returns 401"
      (is (= 401 (:status (app {:uri "/api" :headers {} :session {}})))))

    (testing "OAuth2 login then session auth"
      (let [oauth-resp (app {:uri            "/oauth2/google/success"
                             :request-method :get
                             :session        {::ring-oauth2/access-tokens
                                              {:google {:token "tok"}}}})
            session    (:session oauth-resp)
            api-resp   (app {:uri "/api" :session session :headers {}})]
        (is (= 200 (:status api-resp)))
        (is (= {:user-id 1 :email "alice@example.com"}
               (:body api-resp)))))

    (testing "bearer token header is ignored without bearer strategy"
      (is (= 401 (:status (app {:uri "/api" :headers {"authorization" "Bearer some-token"} :session {}})))))

    (testing "login-fn returning nil rejects user"
      (let [reject-app (-> api-handler
                           (core/wrap-authenticate [sess-strat])
                           (oauth2/wrap-oauth2
                            {:google (assoc google-profile
                                            :fetch-profile-fn (constantly {:email "banned@example.com"})
                                            :login-fn (constantly nil))}))]
        (is (= 403 (:status (reject-app {:uri            "/oauth2/google/success"
                                         :request-method :get
                                         :session        {::ring-oauth2/access-tokens
                                                          {:google {:token "tok"}}}}))))))

    (testing "logout clears session and redirects"
      (let [resp (logout-handler {:request-method :post
                                  :session        {::session/user {:user-id 1}}})]
        (is (= 302 (:status resp)))
        (is (= "/" (get-in resp [:headers "Location"])))
        (is (nil? (:session resp)))))))

(deftest bearer-token-only-flow
  (let [token-store (atom {})
        strategy    (bearer/bearer-token-strategy
                     {:verify-token #(get @token-store %)
                      :clock        clock})
        app         (core/wrap-authenticate api-handler [strategy])]

    (testing "valid token authenticates"
      (let [raw  (token/generate-token "cli_")
            hash (token/hash-token raw)
            data {:username "alice" :roles #{:user} :expires-at 2000 :revoked-at nil}
            _    (swap! token-store assoc hash data)
            resp (app {:headers {"authorization" (str "Bearer " (:value raw))}})]
        (is (= 200 (:status resp)))
        (is (= data (:body resp)))))

    (testing "expired token returns 401"
      (let [raw  (token/generate-token "cli_")
            hash (token/hash-token raw)
            _    (swap! token-store assoc hash {:username "alice" :expires-at 500 :revoked-at nil})
            resp (app {:headers {"authorization" (str "Bearer " (:value raw))}})]
        (is (= 401 (:status resp)))))

    (testing "revoked token returns 401"
      (let [raw  (token/generate-token "cli_")
            hash (token/hash-token raw)
            _    (swap! token-store assoc hash {:username "alice" :expires-at 2000 :revoked-at 999})
            resp (app {:headers {"authorization" (str "Bearer " (:value raw))}})]
        (is (= 401 (:status resp)))))

    (testing "unknown token returns 401"
      (is (= 401 (:status (app {:headers {"authorization" "Bearer unknown-token"}})))))

    (testing "no authorization header returns 401"
      (is (= 401 (:status (app {:headers {}})))))

    (testing "session has no effect without session strategy"
      (is (= 401 (:status (app {:headers {}
                                :session {::session/user {:user-id 1}}})))))))

(deftest mixed-public-authenticated-flow
  (let [token-store  (atom {})
        bearer-strat (bearer/bearer-token-strategy
                      {:verify-token #(get @token-store %)
                       :clock        clock})
        sess-strat   (session-strat/session-strategy)
        app          (core/wrap-authenticate api-handler
                                             [bearer-strat sess-strat]
                                             {:allow-anonymous? true})]

    (testing "anonymous request passes through with no identity"
      (let [resp (app {:uri "/public" :headers {} :session {}})]
        (is (= 200 (:status resp)))
        (is (nil? (:body resp)))))

    (testing "bearer token still authenticates"
      (let [raw  (token/generate-token "cli_")
            hash (token/hash-token raw)
            data {:username "alice" :roles #{:user} :expires-at 2000 :revoked-at nil}
            _    (swap! token-store assoc hash data)
            resp (app {:uri "/api" :headers {"authorization" (str "Bearer " (:value raw))} :session {}})]
        (is (= 200 (:status resp)))
        (is (= data (:body resp)))))

    (testing "invalid bearer token still returns 401"
      (is (= 401 (:status (app {:uri "/api" :headers {"authorization" "Bearer bad-token"} :session {}})))))

    (testing "session still authenticates"
      (let [session {::session/user {:user-id 1 :email "alice@example.com"}}
            resp    (app {:uri "/api" :headers {} :session session})]
        (is (= 200 (:status resp)))
        (is (= {:user-id 1 :email "alice@example.com"} (:body resp)))))))

(deftest magic-link-flow
  (let [secret      "test-secret"
        nonce-store (atom #{})
        sent-tokens (atom {})
        sess-strat  (session-strat/session-strategy)
        app         (-> (core/wrap-authenticate api-handler [sess-strat])
                        (magic-link/wrap-magic-link
                         {:verify-uri          "/auth/magic-link"
                          :request-uri         "/auth/magic-link/request"
                          :secret              secret
                          :consume-nonce       (fn [n] (when (@nonce-store n)
                                                         (swap! nonce-store disj n)
                                                         true))
                          :store-nonce         (fn [n _ _] (swap! nonce-store conj n))
                          :send-fn             (fn [email token] (swap! sent-tokens assoc email token))
                          :login-fn            (fn [{:keys [email]}]
                                                 {:user-id 1 :email email})
                          :success-redirect-uri "/home"
                          :token-ttl           600000
                          :clock               clock}))]

    (testing "unauthenticated request returns 401"
      (is (= 401 (:status (app {:uri "/api" :headers {} :session {}})))))

    (testing "request magic link sends token"
      (let [resp (app {:uri "/auth/magic-link/request"
                       :request-method :post
                       :params {"email" "alice@example.com"}})]
        (is (= 200 (:status resp)))
        (is (contains? @sent-tokens "alice@example.com"))))

    (testing "verify magic link creates session and redirects"
      (let [token (@sent-tokens "alice@example.com")
            resp  (app {:uri            "/auth/magic-link"
                        :request-method :get
                        :query-params   {"token" token}
                        :session        {}})]
        (is (= 302 (:status resp)))
        (is (= "/home" (get-in resp [:headers "Location"])))
        (is (= {:user-id 1 :email "alice@example.com"}
               (get-in resp [:session ::session/user])))))

    (testing "replay of same token returns 401"
      (let [token (@sent-tokens "alice@example.com")
            resp  (app {:uri            "/auth/magic-link"
                        :request-method :get
                        :query-params   {"token" token}
                        :session        {}})]
        (is (= 401 (:status resp)))
        (is (= :already-used (get-in resp [:body :type])))))

    (testing "session-authenticated request succeeds after login"
      (let [session-data {::session/user {:user-id 1 :email "alice@example.com"}}
            resp         (app {:uri "/api" :headers {} :session session-data})]
        (is (= 200 (:status resp)))
        (is (= {:user-id 1 :email "alice@example.com"} (:body resp)))))))
