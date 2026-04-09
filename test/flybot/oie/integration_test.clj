(ns flybot.oie.integration-test
  (:require [clojure.test :refer [deftest is testing]]
            [flybot.oie.core :as core]
            [flybot.oie.session :as session]
            [flybot.oie.strategy.bearer :as bearer]
            [flybot.oie.strategy.oauth2 :as oauth2]
            [flybot.oie.strategy.session :as session-strat]
            [flybot.oie.token :as token]))

(defn- api-handler [req]
  {:status 200
   :body   (core/get-identity req)})

(def ^:private session-key :oie/user)
(def ^:private clock (constantly 1000))

(deftest oauth2-and-bearer-token-flow
  (let [token-store    (atom {})
        bearer-strat   (bearer/bearer-token-strategy
                        {:verify-token #(get @token-store %)
                         :clock        clock})
        sess-strat     (session-strat/session-strategy
                        {:session-key session-key})
        app            (core/wrap-authenticate api-handler [bearer-strat sess-strat])
        oauth-handler  (oauth2/make-oauth-success-handler
                        {:provider-key        :google
                         :session-key         session-key
                         :fetch-profile-fn    (fn [_tokens]
                                                {:email "alice@example.com"
                                                 :name  "Alice"})
                         :login-fn            (fn [profile]
                                                {:user-id 1
                                                 :email   (:email profile)
                                                 :roles   #{:user}})
                         :success-redirect-uri "/"})
        logout-handler (session/logout-handler {:redirect-uri "/"})
        timeout-handler (session/session-timeout-handler {:redirect-uri "/oauth/google/login"})]

    (testing "unauthenticated request returns 401"
      (is (= 401 (:status (app {:headers {}})))))

    (testing "OAuth2 success creates session with identity"
      (let [resp (oauth-handler {:oauth2/access-tokens {:google {:token "access-tok"}}
                                 :session {}})]
        (is (= 302 (:status resp)))
        (is (= "/" (get-in resp [:headers "Location"])))
        (is (= {:user-id 1 :email "alice@example.com" :roles #{:user}}
               (get-in resp [:session session-key])))))

    (testing "session-authenticated request succeeds"
      (let [session  {session-key {:user-id 1 :email "alice@example.com" :roles #{:user}}}
            resp     (app {:headers {} :session session})]
        (is (= 200 (:status resp)))
        (is (= {:user-id 1 :email "alice@example.com" :roles #{:user}}
               (:body resp)))))

    (testing "bearer token authenticates"
      (let [raw        (token/generate-token "test_")
            hash       (token/hash-token raw)
            token-data {:username "bob" :roles #{:admin} :expires-at 2000 :revoked-at nil}
            _          (swap! token-store assoc hash token-data)
            resp       (app {:headers {"authorization" (str "Bearer " (:value raw))}})]
        (is (= 200 (:status resp)))
        (is (= token-data (:body resp)))))

    (testing "bearer token takes priority over session"
      (let [raw        (token/generate-token "test_")
            hash       (token/hash-token raw)
            token-data {:username "bob" :roles #{:admin} :expires-at 2000 :revoked-at nil}
            _          (swap! token-store assoc hash token-data)
            session    {session-key {:user-id 1 :email "alice@example.com"}}
            resp       (app {:headers {"authorization" (str "Bearer " (:value raw))}
                             :session session})]
        (is (= token-data (:body resp)))))

    (testing "logout clears session and redirects"
      (let [resp (logout-handler {:request-method :post
                                  :session        {session-key {:user-id 1}}})]
        (is (= 302 (:status resp)))
        (is (= "/" (get-in resp [:headers "Location"])))
        (is (nil? (:session resp)))))

    (testing "GET logout returns 405"
      (is (= 405 (:status (logout-handler {:request-method :get})))))

    (testing "session timeout returns 401 with redirect hint"
      (let [resp (timeout-handler {})]
        (is (= 401 (:status resp)))
        (is (= {:type :session-timeout :redirect "/oauth/google/login"}
               (:body resp)))))))

(deftest oauth2-only-flow
  (let [sess-strat    (session-strat/session-strategy {:session-key session-key})
        app           (core/wrap-authenticate api-handler [sess-strat])
        oauth-handler (oauth2/make-oauth-success-handler
                       {:provider-key        :google
                        :session-key         session-key
                        :fetch-profile-fn    (constantly {:email "alice@example.com"})
                        :login-fn            (fn [profile]
                                               {:user-id 1 :email (:email profile)})
                        :success-redirect-uri "/home"})
        logout-handler (session/logout-handler {:redirect-uri "/"})]

    (testing "unauthenticated returns 401"
      (is (= 401 (:status (app {:headers {}})))))

    (testing "OAuth2 login then session auth"
      (let [oauth-resp (oauth-handler {:oauth2/access-tokens {:google {:token "tok"}}
                                       :session {}})
            session    (:session oauth-resp)
            api-resp   (app {:session session :headers {}})]
        (is (= 200 (:status api-resp)))
        (is (= {:user-id 1 :email "alice@example.com"}
               (:body api-resp)))))

    (testing "bearer token header is ignored without bearer strategy"
      (is (= 401 (:status (app {:headers {"authorization" "Bearer some-token"}})))))

    (testing "login-fn returning nil rejects user"
      (let [reject-handler (oauth2/make-oauth-success-handler
                            {:provider-key        :google
                             :session-key         session-key
                             :fetch-profile-fn    (constantly {:email "banned@example.com"})
                             :login-fn            (constantly nil)
                             :success-redirect-uri "/"})]
        (is (= 403 (:status (reject-handler {:oauth2/access-tokens {:google {:token "tok"}}
                                             :session {}}))))))

    (testing "logout clears session and redirects"
      (let [resp (logout-handler {:request-method :post
                                  :session        {session-key {:user-id 1}}})]
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
                                :session {session-key {:user-id 1}}})))))))
