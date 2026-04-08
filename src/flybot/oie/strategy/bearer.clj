(ns flybot.oie.strategy.bearer
  (:require [clojure.string :as str]
            [flybot.oie.token :as token]))

(defn- extract-bearer-token [headers]
  (when-let [auth-header (get headers "authorization")]
    (when (str/starts-with? (str/lower-case auth-header) "bearer ")
      (not-empty (str/trim (subs auth-header 7))))))

(defn bearer-token-strategy
  "Returns a strategy map for Bearer token authentication.
   `verify-token` is `(fn [token-hash] -> token-data | nil)`.
   `clock` is `(fn [] -> epoch-ms)`, defaults to `System/currentTimeMillis`."
  [{:keys [verify-token clock] :or {clock #(System/currentTimeMillis)}}]
  {:authenticate (fn [req]
                   (when-let [raw (extract-bearer-token (:headers req))]
                     (let [token-data (verify-token (token/hash-token raw))]
                       (if (token/token-active? token-data (clock))
                         {:authenticated token-data}
                         {:error {:type    :invalid-token
                                  :message "Token is invalid, revoked, or expired."}}))))
   :unauthorized (fn [_req error]
                   {:status 401
                    :body   error})})

^:rct/test
(comment
  ;; valid token authenticates
  (let [raw  "test-token"
        th   (token/hash-token raw)
        data {:username "alice" :roles #{:user} :revoked-at nil :expires-at 2000}
        auth (:authenticate (bearer-token-strategy {:verify-token #(when (= % th) data)
                                                    :clock (constantly 1000)}))]
    (:authenticated (auth {:headers {"authorization" (str "Bearer " raw)}})))
  ;; => {:username "alice", :roles #{:user}, :revoked-at nil, :expires-at 2000}

  ;; unknown token returns error
  (let [auth (:authenticate (bearer-token-strategy {:verify-token (constantly nil)}))]
    (:error (auth {:headers {"authorization" "Bearer bad"}})))
  ;; => {:type :invalid-token, :message "Token is invalid, revoked, or expired."}

  ;; expired token returns error
  (let [data {:revoked-at nil :expires-at 0}
        auth (:authenticate (bearer-token-strategy {:verify-token (constantly data)}))]
    (:error (auth {:headers {"authorization" "Bearer expired"}})))
  ;; => {:type :invalid-token, :message "Token is invalid, revoked, or expired."}

  ;; revoked token returns error
  (let [data {:revoked-at 1000 :expires-at 2000}
        auth (:authenticate (bearer-token-strategy {:verify-token (constantly data)
                                                    :clock (constantly 500)}))]
    (:error (auth {:headers {"authorization" "Bearer revoked"}})))
  ;; => {:type :invalid-token, :message "Token is invalid, revoked, or expired."}

  ;; unauthorized handler returns 401
  (let [unauth (:unauthorized (bearer-token-strategy {:verify-token (constantly nil)}))]
    (:status (unauth {} {:type :invalid-token :message "bad"})))
  ;; => 401

  ;; no Authorization header skips strategy (nil)
  (let [auth (:authenticate (bearer-token-strategy {:verify-token (constantly nil)}))]
    (auth {:headers {}}))
  ;; => nil

  ;; non-Bearer header skips strategy
  (let [auth (:authenticate (bearer-token-strategy {:verify-token (constantly nil)}))]
    (auth {:headers {"authorization" "Basic dXNlcjpw"}}))
  ;; => nil

  ;; case-insensitive Bearer scheme (RFC 6750)
  (let [raw  "test-token"
        th   (token/hash-token raw)
        data {:username "alice" :revoked-at nil :expires-at 2000}
        auth (:authenticate (bearer-token-strategy {:verify-token #(when (= % th) data)
                                                    :clock (constantly 1000)}))]
    (:authenticated (auth {:headers {"authorization" (str "bearer " raw)}})))
  ;; => {:username "alice", :revoked-at nil, :expires-at 2000}

  ;; "Bearer " with nothing after it skips strategy
  (let [auth (:authenticate (bearer-token-strategy {:verify-token (constantly nil)}))]
    (auth {:headers {"authorization" "Bearer "}}))
  ;; => nil
  )
