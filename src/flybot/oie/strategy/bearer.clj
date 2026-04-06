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
  (require '[flybot.oie.core :as core])

  ;; valid token authenticates
  (let [raw     "test-token"
        th      (token/hash-token raw)
        data    {:username "alice" :roles #{:user} :revoked-at nil
                 :expires-at 2000}
        s       (bearer-token-strategy {:verify-token #(when (= % th) data)
                                        :clock (constantly 1000)})
        handler (core/wrap-authenticate identity [s])
        resp    (handler {:headers {"authorization" (str "Bearer " raw)}})]
    (:username (core/get-identity resp)))
  ;; => "alice"

  ;; unknown token returns 401
  (let [s       (bearer-token-strategy {:verify-token (constantly nil)})
        handler (core/wrap-authenticate identity [s])
        resp    (handler {:headers {"authorization" "Bearer bad"}})]
    (:status resp))
  ;; => 401

  ;; expired token returns 401
  (let [data    {:revoked-at nil :expires-at 0}
        s       (bearer-token-strategy {:verify-token (constantly data)})
        handler (core/wrap-authenticate identity [s])
        resp    (handler {:headers {"authorization" "Bearer expired"}})]
    (:status resp))
  ;; => 401

  ;; revoked token returns 401
  (let [data    {:revoked-at 1000 :expires-at 2000}
        s       (bearer-token-strategy {:verify-token (constantly data)
                                        :clock (constantly 500)})
        handler (core/wrap-authenticate identity [s])
        resp    (handler {:headers {"authorization" "Bearer revoked"}})]
    (:status resp))
  ;; => 401

  ;; no Authorization header skips strategy (nil)
  (let [s (:authenticate (bearer-token-strategy {:verify-token (constantly nil)}))]
    (s {:headers {}}))
  ;; => nil

  ;; non-Bearer header skips strategy
  (let [s (:authenticate (bearer-token-strategy {:verify-token (constantly nil)}))]
    (s {:headers {"authorization" "Basic dXNlcjpw"}}))
  ;; => nil

  ;; case-insensitive Bearer scheme (RFC 6750)
  (let [raw     "test-token"
        th      (token/hash-token raw)
        data    {:username "alice" :revoked-at nil
                 :expires-at 2000}
        s       (bearer-token-strategy {:verify-token #(when (= % th) data)
                                        :clock (constantly 1000)})
        handler (core/wrap-authenticate identity [s])
        resp    (handler {:headers {"authorization" (str "bearer " raw)}})]
    (:username (core/get-identity resp)))
  ;; => "alice"

  ;; "Bearer " with nothing after it skips strategy
  (let [s (:authenticate (bearer-token-strategy {:verify-token (constantly nil)}))]
    (s {:headers {"authorization" "Bearer "}}))
  ;; => nil
  )
