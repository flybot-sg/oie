(ns flybot.oie.strategy.bearer-test
  (:require [clojure.test :refer [deftest is testing]]
            [flybot.oie.core :as core]
            [flybot.oie.strategy.bearer :as bearer]
            [flybot.oie.token :as token]))

(deftest bearer-token-strategy-test
  (testing "valid token authenticates"
    (let [raw     "test-token"
          th      (token/hash-token raw)
          data    {:username "alice" :revoked-at nil
                   :expires-at 2000}
          s       (bearer/bearer-token-strategy {:verify-token #(when (= % th) data)
                                                 :clock (constantly 1000)})
          handler (core/wrap-authenticate identity [s])
          resp    (handler {:headers {"authorization" (str "Bearer " raw)}})]
      (is (= "alice" (:username (core/get-identity resp))))))

  (testing "unknown token returns 401 with error from authenticate"
    (let [s       (bearer/bearer-token-strategy {:verify-token (constantly nil)})
          handler (core/wrap-authenticate identity [s])
          resp    (handler {:headers {"authorization" "Bearer bad"}})]
      (is (= 401 (:status resp)))
      (is (= {:type    :invalid-token
              :message "Token is invalid, revoked, or expired."}
             (:body resp)))))

  (testing "expired token returns 401"
    (let [data    {:revoked-at nil :expires-at 0}
          s       (bearer/bearer-token-strategy {:verify-token (constantly data)})
          handler (core/wrap-authenticate identity [s])
          resp    (handler {:headers {"authorization" "Bearer expired"}})]
      (is (= 401 (:status resp)))))

  (testing "revoked token returns 401"
    (let [data    {:revoked-at 1000 :expires-at 2000}
          s       (bearer/bearer-token-strategy {:verify-token (constantly data)
                                                 :clock (constantly 500)})
          handler (core/wrap-authenticate identity [s])
          resp    (handler {:headers {"authorization" "Bearer revoked"}})]
      (is (= 401 (:status resp)))))

  (testing "no Authorization header skips strategy"
    (let [auth-fn (:authenticate (bearer/bearer-token-strategy {:verify-token (constantly nil)}))]
      (is (nil? (auth-fn {:headers {}})))))

  (testing "non-Bearer header skips strategy"
    (let [auth-fn (:authenticate (bearer/bearer-token-strategy {:verify-token (constantly nil)}))]
      (is (nil? (auth-fn {:headers {"authorization" "Basic dXNlcjpw"}})))))

  (testing "case-insensitive Bearer scheme (RFC 6750)"
    (let [raw     "test-token"
          th      (token/hash-token raw)
          data    {:username "alice" :revoked-at nil
                   :expires-at 2000}
          s       (bearer/bearer-token-strategy {:verify-token #(when (= % th) data)
                                                 :clock (constantly 1000)})
          handler (core/wrap-authenticate identity [s])
          resp    (handler {:headers {"authorization" (str "bearer " raw)}})]
      (is (= "alice" (:username (core/get-identity resp))))))

  (testing "Bearer with nothing after space skips strategy"
    (let [auth-fn (:authenticate (bearer/bearer-token-strategy {:verify-token (constantly nil)}))]
      (is (nil? (auth-fn {:headers {"authorization" "Bearer "}}))))))
