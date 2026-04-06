(ns flybot.oie.token-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [flybot.oie.token :as token]))

(deftest generate-token-test
  (testing "returns SensitiveToken with correct prefix"
    (let [t (token/generate-token "hb_live_")]
      (is (instance? flybot.oie.token.SensitiveToken t))
      (is (str/starts-with? (:value t) "hb_live_"))))
  (testing "each call produces a unique token"
    (is (not= (:value (token/generate-token "t_"))
              (:value (token/generate-token "t_")))))
  (testing "print-dup does not leak token value"
    (is (= "#<sensitive-token>"
           (binding [*print-dup* true]
             (pr-str (token/generate-token "t_")))))))

(deftest hash-token-test
  (testing "deterministic 64-char hex"
    (is (= 64 (count (token/hash-token "x"))))
    (is (= (token/hash-token "x") (token/hash-token "x"))))
  (testing "accepts SensitiveToken"
    (is (= (token/hash-token "raw")
           (token/hash-token (token/->SensitiveToken "raw"))))))

(deftest token-active-test
  (testing "active token (nil revoked-at)"
    (is (true? (token/token-active? {:revoked-at nil :expires-at 2000} 1000))))
  (testing "active token (0 revoked-at)"
    (is (true? (token/token-active? {:revoked-at 0 :expires-at 2000} 1000))))
  (testing "expired token"
    (is (false? (token/token-active? {:revoked-at nil :expires-at 500} 1000))))
  (testing "revoked token"
    (is (false? (token/token-active? {:revoked-at 999 :expires-at 2000} 1000))))
  (testing "nil token data"
    (is (false? (token/token-active? nil 1000)))))
