(ns flybot.oie.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [flybot.oie.core :as core]))

(deftest wrap-authenticate-test
  (testing "successful authentication assocs identity"
    (let [s       {:authenticate (fn [_] {:authenticated {:user "alice"}})}
          handler (core/wrap-authenticate identity [s])
          resp    (handler {})]
      (is (= {:user "alice"} (core/get-identity resp)))))

  (testing "first matching strategy wins"
    (let [s1      {:authenticate (fn [_] nil)}
          s2      {:authenticate (fn [_] {:authenticated {:user "bob"}})}
          handler (core/wrap-authenticate identity [s1 s2])
          resp    (handler {})]
      (is (= {:user "bob"} (core/get-identity resp)))))

  (testing "all nil returns 401"
    (let [s       {:authenticate (fn [_] nil)}
          handler (core/wrap-authenticate identity [s])
          resp    (handler {})]
      (is (= 401 (:status resp)))))

  (testing "error returns 401"
    (let [s       {:authenticate (fn [_] {:error {:type :bad}})}
          handler (core/wrap-authenticate identity [s])
          resp    (handler {})]
      (is (= 401 (:status resp)))))

  (testing "error data is passed to unauthorized fn"
    (let [error   {:type :bad-token :detail "expired"}
          s       {:authenticate (fn [_] {:error error})
                   :unauthorized (fn [_req e] {:status 401 :body e})}
          handler (core/wrap-authenticate identity [s])
          resp    (handler {})]
      (is (= error (:body resp)))))

  (testing "first error's unauthorized fn is preferred over later errors"
    (let [s1      {:authenticate (fn [_] {:error {:type :a}})
                   :unauthorized (fn [_req _e] {:status 401 :body "first"})}
          s2      {:authenticate (fn [_] {:error {:type :b}})
                   :unauthorized (fn [_req _e] {:status 401 :body "second"})}
          handler (core/wrap-authenticate identity [s1 s2])
          resp    (handler {})]
      (is (= "first" (:body resp)))))

  (testing "non-erroring strategy's unauthorized fn is ignored"
    (let [s       {:authenticate (fn [_] nil)
                   :unauthorized (fn [_req _e] {:status 401 :body "should not appear"})}
          handler (core/wrap-authenticate identity [s])
          resp    (handler {})]
      (is (= 401 (:status resp)))
      (is (nil? (:body resp)))))

  (testing "error in early strategy, success in later still authenticates"
    (let [s1      {:authenticate (fn [_] {:error {:type :bad}})}
          s2      {:authenticate (fn [_] {:authenticated {:user "carol"}})}
          handler (core/wrap-authenticate identity [s1 s2])
          resp    (handler {})]
      (is (= {:user "carol"} (core/get-identity resp))))))

(deftest get-identity-test
  (testing "returns nil for unauthenticated request"
    (is (nil? (core/get-identity {})))))
