(ns flybot.oie.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [flybot.oie.core :as core]))

(deftest add-test
  (testing "adds two numbers"
    (is (= 3 (core/add 1 2))))
  (testing "identity"
    (is (= 5 (core/add 5 0))))
  (testing "negative numbers"
    (is (= 0 (core/add -1 1)))))
