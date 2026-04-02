(ns flybot.oie.rc-test
  (:require [clojure.test :refer [deftest testing]]
            [com.mjdowney.rich-comment-tests.test-runner :as rct-runner]))

(deftest ^:rct rich-comment-tests
  (testing "Rich comment tests."
    (rct-runner/run-tests-in-file-tree! :dirs #{"src"})))
