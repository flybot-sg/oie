(ns flybot.oie.core)

(defn add [a b]
  (+ a b))

^:rct/test
(comment
  (add 1 2)
  ;; => 3

  (add 0 0)
  ;; => 0

  (add -1 1)
  ;; => 0
  )
