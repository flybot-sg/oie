(ns flybot.oie.authz)

(defn has-role?
  "True if `ident` has `role` in its `:roles` collection."
  [ident role]
  (->> ident :roles (some #{role}) boolean))

^:rct/test
(comment
  (has-role? {:roles #{:user :admin}} :admin) ;=> true
  (has-role? {:roles [:user :admin]} :admin) ;=> true
  (has-role? {:roles #{:user}} :admin) ;=> false
  (has-role? {:name "alice"} :admin) ;=> false
  (has-role? nil :admin) ;=> false
  )
