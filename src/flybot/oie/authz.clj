(ns flybot.oie.authz)

(defn has-role?
  "True if `ident` has `role` in its `:roles` collection."
  [ident role]
  (some #{role} (:roles ident)))

^:rct/test
(comment
  (has-role? {:roles #{:user :admin}} :admin) ;=> :admin
  (has-role? {:roles [:user :admin]} :admin) ;=> :admin
  (has-role? {:roles #{:user}} :admin) ;=> nil
  (has-role? {:name "alice"} :admin) ;=> nil
  (has-role? nil :admin) ;=> nil
  )
