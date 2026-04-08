(ns flybot.oie.strategy.session)

(defn session-strategy
  "Returns a strategy map that checks the session for an authenticated user.
   `session-key` — the key under which the identity is stored in the session."
  [{:keys [session-key]}]
  {:authenticate (fn [req]
                   (when-let [ident (get-in req [:session session-key])]
                     {:authenticated ident}))})

^:rct/test
(comment
  ;; session with identity authenticates
  (let [auth (:authenticate (session-strategy {:session-key :oie/user}))]
    (:authenticated (auth {:session {:oie/user {:email "alice@example.com"}}})))
  ;; => {:email "alice@example.com"}

  ;; empty session skips (nil)
  (let [auth (:authenticate (session-strategy {:session-key :oie/user}))]
    (auth {:session {}}))
  ;; => nil

  ;; no session skips (nil)
  (let [auth (:authenticate (session-strategy {:session-key :oie/user}))]
    (auth {}))
  ;; => nil
  )
