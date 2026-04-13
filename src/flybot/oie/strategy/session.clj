(ns flybot.oie.strategy.session
  (:require [flybot.oie.session :as session]))

(defn session-strategy
  "Returns a strategy map that checks the session for an authenticated user.
   Reads identity from the hardcoded session key `::session/user`."
  []
  {:authenticate (fn [req]
                   (when-let [ident (get-in req [:session session/session-key])]
                     {:authenticated ident}))})

^:rct/test
(comment
  ;; session with identity authenticates
  (let [auth (:authenticate (session-strategy))]
    (:authenticated (auth {:session {::session/user {:email "alice@example.com"}}})))
  ;; => {:email "alice@example.com"}

  ;; empty session skips (nil)
  (let [auth (:authenticate (session-strategy))]
    (auth {:session {}}))
  ;; => nil

  ;; no session skips (nil)
  (let [auth (:authenticate (session-strategy))]
    (auth {}))
  ;; => nil
  )
