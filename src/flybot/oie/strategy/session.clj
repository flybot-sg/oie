(ns flybot.oie.strategy.session
  (:require [flybot.oie.session :as session]))

(defn session-strategy
  "Returns a strategy map that checks the session for an authenticated user.
   Reads identity from the hardcoded session key `::session/user`.

   Options:
   - `:verify` `(fn [identity] -> identity | nil)` — optional re-validation.
     Called with the session identity on every request. Return a (possibly
     enriched) identity to authenticate, or nil to treat the session as stale
     and skip to the next strategy."
  ([]
   (session-strategy {}))
  ([{:keys [verify]}]
   {:authenticate (fn [req]
                    (when-let [ident (get-in req [:session session/session-key])]
                      (if verify
                        (when-let [verified (verify ident)]
                          {:authenticated verified})
                        {:authenticated ident})))}))

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

  ;; verify fn returning identity authenticates
  (let [auth (:authenticate (session-strategy {:verify identity}))]
    (:authenticated (auth {:session {::session/user {:email "alice@example.com"}}})))
  ;; => {:email "alice@example.com"}

  ;; verify fn returning nil skips (stale session)
  (let [auth (:authenticate (session-strategy {:verify (constantly nil)}))]
    (auth {:session {::session/user {:email "alice@example.com"}}}))
  ;; => nil

  ;; verify fn can enrich the identity
  (let [auth (:authenticate (session-strategy {:verify #(assoc % :fresh true)}))]
    (:authenticated (auth {:session {::session/user {:email "alice@example.com"}}})))
  ;; => {:email "alice@example.com", :fresh true}

  ;; verify fn not called when session is empty
  (let [called (atom false)
        auth   (:authenticate (session-strategy {:verify (fn [_] (reset! called true))}))]
    [(auth {:session {}}) @called])
  ;; => [nil false]

  ;; empty opts map behaves like no-arg
  (let [auth (:authenticate (session-strategy {}))]
    (:authenticated (auth {:session {::session/user {:email "alice@example.com"}}})))
  ;; => {:email "alice@example.com"}
  )
