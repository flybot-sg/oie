(ns flybot.oie.session)

(def session-key
  "Key under which the authenticated identity is stored in the Ring session.
   Used internally by session-strategy, wrap-oauth2, and wrap-magic-link."
  ::user)

(def return-to-key
  "Key under which the post-login redirect path is stored in the Ring session.
   Written at launch from a validated `?return-to` query param, removed when
   login completes."
  ::return-to)

(def ^:private max-return-path-length
  "Keeps a cookie-stored session under the 4096-byte browser cookie limit."
  512)

(def ^:private return-path-re
  "Allowlist of a same-origin path: a single leading `/` followed only by
   RFC 3986 path/query characters, plus Unicode letters, marks and numbers so
   that percent-decoded international paths survive. Everything else — control
   characters, whitespace, backslashes, protocol-relative `//host` — is out."
  #"/(?!/)[\p{L}\p{M}\p{N}._~!$&'()*+,;=:@%/?#-]*")

(defn safe-return-path
  "Returns `path` when it is a same-origin path safe to redirect to, nil otherwise."
  [path]
  (when (and (string? path)
             (<= (count path) max-return-path-length)
             (re-matches return-path-re path))
    path))

^:rct/test
(comment
  (safe-return-path "/dashboards/abc") ;; => "/dashboards/abc"
  (safe-return-path "/") ;; => "/"
  (safe-return-path "/dashboards/abc?tab=1") ;; => "/dashboards/abc?tab=1"
  (safe-return-path "/reports/café") ;; => "/reports/café"
  (safe-return-path "/レポート/42") ;; => "/レポート/42"
  (safe-return-path "//evil.com") ;; => nil
  (safe-return-path "///evil.com") ;; => nil
  (safe-return-path "/\\evil.com") ;; => nil
  (safe-return-path "https://evil.com") ;; => nil
  (safe-return-path "javascript:alert(1)") ;; => nil
  (safe-return-path "/x\nSet-Cookie: a=1") ;; => nil
  (safe-return-path "/x\u0085y") ;; => nil
  (safe-return-path "/x\u00a0y") ;; => nil
  (safe-return-path "/x\u2028y") ;; => nil
  (safe-return-path "/x\u200by") ;; => nil
  (safe-return-path (apply str "/" (repeat 600 "a"))) ;; => nil
  (safe-return-path ["/a" "/b"]) ;; => nil
  (safe-return-path "") ;; => nil
  (safe-return-path nil) ;; => nil
  )

(defn logout-handler
  "Returns a Ring handler that clears the session on POST.
   Returns 405 for non-POST requests.
   Callers should apply `ring.middleware.anti-forgery/wrap-anti-forgery`
   to protect against cross-site request forgery.

   Options:
   - `:response-fn` - zero-arg fn returning a Ring response map. Use for SPAs
     where a redirect is not useful. Session is always cleared regardless.
   - `:redirect-uri` - redirect target (default \"/\"). Ignored when
     `:response-fn` is provided."
  [{:keys [redirect-uri response-fn] :or {redirect-uri "/"}}]
  (fn [req]
    (if (= :post (:request-method req))
      (if response-fn
        (assoc (response-fn) :session nil)
        {:status 302 :headers {"Location" redirect-uri} :session nil})
      {:status 405 :headers {"Allow" "POST"}})))

^:rct/test
(comment
  ;; POST clears session and redirects
  (let [handler (logout-handler {:redirect-uri "/home"})]
    (handler {:request-method :post :session {:user "alice"}}))
  ;; => {:status 302, :headers {"Location" "/home"}, :session nil}

  ;; defaults to "/" when no redirect-uri
  (let [handler (logout-handler {})]
    (handler {:request-method :post :session {:user "alice"}}))
  ;; => {:status 302, :headers {"Location" "/"}, :session nil}

  ;; response-fn replaces the redirect
  (let [handler (logout-handler {:response-fn (fn [] {:status 200 :body {:authenticated false}})})]
    (handler {:request-method :post :session {:user "alice"}}))
  ;; => {:status 200, :body {:authenticated false}, :session nil}

  ;; response-fn always clears session even if response includes one
  (let [handler (logout-handler {:response-fn (fn [] {:status 200 :session {:leftover true}})})]
    (handler {:request-method :post :session {:user "alice"}}))
  ;; => {:status 200, :session nil}

  ;; response-fn with non-POST still returns 405
  (let [handler (logout-handler {:response-fn (fn [] {:status 200 :body {:ok true}})})]
    (handler {:request-method :get}))
  ;; => {:status 405, :headers {"Allow" "POST"}}

  ;; GET returns 405
  (let [handler (logout-handler {:redirect-uri "/"})]
    (handler {:request-method :get}))
  ;; => {:status 405, :headers {"Allow" "POST"}}

  ;; PUT returns 405
  (let [handler (logout-handler {:redirect-uri "/"})]
    (handler {:request-method :put}))
  ;; => {:status 405, :headers {"Allow" "POST"}}
  )

(defn session-timeout-handler
  "Returns a Ring handler for session timeout responses.
   Returns 401 with a redirect hint for clients to handle re-authentication.
   Intended for use with `ring.middleware.session-timeout/wrap-idle-session-timeout`."
  [{:keys [redirect-uri] :or {redirect-uri "/"}}]
  (fn [_]
    {:status 401
     :body   {:type :session-timeout :redirect redirect-uri}}))

^:rct/test
(comment
  ;; returns 401 with redirect hint
  (let [handler (session-timeout-handler {:redirect-uri "/login"})]
    (handler {}))
  ;; => {:status 401, :body {:type :session-timeout, :redirect "/login"}}

  ;; redirect-uri is included in body
  (let [handler (session-timeout-handler {:redirect-uri "/auth/google"})]
    (:body (handler {})))
  ;; => {:type :session-timeout, :redirect "/auth/google"}
  )
