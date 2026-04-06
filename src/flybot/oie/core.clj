(ns flybot.oie.core)

(def ^:private identity-key ::identity)

(defn get-identity
  "Extract the authenticated identity from the request."
  [req]
  (get req identity-key))

(defn- try-strategies [strategies req]
  (reduce
   (fn [acc {:keys [authenticate] :as strategy}]
     (let [result (authenticate req)]
       (cond
         (:authenticated result) (reduced result)
         (:error result)         (or acc {::error (:error result) ::strategy strategy})
         :else                   acc)))
   nil
   strategies))

(def ^:private default-401-response
  {:status 401})

(defn wrap-authenticate
  "Ring middleware that tries each strategy in order.
   Each strategy's `:authenticate` fn returns:
   - `{:authenticated data}` — success, assoc identity into request (falsy `data` is treated as a skip)
   - `{:error error}`        — auth attempted but failed
   - `nil`                   — not applicable, try next strategy
   Optional `:unauthorized` `(fn [req error])` handles rejection.
   Only called when the strategy returned an error."
  [handler strategies]
  (fn [req]
    (let [result (try-strategies strategies req)]
      (if (:authenticated result)
        (handler (assoc req identity-key (:authenticated result)))
        (if-let [unauthorized-fn (:unauthorized (::strategy result))]
          (unauthorized-fn req (::error result))
          default-401-response)))))

^:rct/test
(comment
  ;; successful authentication assocs identity
  (let [strategy {:authenticate (fn [_] {:authenticated {:user "alice"}})}
        handler  (wrap-authenticate identity [strategy])
        resp     (handler {})]
    (get-identity resp))
  ;; => {:user "alice"}

  ;; first non-nil wins
  (let [s1      {:authenticate (fn [_] nil)}
        s2      {:authenticate (fn [_] {:authenticated {:user "bob"}})}
        handler (wrap-authenticate identity [s1 s2])
        resp    (handler {})]
    (get-identity resp))
  ;; => {:user "bob"}

  ;; all nil returns 401
  (let [s1      {:authenticate (fn [_] nil)}
        s2      {:authenticate (fn [_] nil)}
        handler (wrap-authenticate identity [s1 s2])
        resp    (handler {})]
    (:status resp))
  ;; => 401

  ;; error without subsequent success returns 401
  (let [s1      {:authenticate (fn [_] {:error {:type :bad-token}})}
        handler (wrap-authenticate identity [s1])
        resp    (handler {})]
    (:status resp))
  ;; => 401

  ;; custom unauthorized fn is used when strategy errors
  (let [s1      {:authenticate (fn [_] {:error {:type :bad}})
                 :unauthorized (fn [_req _error] {:status 401 :body "custom"})}
        handler (wrap-authenticate identity [s1])
        resp    (handler {})]
    (:body resp))
  ;; => "custom"

  ;; error in early strategy, success in later strategy still authenticates
  (let [s1      {:authenticate (fn [_] {:error {:type :bad}})}
        s2      {:authenticate (fn [_] {:authenticated {:user "carol"}})}
        handler (wrap-authenticate identity [s1 s2])
        resp    (handler {})]
    (get-identity resp))
  ;; => {:user "carol"}

  ;; erroring strategy's unauthorized fn is preferred
  (let [s1      {:authenticate (fn [_] {:error {:type :bad}})
                 :unauthorized (fn [_req _error] {:status 401 :body "from-erroring"})}
        s2      {:authenticate (fn [_] nil)
                 :unauthorized (fn [_req _error] {:status 401 :body "from-fallback"})}
        handler (wrap-authenticate identity [s1 s2])
        resp    (handler {})]
    (:body resp))
  ;; => "from-erroring"

  ;; when multiple strategies error, first error's unauthorized fn is used
  (let [s1      {:authenticate (fn [_] {:error {:type :a}})
                 :unauthorized (fn [_req _error] {:status 401 :body "first"})}
        s2      {:authenticate (fn [_] {:error {:type :b}})
                 :unauthorized (fn [_req _error] {:status 401 :body "second"})}
        handler (wrap-authenticate identity [s1 s2])
        resp    (handler {})]
    (:body resp))
  ;; => "first"

  ;; error data is passed to unauthorized fn
  (let [error   {:type :bad-token :detail "expired"}
        s1      {:authenticate (fn [_] {:error error})
                 :unauthorized (fn [_req e] {:status 401 :body e})}
        handler (wrap-authenticate identity [s1])
        resp    (handler {})]
    (:body resp))
  ;; => {:type :bad-token, :detail "expired"}

  ;; get-identity returns nil for unauthenticated request
  (get-identity {})
  ;; => nil
  )
