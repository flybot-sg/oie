(ns flybot.oie.magic-link
  (:require [clojure.string :as str])
  (:import [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]
           [java.security MessageDigest]
           [java.util Base64]))

(defn- base64url-encode [^bytes bs]
  (-> (Base64/getUrlEncoder) .withoutPadding (.encodeToString bs)))

(defn- base64url-decode [^String s]
  (.decode (Base64/getUrlDecoder) s))

(defn- hmac-sha256 [^String secret ^String message]
  (let [secret-key (SecretKeySpec. (.getBytes secret "UTF-8") "HmacSHA256")
        mac        (doto (Mac/getInstance "HmacSHA256") (.init secret-key))]
    (.doFinal mac (.getBytes message "UTF-8"))))

(defn create-magic-link-token
  "Creates an HMAC-signed magic link token.
   `secret` — HMAC key string.
   `email` — the user's email.
   `nonce` — random single-use nonce (caller generates and stores this).
   `expires-at` — expiry as epoch ms.
   Returns a URL-safe token string: `base64url(email|nonce|expires-at).base64url(signature)`."
  [{:keys [secret email nonce expires-at]}]
  (let [payload (str email "|" nonce "|" expires-at)]
    (str (base64url-encode (.getBytes payload "UTF-8"))
         "."
         (base64url-encode (hmac-sha256 secret payload)))))

^:rct/test
(comment
  (= 2 (count (str/split (create-magic-link-token {:secret     "test-secret"
                                                   :email      "alice@example.com"
                                                   :nonce      "nonce123"
                                                   :expires-at 2000})
                         #"\.")))
  ;; => true

  (let [opts {:secret "s" :email "a@b.com" :nonce "n" :expires-at 1000}]
    (= (create-magic-link-token opts)
       (create-magic-link-token opts)))
  ;; => true

  (let [base {:email "a@b.com" :nonce "n" :expires-at 1000}]
    (= (create-magic-link-token (assoc base :secret "s1"))
       (create-magic-link-token (assoc base :secret "s2"))))
  ;; => false
  )

(defn- parse-and-verify
  [secret token]
  (try
    (let [[encoded-payload encoded-sig] (str/split token #"\." 2)]
      (when (and encoded-payload encoded-sig)
        (let [payload      (String. ^bytes (base64url-decode encoded-payload) "UTF-8")
              expected-sig (hmac-sha256 secret payload)
              actual-sig   (base64url-decode encoded-sig)]
          (when (MessageDigest/isEqual expected-sig actual-sig)
            (let [[email nonce expires-str] (str/split payload #"\|" 3)]
              (when-let [expires-at (and email nonce expires-str
                                         (parse-long expires-str))]
                {:email email :nonce nonce :expires-at expires-at}))))))
    (catch Exception _ nil)))

(defn- verify-token
  [secret token clock consume-nonce]
  (if-let [{:keys [email nonce expires-at]} (parse-and-verify secret token)]
    (cond
      (< expires-at (clock))
      {:error {:type :expired :message "Magic link has expired."}}

      (not (consume-nonce nonce))
      {:error {:type :already-used :message "Magic link has already been used."}}

      :else
      {:verified {:email email}})
    {:error {:type :invalid-token :message "Magic link token is invalid."}}))

(defn wrap-magic-link
  "Ring middleware for magic link authentication.
   Intercepts requests to `verify-uri`, validates the token, calls `login-fn`,
   stores identity in session, and redirects. All other requests pass through.

   Config:
   - `verify-uri` — URI path to intercept
   - `secret` — HMAC key string
   - `consume-nonce` — `(fn [nonce] -> truthy | nil)`, atomically consume nonce
   - `login-fn` — `(fn [profile] -> identity | nil)`, app-level authorization
   - `session-key` — key to store identity in session
   - `success-redirect-uri` — string or `(fn [req] -> uri)`
   - `token-param` — query param name, defaults to `\"token\"`
   - `clock` — `(fn [] -> epoch-ms)`, defaults to `System/currentTimeMillis`"
  [handler {:keys [verify-uri secret consume-nonce login-fn session-key
                   success-redirect-uri token-param clock]
            :or   {token-param "token" clock #(System/currentTimeMillis)}}]
  (fn [request]
    (if (and (= (:uri request) verify-uri)
             (= :get (:request-method request)))
      (if-let [token (get-in request [:query-params token-param])]
        (let [result (verify-token secret token clock consume-nonce)
              ident  (some-> (:verified result) login-fn)]
          (cond
            (:error result)
            {:status 401 :body (:error result)}

            (nil? ident)
            {:status 403}

            :else
            {:status  302
             :headers {"Location" (if (fn? success-redirect-uri)
                                    (success-redirect-uri request)
                                    success-redirect-uri)}
             :session (assoc (:session request) session-key ident)}))
        {:status 401 :body {:type :missing-token :message "No magic link token provided."}})
      (handler request))))

^:rct/test
(comment
  (def ^:private test-secret "test-secret")
  (def ^:private test-clock (constantly 1000))

  (defn- make-handler [opts]
    (wrap-magic-link (constantly {:status 200 :body "ok"})
                     (merge {:verify-uri           "/auth/magic-link"
                             :secret               test-secret
                             :consume-nonce         (constantly true)
                             :login-fn              (fn [{:keys [email]}]
                                                      {:user-id 1 :email email})
                             :session-key           :oie/user
                             :success-redirect-uri  "/"
                             :clock                 test-clock}
                            opts)))

  ;; valid token → 302 redirect with session
  (let [token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "n1" :expires-at 2000})
        handler (make-handler {})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" token} :session {}})]
    [(:status resp)
     (get-in resp [:headers "Location"])
     (get-in resp [:session :oie/user])])
  ;; => [302 "/" {:user-id 1, :email "alice@example.com"}]

  ;; expired token → 401
  (let [token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "n" :expires-at 500})
        handler (make-handler {})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" token} :session {}})]
    [(:status resp) (get-in resp [:body :type])])
  ;; => [401 :expired]

  ;; already-used nonce → 401
  (let [token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "used" :expires-at 2000})
        handler (make-handler {:consume-nonce (constantly nil)})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" token} :session {}})]
    [(:status resp) (get-in resp [:body :type])])
  ;; => [401 :already-used]

  ;; invalid token → 401
  (let [handler (make-handler {})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" "garbage"} :session {}})]
    [(:status resp) (get-in resp [:body :type])])
  ;; => [401 :invalid-token]

  ;; tampered token → 401
  (let [token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "n" :expires-at 2000})
        handler (make-handler {})
        resp    (handler {:uri "/auth/magic-link" :request-method :get
                          :query-params {"token" (str token "tampered")}
                          :session {}})]
    [(:status resp) (get-in resp [:body :type])])
  ;; => [401 :invalid-token]

  ;; wrong secret → 401
  (let [token   (create-magic-link-token {:secret "real-secret" :email "alice@example.com"
                                          :nonce "n" :expires-at 2000})
        handler (make-handler {})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" token} :session {}})]
    [(:status resp) (get-in resp [:body :type])])
  ;; => [401 :invalid-token]

  ;; no token param → 401
  (let [handler (make-handler {})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {} :session {}})]
    [(:status resp) (get-in resp [:body :type])])
  ;; => [401 :missing-token]

  ;; non-matching URI passes through
  (let [handler (make-handler {})
        resp    (handler {:uri "/other" :query-params {} :session {}})]
    (:status resp))
  ;; => 200

  ;; non-GET to verify URI passes through
  (let [token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "n" :expires-at 2000})
        handler (make-handler {})
        resp    (handler {:uri "/auth/magic-link" :request-method :post
                          :query-params {"token" token} :session {}})]
    (:status resp))
  ;; => 200

  ;; login-fn returns nil → 403
  (let [token   (create-magic-link-token {:secret test-secret :email "banned@example.com"
                                          :nonce "n" :expires-at 2000})
        handler (make-handler {:login-fn (constantly nil)})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" token} :session {}})]
    (:status resp))
  ;; => 403

  ;; custom token-param works
  (let [token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "n" :expires-at 2000})
        handler (make-handler {:token-param "magic"})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"magic" token} :session {}})]
    (:status resp))
  ;; => 302

  ;; success-redirect-uri as function
  (let [token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "n" :expires-at 2000})
        handler (make-handler {:success-redirect-uri
                               (fn [req] (get-in req [:session :return-to] "/"))})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" token}
                          :session {:return-to "/dashboard"}})]
    (get-in resp [:headers "Location"]))
  ;; => "/dashboard"

  ;; preserves existing session data
  (let [token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "n" :expires-at 2000})
        handler (make-handler {})
        resp    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" token}
                          :session {:other-key "keep-me"}})]
    (get-in resp [:session :other-key]))
  ;; => "keep-me"

  ;; consume-nonce NOT called when token expired
  (let [called? (atom false)
        token   (create-magic-link-token {:secret test-secret :email "alice@example.com"
                                          :nonce "n" :expires-at 500})
        handler (make-handler {:consume-nonce (fn [_] (reset! called? true))})]
    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" token} :session {}})
    @called?)
  ;; => false

  ;; consume-nonce NOT called when HMAC invalid
  (let [called? (atom false)
        handler (make-handler {:consume-nonce (fn [_] (reset! called? true))})]
    (handler {:uri "/auth/magic-link" :request-method :get :query-params {"token" "garbage.garbage"} :session {}})
    @called?)
  ;; => false
  )
