(ns flybot.oie.token
  (:import [java.security MessageDigest SecureRandom]
           [java.util Base64]))

(def ^:private secure-random (SecureRandom.))

(defrecord SensitiveToken [value]
  Object
  (toString [_] "#<sensitive-token>"))

(defmethod print-method SensitiveToken [_ ^java.io.Writer w]
  (.write w "#<sensitive-token>"))

(defmethod print-dup SensitiveToken [_ ^java.io.Writer w]
  (.write w "#<sensitive-token>"))

(defn- ->hex [^bytes bs]
  (->> bs (map #(format "%02x" (bit-and % 0xff))) (apply str)))

(defn generate-token
  "Returns a SensitiveToken with `prefix` + 32 URL-safe base64 characters."
  [prefix]
  (let [bytes (byte-array 24)]
    (.nextBytes secure-random bytes)
    (->SensitiveToken
     (str prefix (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bytes)))))

(defn hash-token
  "SHA-256 hash as 64-char hex string. Accepts string or SensitiveToken."
  [token]
  (let [raw (if (instance? SensitiveToken token) (:value token) token)]
    (-> (MessageDigest/getInstance "SHA-256")
        (.digest (.getBytes ^String raw "UTF-8"))
        ->hex)))

(defn token-active?
  "True if token-data is non-nil, not revoked, and not expired at `now` (epoch ms)."
  [token-data now]
  (and (some? token-data)
       (zero? (or (:revoked-at token-data) 0))
       (> (:expires-at token-data) now)))

^:rct/test
(comment
  (require '[clojure.string :as str])

  (let [t (generate-token "hb_live_")]
    (instance? SensitiveToken t))
  ;; => true

  (let [t (generate-token "hb_live_")]
    (str/starts-with? (:value t) "hb_live_"))
  ;; => true

  (let [t (generate-token "x_")]
    (count (subs (:value t) 2)))
  ;; => 32

  (= (:value (generate-token "t_"))
     (:value (generate-token "t_")))
  ;; => false

  (str (generate-token "t_"))
  ;; => "#<sensitive-token>"

  (binding [*print-dup* true]
    (pr-str (generate-token "t_")))
  ;; => "#<sensitive-token>"

  (count (hash-token "test-token"))
  ;; => 64

  (= (hash-token "same") (hash-token "same"))
  ;; => true

  (= (hash-token "raw") (hash-token (->SensitiveToken "raw")))
  ;; => true

  (token-active? {:revoked-at nil :expires-at 2000} 1000)
  ;; => true

  (token-active? {:revoked-at 0 :expires-at 2000} 1000)
  ;; => true

  (token-active? {:revoked-at nil :expires-at 500} 1000)
  ;; => false

  (token-active? {:revoked-at 999 :expires-at 2000} 1000)
  ;; => false

  (token-active? nil 1000)
  ;; => false

  (->hex (.getBytes "hi" "UTF-8"))
  ;; => "6869"
  )
