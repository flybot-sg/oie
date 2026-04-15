(ns flybot.oie.schema
  "Malli schemas for oie middleware config validation.
   Intended for consumer-side validation at system startup, before
   constructing middleware. Call `validate-config` with the appropriate
   schema to get clear error messages early."
  (:require [malli.core :as m]
            [malli.error :as me]))

(def ^:private redirect-uri-schema
  [:or :string fn?])

(def strategy-schema
  [:map
   [:authenticate fn?]
   [:unauthorized {:optional true} fn?]])

(def wrap-authenticate-schema
  [:sequential strategy-schema])

(def wrap-authenticate-opts-schema
  [:map
   [:allow-anonymous? {:optional true} :boolean]])

(def bearer-token-strategy-schema
  [:map
   [:verify-token fn?]
   [:clock {:optional true} fn?]])

(def logout-handler-schema
  [:map
   [:redirect-uri {:optional true} :string]])

(def session-timeout-handler-schema
  [:map
   [:redirect-uri {:optional true} :string]])

(def wrap-magic-link-schema
  [:map
   [:verify-uri :string]
   [:request-uri :string]
   [:secret :string]
   [:consume-nonce fn?]
   [:store-nonce fn?]
   [:send-fn fn?]
   [:login-fn fn?]
   [:success-redirect-uri redirect-uri-schema]
   [:token-ttl pos-int?]
   [:token-param {:optional true} :string]
   [:request-param {:optional true} :string]
   [:clock {:optional true} fn?]])

(def ^:private oauth2-profile-schema
  [:map
   [:authorize-uri :string]
   [:access-token-uri :string]
   [:client-id :string]
   [:client-secret :string]
   [:scopes [:sequential :keyword]]
   [:launch-uri :string]
   [:redirect-uri :string]
   [:landing-uri :string]
   [:fetch-profile-fn fn?]
   [:login-fn fn?]
   [:success-redirect-uri redirect-uri-schema]])

(def wrap-oauth2-schema
  [:map-of :keyword oauth2-profile-schema])

(defn validate-config
  "Validates `value` against `schema`. Returns `value` if valid.
   Throws ex-info with humanized errors on failure."
  [schema value context]
  (if (m/validate schema value)
    value
    (throw (ex-info (str "Invalid config: " context)
                    {:context context
                     :errors  (-> schema (m/explain value) me/humanize)}))))

^:rct/test
(comment
  ;; wrong type throws
  (try
    (validate-config bearer-token-strategy-schema {:verify-token "not-a-fn"} "bearer-token-strategy")
    (catch Exception e
      (-> e ex-data :errors :verify-token)))
  ;; => ["should be a fn"]

  ;; optional keys are not required
  (validate-config logout-handler-schema {} "logout-handler")
  ;; => {}

  ;; valid magic-link config passes
  (validate-config wrap-magic-link-schema
                   {:verify-uri "/auth" :request-uri "/auth/request"
                    :secret "s" :consume-nonce identity :store-nonce identity
                    :send-fn identity :login-fn identity
                    :success-redirect-uri "/" :token-ttl 600000}
                   "wrap-magic-link")
  ;=>> {:verify-uri "/auth"}

  ;; magic-link missing multiple keys
  (try
    (validate-config wrap-magic-link-schema {:verify-uri "/auth"} "wrap-magic-link")
    (catch Exception e
      (sort (keys (-> e ex-data :errors)))))
  ;; => (:consume-nonce :login-fn :request-uri :secret :send-fn :store-nonce :success-redirect-uri :token-ttl)

  ;; valid oauth2 profiles pass
  (validate-config wrap-oauth2-schema
                   {:google {:authorize-uri "https://a" :access-token-uri "https://t"
                             :client-id "id" :client-secret "s" :scopes [:openid]
                             :launch-uri "/l" :redirect-uri "/r" :landing-uri "/land"
                             :fetch-profile-fn identity
                             :login-fn identity :success-redirect-uri "/"}}
                   "wrap-oauth2")
  ;=>> {:google {:authorize-uri "https://a"}}

  ;; wrap-authenticate validates strategy shape
  (validate-config wrap-authenticate-schema
                   [{:authenticate identity}]
                   "wrap-authenticate")
  ;=>> [{:authenticate fn?}]

  ;; wrap-authenticate opts validates allow-anonymous?
  (validate-config wrap-authenticate-opts-schema
                   {:allow-anonymous? true}
                   "wrap-authenticate-opts")
  ;; => {:allow-anonymous? true}

  ;; wrap-authenticate opts rejects non-boolean
  (try
    (validate-config wrap-authenticate-opts-schema
                     {:allow-anonymous? "yes"}
                     "wrap-authenticate-opts")
    (catch Exception e
      (-> e ex-data :errors :allow-anonymous?)))
  ;; => ["should be a boolean"]

  ;; empty opts map is valid
  (validate-config wrap-authenticate-opts-schema {} "wrap-authenticate-opts")
  ;; => {}
  )
