(ns cerber.oauth2.pkce
  (:require [cerber.error :as error]
            [cerber.oauth2.context :as ctx]
            [failjure.core :as f]
            [clojure.data.codec.base64 :as b64])
  (:import (java.nio.charset StandardCharsets)
           (java.security MessageDigest)
           (java.util Base64)))

(def supported-code-challenge-methods
  #{"plain" "S256"})

;; defmethod for code_challenge_method -> plain, S256
;; store the code_challenge

;; verify code_verifier

(def code-challenge-format
  ;; Also add -._~
  #"\p{Alnum}+")

;; TODO: require PKCE?, 4.4.1

(comment)

(defn url-safe-base64-encode [^bytes bytes]
  (let [encoder (.withoutPadding (Base64/getUrlEncoder))]
    (.encode encoder bytes)))

(defn sha-256-code-challenge
  "Creates the code challenge from a code verifier.

   RFC7636 4.2, 4.6, Appendix B
   BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))"
  [code-verifier]
  (let [digest (MessageDigest/getInstance "SHA-256")]
    (String. ^bytes (->> (.getBytes code-verifier StandardCharsets/US_ASCII)
                         (.digest digest)
                         (url-safe-base64-encode))
             StandardCharsets/UTF_8)))

;; TODO: tests for all 3 conditions
(defn code-challenge-valid? [req]
  ;; Check - code_verifier between 43 and 128 chars and matches the format
  ;; Check code_challenge_method supported

  (if (contains? (:params req) :code_challenge)
    (f/attempt-all [code-challenge (get-in req [:params :code_challenge] (assoc error/invalid-request
                                                                               :message "PKCE code_challenge is required"))
                    code-challenge-method (get-in req [:params :code_challenge_method] (assoc error/invalid-request
                                                                                         :message "PKCE code_challenge_method is required"))
                    code-challenge-method (if (contains? supported-code-challenge-methods code-challenge-method)
                                            code-challenge-method
                                            (assoc error/invalid-request
                                              :message (format "PKCE code_challenge_method transform algorithm not supported for '%s'" code-challenge-method)))]
                   ;; TODO: how to handle optional code challenge, how to handle plain/S256?
                   (assoc req ::code-challenge (get-in req [:params :code_challenge])
                              ::code-challenge-method code-challenge-method))
    req))

(defmulti verify-code-verifier (fn [authcode verifier] (:code-challenge-method authcode)))

(defmethod verify-code-verifier
  "S256"
  [{:keys [code-challenge] :as authcode} code-verifier]
  (and (some? code-verifier)
       (some? code-challenge)
       (= code-challenge
          (sha-256-code-challenge code-verifier))))

(defn code-verifier-valid? [{:keys [::ctx/authcode] :as req}]
  "Checks if the client's code verifier is correct

  RFC7636 4.6"
  (if (:code-challenge-method authcode)
    (f/attempt-all [code-verifier (get-in req [:params :code_verifier] (assoc error/invalid-grant
                                                                         :message "PKCE code verifier is required but not provided"))
                    verified? (or (verify-code-verifier authcode code-verifier)
                                  (assoc error/invalid-grant
                                    :message "Couldn't verify code_verifier"))]
      req)
    req))
