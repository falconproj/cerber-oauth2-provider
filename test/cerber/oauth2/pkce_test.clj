(ns cerber.oauth2.pkce-test
  (:require [clojure.test :refer [deftest is]]
            [cerber.oauth2.pkce :as pkce]))

(deftest rfc7636-appendix-b-test
  (let [code-verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"]
    (is (= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
           (pkce/sha-256-code-challenge code-verifier)))))
