(ns fixtures.crypto-tls
  (:require [clojure.xml :as xml]
            [clojure.data.xml :as dxml])
  (:import [javax.crypto Cipher]
           [javax.net.ssl SSLContext HostnameVerifier]
           [java.security MessageDigest]))

;; --- read-string: honors #= reader-eval, so this is RCE ---------------------
(defn parse-config [s]
  (read-string s))

;; --- XXE: JVM SAX defaults resolve external entities -----------------------
;; Two aliases for the same sink family, guarding the enumerated alias list.
(defn parse-feed [f] (xml/parse f))
(defn parse-doc  [f] (dxml/parse f))

;; --- weak crypto -----------------------------------------------------------
;; Blowfish and DESede are here specifically because clj-holmes shipped rules
;; for both and matched neither; these fixtures pin that regression closed.
(defn digest-md5  [] (MessageDigest/getInstance "MD5"))
(defn digest-sha1 [] (MessageDigest/getInstance "SHA-1"))
(defn cipher-ecb  [] (Cipher/getInstance "AES/ECB/PKCS5Padding"))
(defn cipher-bf   [] (Cipher/getInstance "Blowfish"))
(defn cipher-3des [] (Cipher/getInstance "DESede/CBC/PKCS5Padding"))
(defn cipher-des  [] (Cipher/getInstance "DES"))

;; --- TLS without authentication -------------------------------------------
(defn ctx-ssl []  (SSLContext/getInstance "SSL"))
(defn ctx-tls1 [] (SSLContext/getInstance "TLSv1"))
(defn trust-any-host []
  (reify HostnameVerifier
    (verify [_ _ _] true)))
(defn fetch [url]
  ;; clj-http style: skips certificate validation entirely
  {:url url :insecure? true})
