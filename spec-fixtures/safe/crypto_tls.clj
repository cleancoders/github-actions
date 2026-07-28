(ns fixtures.crypto-tls-safe
  (:require [clojure.edn :as edn])
  (:import [javax.crypto Cipher]
           [javax.net.ssl SSLContext]
           [java.security MessageDigest]))

;; edn/read-string does not honor #= — both the aliased and fully-qualified
;; spellings must stay clean.
(defn parse-config  [s] (edn/read-string s))
(defn parse-config2 [s] (clojure.edn/read-string s))

;; Modern primitives.
(defn digest      [] (MessageDigest/getInstance "SHA-256"))
(defn digest-512  [] (MessageDigest/getInstance "SHA-512"))
(defn cipher-gcm  [] (Cipher/getInstance "AES/GCM/NoPadding"))
(defn cipher-cbc  [] (Cipher/getInstance "AES/CBC/PKCS5Padding"))

;; Protocol negotiation left to the platform, or pinned forward.
(defn ctx-default [] (SSLContext/getInstance "TLS"))
(defn ctx-13      [] (SSLContext/getInstance "TLSv1.3"))
(defn ctx-12      [] (SSLContext/getInstance "TLSv1.2"))

;; NOTE: no hardened clojure.xml/parse call appears here. cc-clojure-xml-xxe is
;; severity WARNING precisely because it cannot tell a hardened factory from a
;; default one — verifying that needs dataflow. Putting a hardened parse in this
;; corpus would fail the false-positive check for a limitation the rule already
;; documents, so the class is triaged by /security-audit instead.
