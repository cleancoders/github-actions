(ns fixtures.deser
  (:require [taoensso.nippy :as nippy]
            [taoensso.nippy :as np])
  (:import [org.yaml.snakeyaml Yaml]))

(defn load-session [^bytes b]
  (nippy/thaw b))

;; Second alias for the same sink — guards the enumerated alias list.
(defn load-cache [^bytes b]
  (np/thaw b))

(defn parse-config [s]
  (.load (Yaml.) s))
