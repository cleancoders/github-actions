(ns fixtures.deser-safe
  (:require [taoensso.nippy :as nippy])
  (:import [org.yaml.snakeyaml Yaml]
           [org.yaml.snakeyaml.constructor SafeConstructor]))

(defn load-session [^bytes b]
  (nippy/thaw b {:incl-class-allowlist #{"clojure.lang.PersistentArrayMap"}}))

(defn parse-config [s]
  (.load (Yaml. (SafeConstructor.)) s))
