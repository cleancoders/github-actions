(ns fixtures.dynamic-exec-safe
  (:require [clojure.java.shell :as sh]))

;; Fixed argv — no shell interprets the value, so no injection surface.
(defn convert [path]
  (sh/sh "convert" path "out.png"))

;; Static symbol literal, resolved once at load, never from runtime input.
(def ^:private report-fn (requiring-resolve 'clojure.string/upper-case))

(defn run-report [s] (report-fn s))
