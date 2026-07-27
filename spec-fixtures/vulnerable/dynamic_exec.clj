(ns fixtures.dynamic-exec
  (:require [clojure.java.shell :as sh]
            [clojure.java.shell :as shell]))

(defn convert [path]
  (sh/sh "bash" "-c" (str "convert " path " out.png")))

;; Second alias for the same sink — guards the enumerated alias list.
(defn thumbnail [path]
  (shell/sh "sh" "-c" (str "convert -thumbnail 64 " path)))

(defn run-report [ns-name fn-name]
  ((requiring-resolve (symbol ns-name fn-name))))

(defn eval-rule [src]
  (load-string src))
