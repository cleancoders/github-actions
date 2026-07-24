(ns c3kit.build.shell
  "The only process-spawning code in the library, so specs have one thing to stub."
  (:require [clojure.java.shell :as shell]))

(defn sh
  "Like clojure.java.shell/sh, but never throws. A missing binary becomes exit 127
   with the reason on :err. This matters because a release gate that throws an
   IOException on a missing tool must not be mistaken for a gate that passed."
  [& args]
  (try
    (apply shell/sh args)
    (catch java.io.IOException e
      {:exit 127
       :out  ""
       :err  (str "could not run " (first args) ": " (.getMessage e))})))
