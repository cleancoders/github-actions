(ns cleancoders.build.publish-verify
  "Re-fetches a published artifact from Clojars and compares its digest to the
   jar that was uploaded. This is the only detection this release path has for
   registry-side substitution or a wrong-artifact publish, so it runs before
   any tag exists.

   Clojars is eventually consistent, so a fetch failure is retried. A digest
   mismatch never is: retrying a mismatch could turn a real finding into a pass."
  (:require [cleancoders.build.digest :as digest]
            [cleancoders.build.shell :as shell]
            [clojure.string :as str]))

(def ^:private repo-url "https://repo.clojars.org")

(defn artifact-url
  "Maven-layout URL Clojars serves the jar from. The group's dots become path
   separators; a single-segment coordinate is its own group."
  [{:keys [lib version]}]
  (let [group (str/replace (or (namespace lib) (name lib)) "." "/")
        name' (name lib)]
    (str repo-url "/" group "/" name' "/" version "/" name' "-" version ".jar")))

(defn verdict
  "nil when the fetched digest matches the local one, otherwise the reason."
  [fetched local]
  (cond (str/blank? (str fetched)) "the published artifact is not readable on Clojars"
        (= fetched local)          nil
        :else                      (str "digest mismatch: Clojars has sha256:" fetched
                                        " but the published jar is sha256:" local)))

(defn- fetch-digest
  "Downloads url to a temp file and returns its digest, or nil when the fetch
   failed. Downloads to a file rather than capturing stdout: jar bytes run
   through a string decoder come out corrupted and would fail every compare."
  [url]
  (let [target (doto (java.io.File/createTempFile "publish-verify" ".jar") (.deleteOnExit))
        {:keys [exit]} (shell/sh "curl" "-fsSL" "--max-time" "60" "-o" (.getAbsolutePath target) url)]
    (when (zero? exit)
      (digest/sha256 target))))

(defn verify!
  "Polls until the artifact is readable, then compares digests. Returns nil on
   success or the reason it failed."
  [{:keys [url digest attempts wait-ms sleep!] :or {attempts 6 wait-ms 5000 sleep! #(Thread/sleep %)}}]
  (loop [attempt 1 wait wait-ms]
    (println (format "verifying published artifact (attempt %d/%d)" attempt attempts))
    (let [fetched (fetch-digest url)]
      (cond
        fetched              (let [reason (verdict fetched digest)]
                               (if reason
                                 reason
                                 (do (println "  sha256 match") nil)))
        (< attempt attempts) (do (println (format "  not readable yet, retrying in %dms" wait))
                                 (sleep! wait)
                                 (recur (inc attempt) (* 2 wait)))
        :else                (verdict nil digest)))))
