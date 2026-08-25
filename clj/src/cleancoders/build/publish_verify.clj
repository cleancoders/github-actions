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

(def default-repo-url
  "Where Clojars serves artifacts from. Note this is not the URL a release
   uploads to (clojars.org/repo) -- reads and writes go to different hosts,
   which is why an override has to replace both."
  "https://repo.clojars.org")

(defn artifact-url
  "Maven-layout URL the repository serves the jar from. The group's dots become
   path separators; a single-segment coordinate is its own group.

   :repo-url overrides the base, which is what lets a release be rehearsed
   against a throwaway repository -- a directory on a CI runner, say -- instead
   of Clojars. That matters because a Clojars deploy cannot be undone: there is
   no self-service deletion for any version, SNAPSHOT included, so a rehearsal
   aimed at Clojars leaves a permanent public artifact.

   not-empty, not a bare or: \"\" is truthy in Clojure, so a blank override would
   otherwise survive as the base and build /com/example/... with no host."
  [{:keys [lib version repo-url]}]
  (let [base  (or (not-empty (str repo-url)) default-repo-url)
        group (str/replace (or (namespace lib) (name lib)) "." "/")
        name' (name lib)]
    (str base "/" group "/" name' "/" version "/" name' "-" version ".jar")))

(defn verdict
  "nil when the fetched digest matches the local one, otherwise a map of
   {:kind :reason}. The kind is a value rather than something a caller has to
   recognize in the reason text, because the two failures have opposite
   remedies: an unreadable artifact usually means Clojars has not caught up yet
   and the release can still be finished by hand, while a mismatch means the
   published coordinate is wrong forever and must never be tagged."
  [fetched local]
  (cond (str/blank? (str fetched)) {:kind   :unreadable
                                    :reason "the published artifact is not readable on Clojars"}
        (= fetched local)          nil
        :else                      {:kind   :mismatch
                                    :reason (str "digest mismatch: Clojars has sha256:" fetched
                                                 " but the published jar is sha256:" local)}))

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
   success or the verdict map describing how it failed."
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
