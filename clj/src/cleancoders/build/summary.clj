(ns cleancoders.build.summary
  "The durable record of what a release shipped. Digests go to the job summary,
   which survives longer than a log line and is readable without re-running
   anything. Falls back to stdout, so a local break-glass release still leaves
   a record, and never throws: losing the record must not fail a release that
   otherwise succeeded."
  (:require [clojure.string :as str]))

(defn getenv
  "Indirection over System/getenv so specs can control the environment."
  [name]
  (System/getenv name))

(defn- digest-rows
  [artifacts]
  (str/join "\n" (map #(format "| `%s` | `sha256:%s` |" (:name %) (:digest %)) artifacts)))

(defn render
  "Markdown for a normal release."
  [{:keys [version commit artifacts]}]
  (str "### Released " version "\n\n"
       "commit `" commit "`\n\n"
       "| artifact | digest |\n|---|---|\n"
       (digest-rows artifacts)
       "\n"))

(defn emergency-banner
  "Markdown for a break-glass release. Names the actor, because the whole point
   of this record is answering who shipped what without CI verification."
  [{:keys [version commit actor emergency-var]}]
  (str "### :warning: EMERGENCY RELEASE " version "\n\n"
       "CI verification was **skipped**.\n\n"
       "- released by: `" (or (not-empty (str actor)) "unknown") "`\n"
       "- commit: `" commit "`\n"
       "- authorized by: `" emergency-var "=" version "`\n"))

(defn emit!
  "Appends text to $GITHUB_STEP_SUMMARY, or prints it when there is none."
  [text]
  (let [path (getenv "GITHUB_STEP_SUMMARY")]
    (if (str/blank? (str path))
      (println text)
      (try
        (spit path (str text "\n") :append true)
        (catch Exception _
          (println text))))))
