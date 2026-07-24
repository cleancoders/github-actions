(ns c3kit.build.release
  "Release policy shared by the c3kit libraries. Gates a Clojars publish on the
   commit's CI result, keeps releases to CI, and tags only after a successful
   publish."
  (:require [c3kit.build.shell :as shell]
            [clojure.string :as str]))

(defn run-verdict
  "Interprets the \"<status> <conclusion>\" projection of a workflow run.
   Returns nil when the run is a success, otherwise a reason string. Every
   non-success case — including an absent run — yields a reason, so the caller
   fails closed."
  [projection]
  (let [[status conclusion] (str/split (str/trim (str projection)) #"\s+")
        status              (or status "")]
    (cond (str/blank? status)       "no CI run found for this commit"
          (not= "completed" status) (str "CI run is " status ", not completed")
          (= "success" conclusion)  nil
          :else                     (str "CI run concluded " (or conclusion "unknown")))))

(defn tag-exists?
  "True when version appears as an exact tag in `git ls-remote --tags` output.
   Matching is exact so 4.2.1 does not match refs/tags/4.2.10. Lines ending in
   ^{} are the dereferenced commits annotated tags emit; they are not tag names."
  [ls-remote-out version]
  (->> (str/split-lines (str ls-remote-out))
       (keep #(second (re-find #"\srefs/tags/(\S+)$" %)))
       (remove #(str/ends-with? % "^{}"))
       (some #{version})
       boolean))

(defn emergency-authorized?
  "True when the break-glass variable names the exact version being released.
   Requiring the version rather than a boolean means a stale exported variable
   cannot authorize a later release."
  [env-value version]
  (and (not (str/blank? version))
       (= (str/trim (str env-value)) (str/trim version))))

(defn clean-tree?
  "True when `git status --porcelain` reported nothing."
  [porcelain-out]
  (str/blank? porcelain-out))

(defn- abort-message!
  "Writes the ABORT line to stderr. CI conventionally distinguishes stderr from
   stdout, and GitHub Actions annotates it distinctly, so this is the line a
   maintainer needs to spot in a log."
  [msg]
  (binding [*out* *err*]
    (println (str "ABORT: " (str/join " " msg)))))

(defn abort!
  "Prints the reason to stderr and exits non-zero. Public so specs can rebind
   it; every gate funnels failure through here so there is one place that
   decides how to die."
  [& msg]
  (abort-message! msg)
  (System/exit 1))

(defn getenv
  "Indirection over System/getenv so specs can control the environment."
  [name]
  (System/getenv name))

(def ^:private run-projection
  ;; Two fields on one line, blank when absent, so an empty run list is
  ;; distinguishable from a queued run and neither can look like success.
  ".workflow_runs[0] // {} | (.status // \"\") + \" \" + (.conclusion // \"\")")

(defn head-sha []
  (let [{:keys [exit out err]} (shell/sh "git" "rev-parse" "HEAD")]
    (if (zero? exit)
      (str/trim out)
      (abort! "could not read HEAD:" err))))

(defn assert-ci! []
  (when (str/blank? (getenv "GITHUB_ACTIONS"))
    (abort! "clj -T:build deploy runs in CI only."
            "Use the Release workflow in the Actions tab,"
            "or clj -T:build emergency-publish to break glass.")))

(defn verify-ci!
  "Aborts unless the newest run of ci-workflow for the current commit succeeded.

   Scoped to a named workflow rather than the commit's check-runs on purpose: the
   release run registers its own check-run against the same commit, so an
   all-check-runs-green query would observe itself as in_progress and deadlock."
  [{:keys [repo ci-workflow]}]
  (let [sha  (head-sha)
        path (format "/repos/%s/actions/workflows/%s/runs?head_sha=%s&per_page=1"
                     repo ci-workflow sha)
        {:keys [exit out err]} (shell/sh "gh" "api" path "--jq" run-projection)]
    (when-not (zero? exit)
      (abort! "could not query CI status:" err))
    (when-let [reason (run-verdict out)]
      (abort! (str reason " (" ci-workflow " @ " sha ")")))
    (println "CI green for" sha)))

(defn assert-untagged! [version]
  (let [{:keys [exit out err]} (shell/sh "git" "ls-remote" "--tags" "origin")]
    (when-not (zero? exit)
      (abort! "could not list remote tags:" err))
    (when (tag-exists? out version)
      (abort! "version" version "is already tagged; bump the version file"))))

(defn assert-clean-tree! []
  (let [{:keys [exit out err]} (shell/sh "git" "status" "--porcelain")]
    (when-not (zero? exit)
      (abort! "could not read git status:" err))
    (when-not (clean-tree? out)
      (abort! "working tree is dirty; commit before releasing"))))

(defn tag!
  "Creates and pushes the tag. Pushes an explicit refspec rather than --tags so
   only this tag moves, and checks the exit of both calls."
  [version]
  (println "tagging" version)
  (let [{:keys [exit err]} (shell/sh "git" "tag" version)]
    (when-not (zero? exit)
      (abort! "git tag failed:" err)))
  (let [{:keys [exit err]} (shell/sh "git" "push" "origin" (str "refs/tags/" version))]
    (when-not (zero? exit)
      (abort! "could not push tag" version ":" err))))

(def emergency-var "C3KIT_EMERGENCY_RELEASE")

(defn deploy!
  "The release path. Tagging happens last so a failed publish leaves no tag
   pointing at a version that was never released."
  [{:keys [repo ci-workflow version jar! publish!]}]
  (assert-ci!)
  (verify-ci! {:repo repo :ci-workflow ci-workflow})
  (assert-untagged! version)
  (jar!)
  (publish!)
  (tag! version))

(defn emergency-deploy!
  "Break-glass release for when the release workflow itself cannot run.

   Skips verify-ci! deliberately — the likeliest reason to need this is that CI
   results are unavailable. Authorization requires naming the exact version so a
   stale exported variable cannot authorize a later release."
  [{:keys [version jar! publish!]}]
  (when-not (emergency-authorized? (getenv emergency-var) version)
    (abort! (str "emergency release requires " emergency-var "=" version)))
  (assert-clean-tree!)
  (assert-untagged! version)
  (println "!!! EMERGENCY RELEASE - CI verification skipped !!!")
  (println "    version:" version)
  (println "    commit :" (head-sha))
  (jar!)
  (publish!)
  (tag! version))
