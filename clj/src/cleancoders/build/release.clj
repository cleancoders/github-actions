(ns cleancoders.build.release
  "Release policy for libraries published to Clojars. Gates a publish on the
   commit's CI result, keeps releases to CI, and tags only after a successful
   publish, its signature, and its published bytes are all verified."
  (:require [cleancoders.build.publish-verify :as publish-verify]
            [cleancoders.build.shell :as shell]
            [cleancoders.build.sign :as sign]
            [cleancoders.build.summary :as summary]
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
  (System/exit 1)
  ;; Unreachable. Every gate is written as (when-not ok (abort! ...)) with code
  ;; after it, so they all depend on abort! never returning. If a future edit
  ;; makes it return, this turns a silent publish into a loud failure.
  (throw (ex-info "unreachable: abort! must not return" {})))

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

(defn- workflow-names
  "One or many, unchanged from what the caller passed. :ci-workflow started as
   a single workflow name and accepts a vector without breaking the consumers
   that pass a string. Does not drop or otherwise tolerate blank entries --
   verify-ci! must never gate on fewer workflows than the caller named, so a
   blank anywhere in the list has to abort the whole check rather than
   silently narrow the gate to whichever names happen to be real."
  [ci-workflow]
  (if (coll? ci-workflow) (vec ci-workflow) [ci-workflow]))

(defn- blank-workflow?
  "True when workflow is a string with no real content. Only strings are
   checked -- a non-string entry is left for workflow-verdict to fail closed
   on via a malformed API path, per the config-validation task's boundary."
  [workflow]
  (and (string? workflow) (str/blank? workflow)))

(defn- workflow-verdict
  "nil when this workflow's newest run at sha succeeded, otherwise the reason."
  [repo sha workflow]
  (let [path (format "/repos/%s/actions/workflows/%s/runs?head_sha=%s&per_page=1"
                     repo workflow sha)
        {:keys [exit out err]} (shell/sh "gh" "api" path "--jq" run-projection)]
    (if (zero? exit)
      (run-verdict out)
      (str "could not query CI status: " (str/trim (str err))))))

(defn verify-ci!
  "Aborts unless the newest run of every named workflow for the current commit
   succeeded. Reads HEAD once, then queries each workflow, so an abort names
   which one was not green.

   Refuses to gate on fewer workflows than the caller actually named: an empty
   :ci-workflow, a blank string, or a blank entry anywhere in a collection all
   abort before any shell call runs, rather than silently proceeding on
   whichever names happen to be real. Do not \"simplify\" this to dropping
   blank entries -- that turns a caller's typo into a partial, unannounced
   gate instead of a loud one.

   Scoped to named workflows rather than the commit's check-runs on purpose: the
   release run registers its own check-run against the same commit, so an
   all-check-runs-green query would observe itself as in_progress and deadlock."
  [{:keys [repo ci-workflow]}]
  (let [workflows (workflow-names ci-workflow)]
    (when (or (empty? workflows) (some blank-workflow? workflows))
      (abort! "no CI workflow was named; a release cannot be gated on nothing"))
    (let [sha (head-sha)]
      (doseq [workflow workflows]
        (when-let [reason (workflow-verdict repo sha workflow)]
          (abort! (str reason " (" workflow " @ " sha ")"))))
      (println "CI green for" sha))))

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

(defn- released-sha
  "Best-effort commit id for the recovery instructions. Degrades to a
   placeholder rather than aborting: we are already on a failure path and must
   not lose the message that explains it."
  []
  (let [{:keys [exit out]} (shell/sh "git" "rev-parse" "HEAD")]
    (if (zero? exit) (str/trim out) "<the released commit>")))

(defn tag-message
  "The annotated tag's message. The first line is the subject git displays;
   the digests follow so \"what bits did we ship\" is answerable from a clone
   alone, with no API call and no log retention window."
  [version sha artifacts]
  (str version "\n\n"
       "commit: " sha "\n"
       (str/join "\n" (map #(format "%s: sha256:%s" (:name %) (:digest %)) artifacts))
       "\n"))

(defn- tag-failure-message
  "tag! runs only after a successful publish, so any failure here means the
   artifact is already live and immutable and only the tag is missing. Say that
   explicitly -- a maintainer reading this mid-incident must not conclude the
   release failed and retry it. Takes sha rather than deriving it, so callers
   that already have one in hand don't pay for a second git process; tag! --
   the only caller with no sha of its own -- passes released-sha instead.
   The git tag line notes that the tag may already exist locally: when git
   tag itself succeeded and only the push failed, re-running it verbatim
   would fail with \"already exists\"."
  [version sha err]
  (str "published " version " but could not tag it.\n"
       "  The artifact is live on Clojars and cannot be republished. Only the\n"
       "  tag is missing; the release is otherwise complete. Finish it with:\n"
       "    git tag -s -a " version " " sha " -m \"" version "\"  (skip if it already exists locally)\n"
       "    git push origin refs/tags/" version "\n"
       "  git reported: " err))

(defn tag!
  "Creates and pushes a signed annotated tag. Signed because the tag is the
   release record and a lightweight tag is forgeable by anyone holding
   contents: write. Pushes an explicit refspec rather than --tags so only this
   tag moves, and checks the exit of both calls."
  [version message]
  (println "tagging" version)
  (let [{:keys [exit err]} (shell/sh "git" "tag" "-s" "-a" version "-m" message)]
    (when-not (zero? exit)
      (abort! (tag-failure-message version (released-sha) err))))
  (let [{:keys [exit err]} (shell/sh "git" "push" "origin" (str "refs/tags/" version))]
    (when-not (zero? exit)
      (abort! (tag-failure-message version (released-sha) err)))))

(def default-emergency-var
  "Break-glass variable name when a consumer does not override it with
   :emergency-var. Generic because this library is not c3kit-specific, and
   short because it gets typed by hand during an incident."
  "EMERGENCY_RELEASE")

(defn assert-signing-key!
  "Aborts unless a signing key is configured. Runs before verify-ci! and before
   anything is built: a missing key is a configuration mistake, and it should
   cost one line of output rather than a build and a failed publish."
  []
  (when-not (sign/configured?)
    (abort! (str "signing key not configured.\n"
                 "  deploy requires GPG_PRIVATE_KEY and GPG_PASSPHRASE in the\n"
                 "  clojars environment. See README \"Signing keys\".\n"
                 "  Nothing was built; no release occurred."))))

(defn sign!
  "Runs the caller's signing thunk, turning a signing failure into a clean
   ABORT. Catches Exception, not just ExceptionInfo: an escape-hatch consumer's
   own :sign! thunk might throw an IOException or the like, and that must abort
   cleanly too rather than surface as a raw stack trace. Signing happens before
   publish!, so aborting here ships nothing."
  [sign-thunk]
  (try
    (sign-thunk)
    (catch Exception e
      (abort! "signing failed:" (ex-message e)))))

(defn- publish-verify-failure-message
  "Like tag-failure-message: by the time verification runs the artifact is live
   and immutable, so the message must not read as \"the release failed, retry\".
   Takes sha rather than deriving it -- the caller already has one in hand."
  [{:keys [name digest url]} reason version sha]
  (str "published " version " but could not verify it on Clojars.\n"
       "  " reason "\n"
       "  The artifact is live and cannot be republished. Check it by hand:\n"
       "    curl -fsSL " url " | shasum -a 256\n"
       "    expected: " digest "  (" name ")\n"
       "  If it matches, finish the release with:\n"
       "    git tag -s -a " version " " sha " -m \"" version "\"  (skip if it already exists locally)\n"
       "    git push origin refs/tags/" version))

(defn verify-published!
  "Re-fetches every artifact that has a :url and compares digests. Takes the
   version and the commit sha the caller already resolved before publishing --
   the failure message must name both, an artifact map carries neither, and
   re-deriving the sha here would mean a second git process for a value the
   caller already has. Aborts before any tag exists, so an unverified artifact
   never gets one."
  [version sha artifacts]
  (doseq [{:keys [url digest] :as artifact} (filter :url artifacts)]
    (when-let [reason (publish-verify/verify! {:url url :digest digest})]
      (abort! (publish-verify-failure-message artifact reason version sha)))))

(defn- shipped-artifacts!
  "Calls the caller's artifacts thunk, turning a failure into a clean abort.
   Runs after publish!, so a thrown exception here -- a file that vanished, a
   digest that can't be computed -- must not read as \"the release failed\":
   the artifact is already live on Clojars, and the same tag-failure message
   applies, since the only thing left undone either way is the tag."
  [version sha artifacts-thunk]
  (try
    (artifacts-thunk)
    (catch Exception e
      (abort! (tag-failure-message version sha (ex-message e))))))

(defn record!
  "Writes the release's digests where they outlive the log."
  [{:keys [version sha artifacts]}]
  (summary/emit! (summary/render {:version version :commit sha :artifacts artifacts})))

(defn deploy!
  "The release path. Every gate that can fail cheaply runs before anything is
   built; tagging happens last so a failed or unverified publish leaves no tag
   pointing at a version nobody confirmed.

   Reads the commit sha once, before jar!, rather than after publish!: reading
   it post-publish means a plain \"could not read HEAD\" abort would follow a
   real publish, misleading a maintainer into thinking the release failed and
   retrying it. Read early, the same failure is just another pre-build gate."
  [{:keys [repo ci-workflow version jar! publish! artifacts] sign-thunk :sign!}]
  (assert-ci!)
  (assert-signing-key!)
  (verify-ci! {:repo repo :ci-workflow ci-workflow})
  (assert-untagged! version)
  (let [sha (head-sha)]
    (jar!)
    (sign! sign-thunk)
    (publish!)
    (let [shipped (shipped-artifacts! version sha artifacts)]
      (verify-published! version sha shipped)
      (record! {:version version :sha sha :artifacts shipped})
      (tag! version (tag-message version sha shipped)))))

(defn emergency-deploy!
  "Break-glass release for when the release workflow itself cannot run.

   Skips verify-ci! deliberately -- the likeliest reason to need this is that CI
   results are unavailable. It does not skip signing: an emergency is not a
   reason to ship bytes a consumer cannot verify. Authorization requires naming
   the exact version so a stale exported variable cannot authorize a later
   release, and the banner leaves a record that outlives the log."
  [{:keys [version jar! publish! artifacts emergency-var] sign-thunk :sign!}]
  ;; not-empty, not a bare or: "" is truthy in Clojure, so a blank :emergency-var
  ;; would otherwise survive as the lookup key and print "requires =4.2.1".
  (let [emergency-var (or (not-empty emergency-var) default-emergency-var)]
    (when-not (emergency-authorized? (getenv emergency-var) version)
      (abort! (str "emergency release requires " emergency-var "=" version)))
    (assert-signing-key!)
    (assert-clean-tree!)
    (assert-untagged! version)
    (let [sha (head-sha)]
      (println "!!! EMERGENCY RELEASE - CI verification skipped !!!")
      (println "    version:" version)
      (println "    commit :" sha)
      (summary/emit! (summary/emergency-banner {:version       version
                                                :commit        sha
                                                :actor         (getenv "GITHUB_ACTOR")
                                                :emergency-var emergency-var}))
      (jar!)
      (sign! sign-thunk)
      (publish!)
      (let [shipped (shipped-artifacts! version sha artifacts)]
        (verify-published! version sha shipped)
        (record! {:version version :sha sha :artifacts shipped})
        (tag! version (tag-message version sha shipped))))))
