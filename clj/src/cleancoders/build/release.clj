(ns cleancoders.build.release
  "Release policy for libraries published to Clojars. Gates a publish on the
   commit's CI result, keeps releases to CI, and tags only after a successful
   publish and, where the caller opted into them, its signature and a re-fetch
   of its published bytes.

   Signing (:sign!) and post-publish verification (:artifacts) are opt-in
   thunks. They were added after consumers had already onboarded, and a consumer
   pins this library by :git/sha -- so making either mandatory would mean a repo
   bumping that sha for an unrelated fix could no longer release at all. Absent,
   they are skipped and announced in the log; supplied, they gate the release as
   strictly as every other check here."
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
   release failed and retry it. Takes sha rather than deriving it, since every
   caller already has one in hand and re-deriving it would risk a second git
   process disagreeing with the sha the tag body already claims.
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
  "Creates and pushes a signed annotated tag at sha, rather than whatever
   commit HEAD happens to be when this runs: the tag body already claims
   `commit: sha`, and emergency-deploy! runs on a developer's machine where
   HEAD can move during the jar/sign/publish/verify window between reading
   sha and this call. Signed because the tag is the release record and a
   lightweight tag is forgeable by anyone holding contents: write. Pushes an
   explicit refspec rather than --tags so only this tag moves, and checks the
   exit of both calls."
  [version sha message]
  (println "tagging" version)
  (let [{:keys [exit err]} (shell/sh "git" "tag" "-s" "-a" version "-m" message sha)]
    (when-not (zero? exit)
      (abort! (tag-failure-message version sha err))))
  (let [{:keys [exit err]} (shell/sh "git" "push" "origin" (str "refs/tags/" version))]
    (when-not (zero? exit)
      (abort! (tag-failure-message version sha err)))))

(def default-emergency-var
  "Break-glass variable name when a consumer does not override it with
   :emergency-var. Generic because this library is not tied to any one project, and
   short because it gets typed by hand during an incident."
  "EMERGENCY_RELEASE")

(defn assert-signing-key!
  "Aborts unless a signing key is configured. Runs before verify-ci! and before
   anything is built: a missing key is a configuration mistake, and it should
   cost one line of output rather than a build and a failed publish.

   Reached only when the caller supplied a :sign! thunk, so this is never the
   gate a consumer who has not opted into signing runs into. It names what asked
   for the key, because the fix is either to add the secrets or to turn signing
   back off -- and a bare \"key not configured\" does not say that second option
   exists."
  []
  (when-not (sign/configured?)
    (abort! (str "signing key not configured, but this release is set up to sign.\n"
                 "  Signing needs GPG_PRIVATE_KEY and GPG_PASSPHRASE in the\n"
                 "  clojars environment. Add them (see docs/signing.md),\n"
                 "  or drop :sign from :exec-args to release unsigned.\n"
                 "  Nothing was built; no release occurred."))))

(def ^:private required-thunks
  ;; Required since the first version of this contract, so no existing consumer
  ;; script can be missing them.
  [:jar! :publish!])

(def ^:private optional-thunks
  ;; Added after four repos had already onboarded. A script written before then
  ;; passes neither, and must keep releasing: absent, signing and post-publish
  ;; verification are skipped rather than fatal. Supplying one is how a consumer
  ;; opts in.
  [:sign! :artifacts])

(defn assert-thunks!
  "Aborts unless every thunk the release path will actually call is callable.
   Runs with the other pre-build gates, because unguarded a bad :sign! reaches
   (sign-thunk) and dies with a bare `Cannot invoke
   \"clojure.lang.IFn.invoke()\"` -- after jar! has already run -- and a bad
   :artifacts dies the same way after publish!, when the artifact is already
   live and unrepairable.

   Distinguishes absent from wrong. An absent optional thunk is a consumer who
   has not opted into that feature, and aborting on it would mean a repo that
   bumps the pinned :git/sha for an unrelated fix suddenly cannot release. A
   present-but-not-callable one is a mistake in a build script, and it gets the
   same early, loud abort a missing required thunk gets."
  [opts]
  (doseq [k required-thunks]
    (when-not (ifn? (get opts k))
      (abort! (str "no " k " thunk was supplied.\n"
                   "  " k " must be a zero-arg function; the release path calls it.\n"
                   "  See docs/custom-builds.md for the full contract.\n"
                   "  Nothing was built; no release occurred."))))
  (doseq [k optional-thunks]
    (when (and (contains? opts k) (some? (get opts k)) (not (ifn? (get opts k))))
      (abort! (str k " is not callable.\n"
                   "  " k " is optional, but when supplied it must be a\n"
                   "  zero-arg function; the release path calls it. Omit it\n"
                   "  entirely to opt out.\n"
                   "  See docs/custom-builds.md for the full contract.\n"
                   "  Nothing was built; no release occurred.")))))

(defn sign!
  "Runs the caller's signing thunk, turning a signing failure into a clean
   ABORT. Catches Exception, not just ExceptionInfo: an escape-hatch consumer's
   own :sign! thunk might throw an IOException or the like, and that must abort
   cleanly too rather than surface as a raw stack trace. Signing happens before
   publish!, so aborting here ships nothing.

   A nil thunk means the consumer has not opted into signing. That is allowed,
   but it is announced: an unsigned release is a weaker release, and the line
   below is how a maintainer notices their repo never finished onboarding
   signing rather than discovering it when someone tries to verify a jar."
  [sign-thunk]
  (if sign-thunk
    (try
      (sign-thunk)
      (catch Exception e
        (abort! "signing failed:" (ex-message e))))
    (println "NOTE: this release is not signed (no :sign! thunk; see docs/signing.md)")))

(defn- by-hand-check
  "The two lines that let an operator repeat the digest comparison themselves.
   Shared by both verification-failure messages: whichever way verification
   failed, the first thing to establish is what Clojars is actually serving."
  [{:keys [name digest url]}]
  (str "    curl -fsSL " url " | shasum -a 256\n"
       "    expected: " digest "  (" name ")\n"))

(defn- unreadable-failure-message
  "Like tag-failure-message: by the time verification runs the artifact is live
   and immutable, so the message must not read as \"the release failed, retry\".
   Takes sha rather than deriving it -- the caller already has one in hand.

   This is the benign failure. Clojars is eventually consistent, so the usual
   cause is that the CDN has not caught up within the polling window; the bytes
   are almost certainly fine and the release only needs finishing. Hence the
   ready-to-run tag command, which the mismatch message deliberately withholds."
  [artifact reason version sha]
  (str "published " version " but could not verify it on Clojars.\n"
       "  " reason "\n"
       "  The artifact is live and cannot be republished. Clojars is eventually\n"
       "  consistent, so it most likely just has not caught up yet. Check it by\n"
       "  hand:\n"
       (by-hand-check artifact)
       "  If it matches, finish the release with:\n"
       "    git tag -s -a " version " " sha " -m \"" version "\"\n"
       "    git push origin refs/tags/" version))

(defn- mismatch-failure-message
  "The hostile failure, and deliberately NOT unreadable-failure-message. Both
   fetches completed; the bytes Clojars served simply are not the bytes that
   were published. That is either a wrong-artifact publish or registry-side
   substitution, and this digest comparison is the only check in the release
   path that detects either one.

   Hands over no tag command, on purpose. Every other post-publish failure
   message ends in a ready-to-run `git tag`, so an operator who has released a
   few times will reach for it by muscle memory -- and here that would sign the
   release record, the artifact-provenance claim consumers rely on, over bytes
   that just failed the integrity check. Withholding the command forces the one
   decision that cannot be automated.

   Says the version is spent rather than offering a repair, because there is
   none: Clojars refuses to redeploy a non-SNAPSHOT coordinate, and it deletes
   only for malicious code or leaked credentials -- a wrong digest is neither."
  [artifact reason version sha]
  (str "published " version " but the bytes on Clojars are not the bytes that\n"
       "  were published.\n"
       "  " reason "\n"
       "  commit: " sha "\n"
       "\n"
       "  Do NOT tag this release. A tag is the release record, and signing one\n"
       "  over these bytes would vouch for them.\n"
       "\n"
       "  " version " cannot be repaired. Clojars will not redeploy a released\n"
       "  version, and it deletes only for malicious code or leaked credentials,\n"
       "  so this version number is spent either way.\n"
       "\n"
       "  What to do:\n"
       "  1. See what Clojars is serving, so you are not acting on one bad\n"
       "     download:\n"
       (by-hand-check artifact)
       "  2. If it does NOT match, bump the version file and release again. The\n"
       "     new release is the fix; nothing recovers " version ". Then decide\n"
       "     whether the bad version warrants a deletion request to the Clojars\n"
       "     admins and a notice to consumers -- it does if you conclude the\n"
       "     served bytes are malicious rather than merely wrong.\n"
       "  3. If it DOES match, Clojars served two different complete bodies for\n"
       "     one coordinate. Treat that as unresolved, not as a pass: re-check\n"
       "     from another machine and network before you decide anything, and do\n"
       "     not copy a tag command out of an earlier release's log.\n"
       "  See docs/verifying-a-release.md."))

(defn- publish-verify-failure-message
  "Routes to the message for this kind of failure. Dispatches on the verdict's
   :kind rather than matching phrases in :reason, so a reworded reason cannot
   quietly send a substituted artifact down the benign path."
  [artifact {:keys [kind reason]} version sha]
  (if (= :mismatch kind)
    (mismatch-failure-message artifact reason version sha)
    (unreadable-failure-message artifact reason version sha)))

(defn verify-published!
  "Re-fetches every artifact that has a :url and compares digests. Takes the
   version and the commit sha the caller already resolved before publishing --
   the failure message must name both, an artifact map carries neither, and
   re-deriving the sha here would mean a second git process for a value the
   caller already has. Aborts before any tag exists, so an unverified artifact
   never gets one."
  [version sha artifacts]
  (doseq [{:keys [url digest] :as artifact} (filter :url artifacts)]
    (when-let [verdict (publish-verify/verify! {:url url :digest digest})]
      (abort! (publish-verify-failure-message artifact verdict version sha)))))

(defn- artifacts-failure-message
  "Deliberately NOT tag-failure-message: this failure runs before
   verify-published! and record!, so neither ran -- unlike a tag failure, the
   release is NOT otherwise complete. The published bytes have not been
   checked against what Clojars actually served, and no digest record exists.
   Must not hand over a bare tag command either: with no usable artifact list
   there is no digest manifest to put in one, and signing a tag over unverified
   bytes is exactly what the rest of this release path exists to prevent.

   Names the sha, because it is the one fact nobody can re-derive afterwards:
   emergency-deploy! runs on a developer's machine, where HEAD moves during the
   jar/sign/publish window, so an operator who verifies by hand and then tags
   at HEAD would tag the wrong commit. `detail` says in which way the artifact
   list was unusable."
  [version sha detail]
  (str "published " version " but could not determine what shipped.\n"
       "  commit: " sha "\n"
       "  The artifact is live on Clojars and cannot be republished, but its\n"
       "  bytes have NOT been verified against what Clojars actually served,\n"
       "  and no digest record was written. Do NOT tag yet.\n"
       "  " detail "\n"
       "  Fix that, then verify by hand: re-derive the artifact list, compare\n"
       "  each digest against Clojars, and only once every digest matches\n"
       "  should you tag that exact commit -- the one named above, not HEAD --\n"
       "  yourself. See docs/verifying-a-release.md for the shape the tag\n"
       "  has to have: signed, annotated, and carrying every digest."))

(defn- artifacts-verdict
  "nil when the artifact list is one the gates after it can do something with,
   otherwise the reason it is not. An empty list is not a benign \"nothing to
   check\": verify-published! filters on :url, so it would verify nothing,
   record! would write an empty digest manifest, and tag! would still tag --
   a release that passed every gate while proving nothing about its own bytes.
   A list where no entry carries a :url fails the same way."
  [artifacts]
  (cond (empty? artifacts)
        (str ":artifacts returned an empty list, so there is nothing to "
             "verify and no digest to record.")
        (not-any? :url artifacts)
        (str ":artifacts returned no entry carrying a :url, so post-publish "
             "verification would re-fetch nothing.")))

(defn- shipped-artifacts!
  "Calls the caller's artifacts thunk and insists the result is usable, turning
   either failure into a clean abort. Runs after publish!, so a failure here --
   a file that vanished, a digest that can't be computed, a thunk that returned
   nothing useful -- means the artifact is live but nothing past this point has
   happened yet: not verification, not the digest record, not the tag. Both
   entry points funnel through here, so the emptiness check cannot end up
   present on one and missing on the other."
  [version sha artifacts-thunk]
  (let [artifacts (try
                    (artifacts-thunk)
                    (catch Exception e
                      (abort! (artifacts-failure-message
                               version sha (str "Reading the artifact list failed: " (ex-message e))))))]
    (when-let [reason (artifacts-verdict artifacts)]
      (abort! (artifacts-failure-message version sha reason)))
    artifacts))

(defn record!
  "Writes the release's digests where they outlive the log."
  [{:keys [version sha artifacts]}]
  (summary/emit! (summary/render {:version version :commit sha :artifacts artifacts})))

(defn- finish!
  "Everything after a successful publish: work out what shipped, prove Clojars
   is serving those bytes, record the digests, and only then tag.

   With no :artifacts thunk there is nothing to verify against and no digest
   manifest to record, so those three steps are skipped and the tag carries the
   version alone -- exactly what a build script written before this contract
   existed already produced. Skipping is announced, because the weaker mode has
   to be visible in the log rather than inferable from an absence.

   Both entry points funnel through here, so verification cannot end up present
   on one and missing on the other."
  [version sha artifacts-thunk]
  (if artifacts-thunk
    (let [shipped (shipped-artifacts! version sha artifacts-thunk)]
      (verify-published! version sha shipped)
      (record! {:version version :sha sha :artifacts shipped})
      (tag! version sha (tag-message version sha shipped)))
    (do
      (println "NOTE: no :artifacts thunk, so the published bytes were not"
               "re-fetched and verified, and no digest record was written"
               "(see docs/custom-builds.md)")
      (tag! version sha version))))

(defn deploy!
  "The release path. Every gate that can fail cheaply runs before anything is
   built; tagging happens last so a failed or unverified publish leaves no tag
   pointing at a version nobody confirmed.

   Reads the commit sha once, before jar!, rather than after publish!: reading
   it post-publish means a plain \"could not read HEAD\" abort would follow a
   real publish, misleading a maintainer into thinking the release failed and
   retrying it. Read early, the same failure is just another pre-build gate."
  [{:keys [repo ci-workflow version jar! publish! artifacts] sign-thunk :sign! :as opts}]
  (assert-ci!)
  (assert-thunks! opts)
  ;; Only when the caller actually signs. The gate exists to fail a signing
  ;; release early rather than after a publish; for a consumer who has not
  ;; opted in there is no key to check for.
  (when sign-thunk (assert-signing-key!))
  (verify-ci! {:repo repo :ci-workflow ci-workflow})
  (assert-untagged! version)
  (let [sha (head-sha)]
    (jar!)
    (sign! sign-thunk)
    (publish!)
    (finish! version sha artifacts)))

(defn emergency-deploy!
  "Break-glass release for when the release workflow itself cannot run.

   Skips verify-ci! deliberately -- the likeliest reason to need this is that CI
   results are unavailable. It does not additionally skip signing: where a
   consumer signs at all, they sign here too, because an emergency is not a
   reason to ship bytes a consumer cannot verify. Authorization requires naming
   the exact version so a stale exported variable cannot authorize a later
   release, and the banner leaves a record that outlives the log."
  [{:keys [version jar! publish! artifacts emergency-var] sign-thunk :sign! :as opts}]
  ;; not-empty, not a bare or: "" is truthy in Clojure, so a blank :emergency-var
  ;; would otherwise survive as the lookup key and print "requires =4.2.1".
  (let [emergency-var (or (not-empty emergency-var) default-emergency-var)]
    (when-not (emergency-authorized? (getenv emergency-var) version)
      (abort! (str "emergency release requires " emergency-var "=" version)))
    ;; After authorization, before anything else: an unauthorized caller should
    ;; hear about authorization first, but a caller who IS authorized must not
    ;; get as far as building with a thunk that cannot be called.
    (assert-thunks! opts)
    (when sign-thunk (assert-signing-key!))
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
      (finish! version sha artifacts))))
