(ns c3kit.build.release-spec
  (:require [c3kit.build.release :as sut]
            [c3kit.build.shell :as shell]
            [clojure.string :as cstr]
            [speclj.core :refer :all]))

(defmacro with-err-str
  "Like clojure.core/with-out-str, but captures *err* instead."
  [& body]
  `(let [s# (java.io.StringWriter.)]
     (binding [*err* s#]
       ~@body
       (str s#))))

(def aborted (atom nil))
(def commands (atom []))

(defn- stub-sh
  "Returns an sh replacement that records invocations and answers from responses,
   a map of first-argument -> result. Unlisted commands succeed silently."
  [responses]
  (fn [& args]
    (swap! commands conj (vec args))
    (get responses (vec (take 2 args))
         (get responses [(first args)] {:exit 0 :out "" :err ""}))))

(defn- capturing
  "Runs f with abort! captured rather than exiting. Returns the abort message, or
   nil when f completed without aborting."
  [f]
  (reset! aborted nil)
  (with-redefs [sut/abort! (fn [& msg]
                             (reset! aborted (cstr/join " " msg))
                             (throw (ex-info "aborted" {:aborted true})))]
    (try (f) (catch clojure.lang.ExceptionInfo _ nil)))
  @aborted)

(describe "release"

          (context "run-verdict"
            (it "passes a completed successful run"
                (should-be-nil (sut/run-verdict "completed success")))

            (it "rejects an absent run"
                (should= "no CI run found for this commit" (sut/run-verdict " ")))

            (it "rejects an empty projection"
                (should= "no CI run found for this commit" (sut/run-verdict "")))

            (it "rejects a run still in progress"
                (should= "CI run is in_progress, not completed" (sut/run-verdict "in_progress ")))

            (it "rejects a queued run"
                (should= "CI run is queued, not completed" (sut/run-verdict "queued ")))

            (it "rejects a failed run"
                (should= "CI run concluded failure" (sut/run-verdict "completed failure")))

            (it "rejects a cancelled run"
                (should= "CI run concluded cancelled" (sut/run-verdict "completed cancelled")))

            (it "rejects a skipped run"
                (should= "CI run concluded skipped" (sut/run-verdict "completed skipped")))

            (it "rejects a completed run with no conclusion"
                (should= "CI run concluded unknown" (sut/run-verdict "completed")))

            (it "tolerates surrounding whitespace"
                (should-be-nil (sut/run-verdict "  completed success\n"))))

          (context "tag-exists?"
            (with lines (str "abc123\trefs/tags/4.2.0\n"
                             "def456\trefs/tags/4.2.10\n"
                             "789abc\trefs/tags/4.3.0\n"))

            (it "finds an exact tag"
                (should= true (sut/tag-exists? @lines "4.2.0")))

            (it "does not treat 4.2.1 as present because 4.2.10 is"
                (should= false (sut/tag-exists? @lines "4.2.1")))

            (it "is false for an unknown version"
                (should= false (sut/tag-exists? @lines "9.9.9")))

            (it "is false for empty output"
                (should= false (sut/tag-exists? "" "4.2.0")))

            (it "ignores the dereferenced-tag lines annotated tags produce"
                (should= false (sut/tag-exists? "abc123\trefs/tags/4.2.0^{}\n" "4.2.0"))))

          (context "emergency-authorized?"
            (it "authorizes an exact version match"
                (should= true (sut/emergency-authorized? "4.2.2" "4.2.2")))

            (it "tolerates surrounding whitespace in the env value"
                (should= true (sut/emergency-authorized? " 4.2.2 " "4.2.2")))

            (it "refuses a different version"
                (should= false (sut/emergency-authorized? "4.2.1" "4.2.2")))

            (it "refuses an unset variable"
                (should= false (sut/emergency-authorized? nil "4.2.2")))

            (it "refuses an empty variable"
                (should= false (sut/emergency-authorized? "" "4.2.2")))

            (it "refuses a blank version even when the env value is also blank"
                (should= false (sut/emergency-authorized? "" ""))))

          (context "clean-tree?"
            (it "is true for empty porcelain output"
                (should= true (sut/clean-tree? "")))

            (it "is true for whitespace-only output"
                (should= true (sut/clean-tree? "\n")))

            (it "is false when a file is modified"
                (should= false (sut/clean-tree? " M dev/build.clj\n")))

            (it "is false when a file is untracked"
                (should= false (sut/clean-tree? "?? notes.txt\n"))))

          (context "abort!"
            (it "writes the ABORT message to stderr, not stdout"
                (let [err (atom nil)
                      out (with-out-str
                            (reset! err (with-err-str (#'sut/abort-message! ["something" "broke"]))))]
                  (should= "" out)
                  (should-contain "ABORT: something broke" @err))))

          (context "assert-ci!"
            (before (reset! commands []))

            (it "proceeds inside GitHub Actions"
                (should-be-nil (capturing #(with-redefs [sut/getenv (constantly "true")]
                                             (sut/assert-ci!)))))

            (it "aborts outside CI"
                (should-contain "runs in CI only"
                                (capturing #(with-redefs [sut/getenv (constantly nil)]
                                              (sut/assert-ci!))))))

          (context "verify-ci!"
            (before (reset! commands []))

            (it "proceeds when the newest run succeeded"
                (should-be-nil
                 (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                              ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                               (sut/verify-ci! {:repo "cleancoders/c3kit-wire" :ci-workflow "build.yml"})))))

            (it "aborts when the newest run failed"
                (should-contain "concluded failure"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                                             ["gh"]              {:exit 0 :out "completed failure" :err ""}})]
                                              (sut/verify-ci! {:repo "cleancoders/c3kit-wire" :ci-workflow "build.yml"})))))

            (it "aborts when no run exists for the commit"
                (should-contain "no CI run found"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                                             ["gh"]              {:exit 0 :out " " :err ""}})]
                                              (sut/verify-ci! {:repo "cleancoders/c3kit-wire" :ci-workflow "build.yml"})))))

            (it "aborts when gh is missing rather than treating it as green"
                (should-contain "could not query CI status"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                                             ["gh"]              {:exit 127 :out "" :err "could not run gh"}})]
                                              (sut/verify-ci! {:repo "cleancoders/c3kit-wire" :ci-workflow "build.yml"})))))

            (it "queries the named workflow for the head sha"
                (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                             ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                              (sut/verify-ci! {:repo "cleancoders/c3kit-wire" :ci-workflow "build.yml"})))
                (let [gh-args (first (filter #(= "gh" (first %)) @commands))]
                  (should-contain "/repos/cleancoders/c3kit-wire/actions/workflows/build.yml/runs" (nth gh-args 2))
                  (should-contain "head_sha=abc123" (nth gh-args 2)))))

          (context "assert-untagged!"
            (before (reset! commands []))

            (it "proceeds when the version is not tagged"
                (should-be-nil
                 (capturing #(with-redefs [shell/sh (stub-sh {["git" "ls-remote"] {:exit 0 :out "abc\trefs/tags/4.2.0\n" :err ""}})]
                               (sut/assert-untagged! "4.2.1")))))

            (it "aborts when the version is already tagged"
                (should-contain "already tagged"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "ls-remote"] {:exit 0 :out "abc\trefs/tags/4.2.1\n" :err ""}})]
                                              (sut/assert-untagged! "4.2.1")))))

            (it "aborts when the remote cannot be reached"
                (should-contain "could not list remote tags"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "ls-remote"] {:exit 128 :out "" :err "no such remote"}})]
                                              (sut/assert-untagged! "4.2.1"))))))

          (context "assert-clean-tree!"
            (before (reset! commands []))

            (it "proceeds when the tree is clean"
                (should-be-nil
                 (capturing #(with-redefs [shell/sh (stub-sh {["git" "status"] {:exit 0 :out "" :err ""}})]
                               (sut/assert-clean-tree!)))))

            (it "aborts when the tree is dirty"
                (should-contain "working tree is dirty"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "status"] {:exit 0 :out " M dev/build.clj\n" :err ""}})]
                                              (sut/assert-clean-tree!))))))

          (context "tag!"
            (before (reset! commands []))

            (it "creates and pushes the tag"
                (should-be-nil
                 (capturing #(with-redefs [shell/sh (stub-sh {})] (sut/tag! "4.2.1"))))
                (should= ["git" "tag" "4.2.1"] (first @commands))
                (should= ["git" "push" "origin" "refs/tags/4.2.1"] (second @commands)))

            (it "aborts when git tag fails"
                (should-contain "git tag failed"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "tag"] {:exit 128 :out "" :err "already exists"}})]
                                              (sut/tag! "4.2.1")))))

            (it "aborts when the tag push fails"
                (should-contain "could not push tag"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "push"] {:exit 1 :out "" :err "rejected"}})]
                                              (sut/tag! "4.2.1"))))))

          (context "deploy!"
            (it "runs the gates, then jars, then publishes, then tags"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!       (fn [] (swap! calls conj :assert-ci))
                                sut/verify-ci!       (fn [_] (swap! calls conj :verify-ci))
                                sut/assert-untagged! (fn [_] (swap! calls conj :assert-untagged))
                                sut/tag!             (fn [_] (swap! calls conj :tag))]
                    (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                  :ci-workflow "build.yml"
                                  :version     "4.2.1"
                                  :jar!        #(swap! calls conj :jar)
                                  :publish!    #(swap! calls conj :publish)}))
                  (should= [:assert-ci :verify-ci :assert-untagged :jar :publish :tag] @calls)))

            (it "does not tag when publishing throws"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!       (constantly nil)
                                sut/verify-ci!       (constantly nil)
                                sut/assert-untagged! (constantly nil)
                                sut/tag!             (fn [_] (swap! calls conj :tag))]
                    (should-throw Exception
                                  (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                                :ci-workflow "build.yml"
                                                :version     "4.2.1"
                                                :jar!        (constantly nil)
                                                :publish!    #(throw (ex-info "clojars said no" {}))})))
                  (should= [] @calls))))

          (context "emergency-deploy!"
            (it "refuses when the break-glass variable is unset"
                (let [calls (atom [])]
                  (should-contain "C3KIT_EMERGENCY_RELEASE"
                                  (capturing (fn [] (with-redefs [sut/getenv (constantly nil)]
                                                      (sut/emergency-deploy! {:version  "4.2.1"
                                                                              :jar!     #(swap! calls conj :jar)
                                                                              :publish! #(swap! calls conj :publish)})))))
                  (should= [] @calls)))

            (it "refuses when the break-glass variable names a different version"
                (let [calls (atom [])]
                  (should-contain "C3KIT_EMERGENCY_RELEASE"
                                  (capturing (fn [] (with-redefs [sut/getenv (constantly "4.2.0")]
                                                      (sut/emergency-deploy! {:version  "4.2.1"
                                                                              :jar!     #(swap! calls conj :jar)
                                                                              :publish! #(swap! calls conj :publish)})))))
                  (should= [] @calls)))

            (it "proceeds when the variable names the exact version, skipping the CI check"
                (let [calls (atom [])]
                  (with-redefs [sut/getenv             (constantly "4.2.1")
                                sut/assert-clean-tree! (fn [] (swap! calls conj :clean-tree))
                                sut/assert-untagged!   (fn [_] (swap! calls conj :assert-untagged))
                                sut/head-sha           (constantly "abc123")
                                sut/verify-ci!         (fn [_] (swap! calls conj :verify-ci))
                                sut/tag!               (fn [_] (swap! calls conj :tag))]
                    (sut/emergency-deploy! {:version  "4.2.1"
                                            :jar!     #(swap! calls conj :jar)
                                            :publish! #(swap! calls conj :publish)}))
                  (should= [:clean-tree :assert-untagged :jar :publish :tag] @calls)
                  (should-not-contain :verify-ci @calls)))))

(run-specs)
