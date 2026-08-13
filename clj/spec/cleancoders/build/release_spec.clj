(ns cleancoders.build.release-spec
  (:require [cleancoders.build.publish-verify :as pv]
            [cleancoders.build.release :as sut]
            [cleancoders.build.shell :as shell]
            [cleancoders.build.sign :as sign]
            [cleancoders.build.summary :as summary]
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

(defn- capturing-value
  "Runs f with abort! captured, returning f's value."
  [f]
  (with-redefs [sut/abort! (fn [& msg] (throw (ex-info (cstr/join " " msg) {:aborted true})))]
    (f)))

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
                  (should-contain "head_sha=abc123" (nth gh-args 2))))

            (it "checks every workflow when given a vector"
                (should-be-nil
                 (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                              ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                               (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                                :ci-workflow ["build.yml" "security.yml"]}))))
                (should= 2 (count (filter #(= "gh" (first %)) @commands))))

            (it "queries each named workflow"
                (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                             ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                              (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                               :ci-workflow ["build.yml" "security.yml"]})))
                (let [paths (map #(nth % 2) (filter #(= "gh" (first %)) @commands))]
                  (should-contain "/actions/workflows/build.yml/runs" (first paths))
                  (should-contain "/actions/workflows/security.yml/runs" (second paths))))

            (it "aborts naming the workflow that was not green"
                (let [msg (capturing
                           #(with-redefs [shell/sh (fn [& args]
                                                     (swap! commands conj (vec args))
                                                     (cond (= "git" (first args)) {:exit 0 :out "abc123\n" :err ""}
                                                           (re-find #"security\.yml" (str args)) {:exit 0 :out "completed failure" :err ""}
                                                           :else {:exit 0 :out "completed success" :err ""}))]
                              (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                               :ci-workflow ["build.yml" "security.yml"]})))]
                  (should-contain "concluded failure" msg)
                  (should-contain "security.yml" msg)))

            (it "reads HEAD once no matter how many workflows are named"
                (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                             ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                              (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                               :ci-workflow ["build.yml" "security.yml" "lint.yml"]})))
                (should= 1 (count (filter #(= ["git" "rev-parse"] (vec (take 2 %))) @commands))))

            (it "aborts when no CI workflow is named"
                (should-contain "cannot be gated on nothing"
                                (capturing #(sut/verify-ci! {:repo "cleancoders/c3kit-wire" :ci-workflow []}))))

            (it "aborts when the workflow name is blank"
                (should-contain "cannot be gated on nothing"
                                (capturing #(sut/verify-ci! {:repo "cleancoders/c3kit-wire" :ci-workflow "  "}))))

            (it "aborts on a blank entry in a list without querying the named workflows"
                (let [msg (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                                       ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                                        (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                                         :ci-workflow ["build.yml" "  "]})))]
                  (should-contain "cannot be gated on nothing" msg)
                  (should= 0 (count (filter #(= "gh" (first %)) @commands))))))

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

          (context "tag-message"
            (with artifacts [{:name "bucket-2.14.0.jar" :digest "1f3a"}
                             {:name "bucket-2.14.0.pom" :digest "8c02"}])

            (it "starts with the version, which git shows as the tag subject"
                (should-start-with "4.2.1" (sut/tag-message "4.2.1" "abc123" @artifacts)))

            (it "records the commit and every artifact digest, so a clone answers what shipped"
                (let [msg (sut/tag-message "4.2.1" "abc123" @artifacts)]
                  (should-contain "abc123" msg)
                  (should-contain "bucket-2.14.0.jar" msg)
                  (should-contain "sha256:1f3a" msg)
                  (should-contain "bucket-2.14.0.pom" msg)
                  (should-contain "sha256:8c02" msg))))

          (context "tag!"
            (before (reset! commands []))

            (it "creates a signed annotated tag at sha and pushes it"
                (should-be-nil
                 (capturing #(with-redefs [shell/sh (stub-sh {})]
                               (sut/tag! "4.2.1" "abc123" "4.2.1\n\nmessage"))))
                (should= ["git" "tag" "-s" "-a" "4.2.1" "-m" "4.2.1\n\nmessage" "abc123"] (first @commands))
                (should= ["git" "push" "origin" "refs/tags/4.2.1"] (second @commands)))

            (it "aborts when git tag fails"
                (should-contain "already exists"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "tag"] {:exit 128 :out "" :err "already exists"}})]
                                              (sut/tag! "4.2.1" "abc123" "msg")))))

            (it "aborts when the tag push fails"
                (should-contain "rejected"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "push"] {:exit 1 :out "" :err "rejected"}})]
                                              (sut/tag! "4.2.1" "abc123" "msg")))))

            (it "states the release is already live, and repairs with a signed tag"
                (let [msg (capturing #(with-redefs [shell/sh (stub-sh {["git" "push"] {:exit 1 :out "" :err "rejected"}})]
                                        (sut/tag! "4.2.1" "abc123" "msg")))]
                  (should-contain "published 4.2.1" msg)
                  (should-contain "live on Clojars" msg)
                  (should-contain "git tag -s -a 4.2.1 abc123" msg)
                  (should-contain "git push origin refs/tags/4.2.1" msg)
                  (should-contain "rejected" msg)))

            (it "states the release is already live when git tag itself fails"
                (let [msg (capturing #(with-redefs [shell/sh (stub-sh {["git" "tag"] {:exit 128 :out "" :err "already exists"}})]
                                        (sut/tag! "4.2.1" "abc123" "msg")))]
                  (should-contain "published 4.2.1" msg)
                  (should-contain "git tag -s -a 4.2.1 abc123" msg))))

          (context "assert-signing-key!"
            (it "proceeds when a key is configured"
                (should-be-nil (capturing #(with-redefs [sign/configured? (constantly true)]
                                             (sut/assert-signing-key!)))))

            (it "aborts naming both variables and says nothing was built"
                (let [msg (capturing #(with-redefs [sign/configured? (constantly false)]
                                        (sut/assert-signing-key!)))]
                  (should-contain "GPG_PRIVATE_KEY" msg)
                  (should-contain "GPG_PASSPHRASE" msg)
                  (should-contain "clojars environment" msg)
                  (should-contain "no release occurred" msg))))

          (context "sign!"
            (it "returns the thunk's value when signing succeeds"
                (should= [:asc] (capturing-value #(sut/sign! (constantly [:asc])))))

            (it "aborts with the reason when signing throws, before anything is published"
                (should-contain "could not sign target/bucket-2.14.0.jar"
                                (capturing #(sut/sign! (fn [] (throw (ex-info "could not sign target/bucket-2.14.0.jar" {}))))))))

          (context "verify-published!"
            (it "verifies every artifact that carries a url"
                (let [checked (atom [])]
                  (should-be-nil
                   (capturing #(with-redefs [pv/verify! (fn [opts] (swap! checked conj (:url opts)) nil)]
                                 (sut/verify-published! "4.2.1" "abc123"
                                                        [{:name "a.jar" :digest "1f3a" :url "https://clojars/a.jar"}
                                                         {:name "a.pom" :digest "8c02"}]))))
                  (should= ["https://clojars/a.jar"] @checked)))

            (it "passes the local digest to the verifier"
                (let [captured (atom nil)]
                  (capturing #(with-redefs [pv/verify! (fn [opts] (reset! captured opts) nil)]
                                (sut/verify-published! "4.2.1" "abc123"
                                                       [{:name "a.jar" :digest "1f3a" :url "https://clojars/a.jar"}])))
                  (should= "1f3a" (:digest @captured))))

            ;; No shell/sh stub needed here: verify-published! takes sha as an
            ;; argument now (rather than re-deriving it via released-sha), so
            ;; the failure message is built entirely from its own arguments.
            (it "aborts saying the artifact is live and gives the manual check"
                (let [msg (capturing #(with-redefs [pv/verify! (constantly "digest mismatch: Clojars has sha256:bbbb")]
                                        (sut/verify-published! "2.14.0" "abc123"
                                                               [{:name "bucket-2.14.0.jar" :digest "1f3a"
                                                                 :url  "https://clojars/bucket-2.14.0.jar"}])))]
                  (should-contain "digest mismatch" msg)
                  (should-contain "published 2.14.0" msg)
                  (should-contain "cannot be republished" msg)
                  (should-contain "https://clojars/bucket-2.14.0.jar" msg)
                  (should-contain "1f3a" msg))))

          (context "record!"
            (it "emits the rendered summary"
                (let [emitted (atom nil)]
                  (with-redefs [summary/emit! (fn [text] (reset! emitted text))]
                    (sut/record! {:version   "2.14.0"
                                  :sha       "abc123"
                                  :artifacts [{:name "bucket-2.14.0.jar" :digest "1f3a"}]}))
                  (should-contain "2.14.0" @emitted)
                  (should-contain "abc123" @emitted)
                  (should-contain "1f3a" @emitted))))

          (context "deploy!"
            (it "runs every gate in order: key, CI, tag check, jar, sign, publish, verify, record, tag"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!           (fn [] (swap! calls conj :assert-ci))
                                sut/assert-signing-key!  (fn [] (swap! calls conj :assert-signing-key))
                                sut/verify-ci!           (fn [_] (swap! calls conj :verify-ci))
                                sut/assert-untagged!     (fn [_] (swap! calls conj :assert-untagged))
                                sut/verify-published!    (fn [_ _ _] (swap! calls conj :verify-published))
                                sut/record!              (fn [_] (swap! calls conj :record))
                                sut/head-sha             (constantly "abc123")
                                sut/tag!                 (fn [_ _ _] (swap! calls conj :tag))]
                    (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                  :ci-workflow "build.yml"
                                  :version     "4.2.1"
                                  :jar!        #(swap! calls conj :jar)
                                  :sign!       #(swap! calls conj :sign)
                                  :publish!    #(swap! calls conj :publish)
                                  :artifacts   (fn [] [])}))
                  (should= [:assert-ci :assert-signing-key :verify-ci :assert-untagged
                            :jar :sign :publish :verify-published :record :tag]
                           @calls)))

            (it "checks for the signing key before spending CI queries or building"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!    (constantly nil)
                                sign/configured?  (constantly false)
                                sut/verify-ci!    (fn [_] (swap! calls conj :verify-ci))]
                    (capturing (fn [] (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                                    :ci-workflow "build.yml"
                                                    :version     "4.2.1"
                                                    :jar!        #(swap! calls conj :jar)
                                                    :sign!       (constantly nil)
                                                    :publish!    #(swap! calls conj :publish)
                                                    :artifacts   (fn [] [])}))))
                  (should= [] @calls)))

            (it "reads the artifact list after the jar is built, not before"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/verify-published!   (constantly nil)
                                sut/record!             (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                sut/tag!                (fn [_ _ _] nil)]
                    (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                  :ci-workflow "build.yml"
                                  :version     "4.2.1"
                                  :jar!        #(swap! calls conj :jar)
                                  :sign!       (constantly nil)
                                  :publish!    (constantly nil)
                                  :artifacts   (fn [] (swap! calls conj :artifacts) [])}))
                  (should= [:jar :artifacts] @calls)))

            (it "puts the digests in the tag message"
                (let [tagged (atom nil)]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/verify-published!   (constantly nil)
                                sut/record!             (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                sut/tag!                (fn [_ _ message] (reset! tagged message))]
                    (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                  :ci-workflow "build.yml"
                                  :version     "4.2.1"
                                  :jar!        (constantly nil)
                                  :sign!       (constantly nil)
                                  :publish!    (constantly nil)
                                  :artifacts   (fn [] [{:name "wire-4.2.1.jar" :digest "1f3a"}])}))
                  (should-contain "wire-4.2.1.jar" @tagged)
                  (should-contain "sha256:1f3a" @tagged)))

            (it "does not publish when signing fails"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                sut/tag!                (fn [_ _ _] (swap! calls conj :tag))]
                    (capturing (fn [] (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                                    :ci-workflow "build.yml"
                                                    :version     "4.2.1"
                                                    :jar!        (constantly nil)
                                                    :sign!       (fn [] (throw (ex-info "no secret key" {})))
                                                    :publish!    #(swap! calls conj :publish)
                                                    :artifacts   (fn [] [])}))))
                  (should= [] @calls)))

            (it "does not tag when publishing throws"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                sut/tag!                (fn [_ _ _] (swap! calls conj :tag))]
                    (should-throw Exception "clojars said no"
                                  (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                                :ci-workflow "build.yml"
                                                :version     "4.2.1"
                                                :jar!        (constantly nil)
                                                :sign!       (constantly nil)
                                                :publish!    #(do (swap! calls conj :publish)
                                                                  (throw (ex-info "clojars said no" {})))
                                                :artifacts   (fn [] [])})))
                  ;; :publish is recorded before the throw, so this pins that
                  ;; publish! genuinely ran (not that deploy! blew up earlier
                  ;; and never got there) -- and that tag! still never fires.
                  (should= [:publish] @calls)))

            (it "does not tag when post-publish verification fails"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                pv/verify!              (constantly "digest mismatch: Clojars has sha256:bbbb")
                                sut/tag!                (fn [_ _ _] (swap! calls conj :tag))]
                    (capturing #(sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                              :ci-workflow "build.yml"
                                              :version     "4.2.1"
                                              :jar!        (constantly nil)
                                              :sign!       (constantly nil)
                                              :publish!    (constantly nil)
                                              :artifacts   (fn [] [{:name "wire-4.2.1.jar" :digest "1f3a"
                                                                    :url  "https://clojars/wire-4.2.1.jar"}])})))
                  (should= [] @calls)))

            ;; This message must NOT claim the release is otherwise complete
            ;; (verify-published! and record! never ran) and must NOT hand
            ;; over a bare tag command (there is no artifact list to build one
            ;; from, and tagging unverified bytes is what this whole path
            ;; exists to prevent) -- so assert those specifically, not just a
            ;; few substrings that would still be present in a wrong message.
            (it "does not tag when reading the shipped artifacts throws, and says verification never ran"
                (let [calls (atom [])
                      msg   (capturing (fn [] (with-redefs [sut/assert-ci!          (constantly nil)
                                                            sut/assert-signing-key! (constantly nil)
                                                            sut/verify-ci!          (constantly nil)
                                                            sut/assert-untagged!    (constantly nil)
                                                            sut/head-sha            (constantly "abc123")
                                                            sut/tag!                (fn [_ _ _] (swap! calls conj :tag))]
                                                (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                                              :ci-workflow "build.yml"
                                                              :version     "4.2.1"
                                                              :jar!        (constantly nil)
                                                              :sign!       (constantly nil)
                                                              :publish!    (constantly nil)
                                                              :artifacts   (fn [] (throw (ex-info "no such file" {})))}))))]
                  (should-contain "published 4.2.1" msg)
                  (should-contain "live on Clojars" msg)
                  (should-contain "no such file" msg)
                  (should-contain "NOT been verified" msg)
                  (should-contain "no digest record" msg)
                  (should-contain "Do NOT tag yet" msg)
                  (should-not-contain "otherwise complete" msg)
                  (should-not-contain "git tag -s -a" msg)
                  (should= [] @calls))))

          (context "emergency-deploy!"
            (it "refuses when the break-glass variable is unset"
                (let [calls (atom [])]
                  (should-contain "EMERGENCY_RELEASE"
                                  (capturing (fn [] (with-redefs [sut/getenv (constantly nil)]
                                                      (sut/emergency-deploy! {:version   "4.2.1"
                                                                              :jar!      #(swap! calls conj :jar)
                                                                              :sign!     (constantly nil)
                                                                              :publish!  #(swap! calls conj :publish)
                                                                              :artifacts (fn [] [])})))))
                  (should= [] @calls)))

            (it "refuses when the break-glass variable names a different version"
                (let [calls (atom [])]
                  (should-contain "EMERGENCY_RELEASE"
                                  (capturing (fn [] (with-redefs [sut/getenv (constantly "4.2.0")]
                                                      (sut/emergency-deploy! {:version   "4.2.1"
                                                                              :jar!      #(swap! calls conj :jar)
                                                                              :sign!     (constantly nil)
                                                                              :publish!  #(swap! calls conj :publish)
                                                                              :artifacts (fn [] [])})))))
                  (should= [] @calls)))

            (it "still requires a signing key: an emergency is no reason to ship unverifiable bytes"
                (let [calls (atom [])
                      msg   (capturing (fn [] (with-redefs [sut/getenv       (constantly "4.2.1")
                                                            sign/configured? (constantly false)]
                                                (sut/emergency-deploy! {:version   "4.2.1"
                                                                        :jar!      #(swap! calls conj :jar)
                                                                        :sign!     (constantly nil)
                                                                        :publish!  #(swap! calls conj :publish)
                                                                        :artifacts (fn [] [])}))))]
                  (should-contain "GPG_PRIVATE_KEY" msg)
                  (should= [] @calls)))

            (it "proceeds when the variable names the exact version, skipping only the CI check"
                (let [calls (atom [])]
                  (with-redefs [sut/getenv              (constantly "4.2.1")
                                sut/assert-signing-key! (fn [] (swap! calls conj :assert-signing-key))
                                sut/assert-clean-tree!  (fn [] (swap! calls conj :clean-tree))
                                sut/assert-untagged!    (fn [_] (swap! calls conj :assert-untagged))
                                sut/verify-published!   (fn [_ _ _] (swap! calls conj :verify-published))
                                sut/record!             (fn [_] (swap! calls conj :record))
                                sut/head-sha            (constantly "abc123")
                                sut/verify-ci!          (fn [_] (swap! calls conj :verify-ci))
                                summary/emit!           (constantly nil)
                                sut/tag!                (fn [_ _ _] (swap! calls conj :tag))]
                    (sut/emergency-deploy! {:version   "4.2.1"
                                            :jar!      #(swap! calls conj :jar)
                                            :sign!     #(swap! calls conj :sign)
                                            :publish!  #(swap! calls conj :publish)
                                            :artifacts (fn [] [])}))
                  (should= [:assert-signing-key :clean-tree :assert-untagged :jar :sign
                            :publish :verify-published :record :tag]
                           @calls)
                  (should-not-contain :verify-ci @calls)))

            (it "authorizes against the custom variable when one is given, using it as the lookup key"
                (let [calls  (atom [])
                      looked (atom [])]
                  (with-redefs [sut/getenv              (fn [n] (swap! looked conj n) "4.2.1")
                                sut/assert-signing-key! (fn [] (swap! calls conj :assert-signing-key))
                                sut/assert-clean-tree!  (fn [] (swap! calls conj :clean-tree))
                                sut/assert-untagged!    (fn [_] (swap! calls conj :assert-untagged))
                                sut/verify-published!   (fn [_ _ _] (swap! calls conj :verify-published))
                                sut/record!             (fn [_] (swap! calls conj :record))
                                sut/head-sha            (constantly "abc123")
                                summary/emit!           (constantly nil)
                                sut/tag!                (fn [_ _ _] (swap! calls conj :tag))]
                    (sut/emergency-deploy! {:version       "4.2.1"
                                            :emergency-var "MY_VAR"
                                            :jar!          #(swap! calls conj :jar)
                                            :sign!         #(swap! calls conj :sign)
                                            :publish!      #(swap! calls conj :publish)
                                            :artifacts     (fn [] [])}))
                  ;; getenv is also called for GITHUB_ACTOR (the banner), so
                  ;; this asserts MY_VAR was among the lookups, not merely the
                  ;; last one -- confirming it authorized the release rather
                  ;; than just appearing in the abort message's text.
                  (should-contain "MY_VAR" @looked)
                  (should= [:assert-signing-key :clean-tree :assert-untagged :jar :sign
                            :publish :verify-published :record :tag]
                           @calls)))

            (it "emits an audit banner naming the actor and the authorizing variable"
                (let [emitted (atom [])]
                  (with-redefs [sut/getenv              (fn [n] (if (= "GITHUB_ACTOR" n) "someone" "4.2.1"))
                                sut/assert-signing-key! (constantly nil)
                                sut/assert-clean-tree!  (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/verify-published!   (constantly nil)
                                sut/record!             (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                summary/emit!           (fn [text] (swap! emitted conj text))
                                sut/tag!                (fn [_ _ _] nil)]
                    (sut/emergency-deploy! {:version   "4.2.1"
                                            :jar!      (constantly nil)
                                            :sign!     (constantly nil)
                                            :publish!  (constantly nil)
                                            :artifacts (fn [] [])}))
                  (let [banner (first (filter #(re-find #"EMERGENCY" %) @emitted))]
                    (should-contain "someone" banner)
                    (should-contain "4.2.1" banner)
                    (should-contain "abc123" banner)
                    (should-contain "EMERGENCY_RELEASE" banner))))

            (it "names the default variable in the abort message"
                (should-contain "EMERGENCY_RELEASE=4.2.1"
                                (capturing (fn [] (with-redefs [sut/getenv (constantly nil)]
                                                    (sut/emergency-deploy! {:version   "4.2.1"
                                                                            :jar!      (constantly nil)
                                                                            :sign!     (constantly nil)
                                                                            :publish!  (constantly nil)
                                                                            :artifacts (fn [] [])}))))))

            (it "honors a custom :emergency-var in the abort message"
                (should-contain "C3KIT_EMERGENCY_RELEASE=4.2.1"
                                (capturing (fn [] (with-redefs [sut/getenv (constantly nil)]
                                                    (sut/emergency-deploy! {:version       "4.2.1"
                                                                            :emergency-var "C3KIT_EMERGENCY_RELEASE"
                                                                            :jar!          (constantly nil)
                                                                            :sign!         (constantly nil)
                                                                            :publish!      (constantly nil)
                                                                            :artifacts     (fn [] [])}))))))

            (it "falls back to the default variable when :emergency-var is blank"
                (let [looked (atom nil)
                      msg    (capturing (fn [] (with-redefs [sut/getenv (fn [n] (reset! looked n) nil)]
                                                 (sut/emergency-deploy! {:version       "4.2.1"
                                                                         :emergency-var ""
                                                                         :jar!          (constantly nil)
                                                                         :sign!         (constantly nil)
                                                                         :publish!      (constantly nil)
                                                                         :artifacts     (fn [] [])}))))]
                  (should= "EMERGENCY_RELEASE" @looked)
                  (should-contain "EMERGENCY_RELEASE=4.2.1" msg)))))

(run-specs)
