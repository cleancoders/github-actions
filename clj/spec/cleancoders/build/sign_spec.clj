(ns cleancoders.build.sign-spec
  (:require [cleancoders.build.shell :as shell]
            [cleancoders.build.sign :as sut]
            [speclj.core :refer :all]))

(def commands (atom []))

(defn- stub-sh
  "Records invocations and answers from responses, keyed by the first two args
   or the first arg. Unlisted commands succeed silently."
  [responses]
  (fn [& args]
    (swap! commands conj (vec args))
    (get responses (vec (take 2 args))
         (get responses [(first args)] {:exit 0 :out "" :err ""}))))

(defn- stub-sh-signing
  "Like stub-sh, but a successful --detach-sign invocation also writes a
   placeholder .asc beside its target path, mirroring what gpg does on disk.
   import-key!'s passphrase proof calls the real sign-file!, which requires
   that file to exist; the sign-file! spec controls file-writing explicitly
   and does not need this variant."
  [responses]
  (let [answer (stub-sh responses)]
    (fn [& args]
      (let [result (apply answer args)]
        (when (and (zero? (:exit result)) (some #{"--detach-sign"} args))
          ;; Assumes gpg-sign!'s target path is the last positional argument
          ;; (before :in) -- a flag-order coupling like round 1's, so a future
          ;; reordering of gpg-sign!'s args needs this comment updated too.
          (spit (str (last (take-while #(not= :in %) args)) ".asc") "-----BEGIN PGP SIGNATURE-----"))
        result))))

(def colon-output
  (str "sec:u:255:22:AAAA1111BBBB2222:1700000000:::u:::scESC:::+::ed25519:::0:\n"
       "fpr:::::::::1111222233334444555566667777888899990000:\n"
       "uid:u::::1700000000::ABC::Release Signing Key <releases@example.com>::::::::::0:\n"))

(def colon-output-no-contact
  (str "sec:u:255:22:AAAA1111BBBB2222:1700000000:::u:::scESC:::+::ed25519:::0:\n"
       "fpr:::::::::1111222233334444555566667777888899990000:\n"
       "uid:u::::1700000000::ABC::Release Signing Key::::::::::0:\n"))

(def passphrase-rejected-message
  #"the signing key could not sign a test file; check GPG_PASSPHRASE: could not sign .*: bad passphrase")

(def gnupg-dir
  "A scratch gpg home, created lazily and reused for the whole run rather than
   at namespace load -- a run that never exercises import-key! (e.g. just
   key-id) should not leave a directory behind at all."
  (delay (.getAbsolutePath (doto (java.io.File/createTempFile "sign-spec-gnupg" "")
                             (.delete)
                             (.mkdir)))))

(defn- with-gnupg-home
  "Merges GNUPGHOME into a getenv stub map, pointed at a scratch directory, so
   import-key! never touches the operator's real ~/.gnupg while under test."
  ([env] (with-gnupg-home env @gnupg-dir))
  ([env dir] (assoc env "GNUPGHOME" dir)))

(defn- default-env
  "A getenv stub map for import-key!, defaulting to a working key, passphrase,
   and scratch GNUPGHOME. `overrides` replaces individual variables so each
   spec can flip just the one value it is testing."
  [& {:as overrides}]
  (with-gnupg-home (merge {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"} overrides)))

(defn- args-for [command]
  (first (filter #(= command (first %)) @commands)))

(describe "sign"

          (context "configured?"
            (it "is true when both variables are present"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}]
                  (should= true (sut/configured?))))

            (it "is false when the key is missing"
                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}]
                  (should= false (sut/configured?))))

            (it "is false when the passphrase is missing"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY"}]
                  (should= false (sut/configured?))))

            (it "is false when either is blank rather than absent"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "   "}]
                  (should= false (sut/configured?)))))

          (context "key-id"
            (it "reads the fingerprint of the imported secret key"
                (should= "1111222233334444555566667777888899990000" (sut/key-id colon-output)))

            (it "is nil when no secret key is present"
                (should-be-nil (sut/key-id "")))

            (it "is nil when a public key exists but no secret key does"
                (should-be-nil (sut/key-id "pub:u:255:22:X:1700000000:::u:::scESC:::+::ed25519:::0:\n"))))

          (context "gnupg-home"
            (it "defaults to ~/.gnupg under the user's home directory when GNUPGHOME is unset"
                (with-redefs [sut/getenv {}]
                  (should= (java.io.File. (System/getProperty "user.home") ".gnupg") (sut/gnupg-home))))

            (it "honors GNUPGHOME when it is set"
                (with-redefs [sut/getenv {"GNUPGHOME" "/tmp/sign-spec-gnupg-home-test"}]
                  (should= (java.io.File. "/tmp/sign-spec-gnupg-home-test") (sut/gnupg-home)))))

          (context "import-key!"
            (before (reset! commands []))
            ;; Hardens the CRITICAL fix structurally: every spec below signs
            ;; against the shared scratch directory no matter what its own
            ;; getenv stub says, so a future spec that forgets GNUPGHOME still
            ;; cannot reach the operator's real ~/.gnupg.
            (redefs-around [sut/gnupg-home (constantly (java.io.File. ^String @gnupg-dir))])

            (it "imports the key, primes the agent, and returns the fingerprint"
                (let [id (with-redefs [sut/getenv (default-env)
                                       shell/sh   (stub-sh-signing
                                                   {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                           (sut/import-key!))]
                  (should= "1111222233334444555566667777888899990000" id)))

            (it "feeds the key material on stdin, never as an argument"
                (with-redefs [sut/getenv (default-env "GPG_PRIVATE_KEY" "SECRET-KEY-MATERIAL")
                              shell/sh   (stub-sh-signing
                                          {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (let [flat (pr-str (remove #(= :in %) (flatten @commands)))]
                  (should-not-contain "SECRET-KEY-MATERIAL" (pr-str (take-while #(not= :in %) (args-for "gpg"))))
                  (should-contain "SECRET-KEY-MATERIAL" flat)))

            (it "never puts the passphrase in an argument vector"
                (with-redefs [sut/getenv (default-env "GPG_PASSPHRASE" "s3cret-pass")
                              shell/sh   (stub-sh-signing
                                          {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (should-not= [] @commands)
                (doseq [command @commands]
                  (let [positional (take-while #(not= :in %) command)]
                    (should-not-contain "s3cret-pass" (pr-str positional)))))

            (it "configures git to sign with the imported key"
                (with-redefs [sut/getenv (default-env)
                              shell/sh   (stub-sh-signing
                                          {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (let [configs (filter #(= ["git" "config"] (vec (take 2 %))) @commands)
                      flat    (pr-str configs)]
                  (should-contain "user.signingkey" flat)
                  (should-contain "1111222233334444555566667777888899990000" flat)
                  ;; git tag -a refuses to run without an identity, and GitHub
                  ;; runners have none configured.
                  (should-contain "user.name" flat)
                  (should-contain "user.email" flat)
                  (should-contain "releases@example.com" flat)))

            (it "writes the gpg-agent configuration inside the scratch GNUPGHOME, never $HOME"
                (with-redefs [sut/getenv (default-env)
                              shell/sh   (stub-sh-signing
                                          {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (should= true (.exists (java.io.File. ^String @gnupg-dir "gpg-agent.conf"))))

            (it "throws when the import fails"
                (should-throw clojure.lang.ExceptionInfo "could not import the signing key: bad key"
                              (with-redefs [sut/getenv (default-env)
                                            shell/sh   (stub-sh-signing
                                                        {["gpg" "--import"] {:exit 2 :out "" :err "bad key"}})]
                                (sut/import-key!))))

            (it "throws when no secret key is present after a successful import"
                (should-throw clojure.lang.ExceptionInfo
                              "no secret key present after import; is GPG_PRIVATE_KEY a private key?"
                              (with-redefs [sut/getenv (default-env)
                                            shell/sh   (stub-sh-signing
                                                        {["gpg" "--list-secret-keys"] {:exit 0 :out "" :err ""}})]
                                (sut/import-key!))))

            (it "throws when the agent will not accept the passphrase, preserving gpg's stderr"
                (let [responses {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}
                                 ["gpg" "--detach-sign"]     {:exit 2 :out "" :err "bad passphrase"}}]
                  (should-throw clojure.lang.ExceptionInfo passphrase-rejected-message
                                (with-redefs [sut/getenv (default-env "GPG_PASSPHRASE" "wrong")
                                              shell/sh   (stub-sh-signing responses)]
                                  (sut/import-key!)))))

            (it "throws when configuring the signing key with git fails"
                (let [responses {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}
                                 ["git" "config"]            {:exit 1 :out "" :err "not a repository"}}]
                  (should-throw clojure.lang.ExceptionInfo "could not configure git user.signingkey: not a repository"
                                (with-redefs [sut/getenv (default-env)
                                              shell/sh   (stub-sh-signing responses)]
                                  (sut/import-key!)))))

            (it "throws when the gpg agent will not reload"
                (should-throw clojure.lang.ExceptionInfo "could not reload the gpg agent: no agent"
                              (with-redefs [sut/getenv (default-env)
                                            shell/sh   (stub-sh-signing
                                                        {["gpg-connect-agent" "reloadagent"]
                                                         {:exit 1 :out "" :err "no agent"}})]
                                (sut/import-key!))))

            (it "throws when the uid carries no name or email"
                (should-throw clojure.lang.ExceptionInfo
                              "the signing key's user id must include a name and an email address"
                              (with-redefs [sut/getenv (default-env)
                                            shell/sh   (stub-sh-signing
                                                        {["gpg" "--list-secret-keys"]
                                                         {:exit 0 :out colon-output-no-contact :err ""}})]
                                (sut/import-key!)))))

          (context "sign-file!"
            (before (reset! commands []))

            (it "produces a detached armored signature and returns its path"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))
                      asc    (java.io.File. (str (.getAbsolutePath target) ".asc"))]
                  (.deleteOnExit asc)
                  (let [result (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                             shell/sh   (fn [& args]
                                                          (swap! commands conj (vec args))
                                                          (spit asc "-----BEGIN PGP SIGNATURE-----")
                                                          {:exit 0 :out "" :err ""})]
                                 (sut/sign-file! "FPR" (.getAbsolutePath target)))]
                    (should= (.getAbsolutePath asc) result)
                    (should-contain "--detach-sign" (args-for "gpg"))
                    (should-contain "--armor" (args-for "gpg")))))

            ;; Without --local-user, gpg signs with whatever its default key is.
            ;; In CI the imported key is the only one, so the omission is
            ;; invisible there -- but a break-glass release from a developer's
            ;; machine would sign the artifacts with that developer's personal
            ;; key while `git tag -s` signed the tag with user.signingkey,
            ;; shipping a release whose signatures disagree about who made it.
            (it "signs with the key it was given rather than gpg's default key"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))
                      asc    (java.io.File. (str (.getAbsolutePath target) ".asc"))]
                  (.deleteOnExit asc)
                  (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                shell/sh   (fn [& args]
                                             (swap! commands conj (vec args))
                                             (spit asc "-----BEGIN PGP SIGNATURE-----")
                                             {:exit 0 :out "" :err ""})]
                    (sut/sign-file! "1111222233334444555566667777888899990000" (.getAbsolutePath target)))
                  (let [args (vec (args-for "gpg"))
                        i    (.indexOf args "--local-user")]
                    (should-not= -1 i)
                    ;; The fingerprint must be --local-user's value, not merely
                    ;; present somewhere in the vector.
                    (should= "1111222233334444555566667777888899990000" (nth args (inc i))))))

            (it "still keeps the passphrase off the argument vector when signing with a named key"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))
                      asc    (java.io.File. (str (.getAbsolutePath target) ".asc"))]
                  (.deleteOnExit asc)
                  (with-redefs [sut/getenv {"GPG_PASSPHRASE" "s3cret-pass"}
                                shell/sh   (fn [& args]
                                             (swap! commands conj (vec args))
                                             (spit asc "-----BEGIN PGP SIGNATURE-----")
                                             {:exit 0 :out "" :err ""})]
                    (sut/sign-file! "FPR" (.getAbsolutePath target)))
                  (should-not= [] @commands)
                  (doseq [command @commands]
                    (should-not-contain "s3cret-pass" (pr-str (take-while #(not= :in %) command))))))

            (it "throws when gpg fails"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))]
                  (should-throw clojure.lang.ExceptionInfo
                                (str "could not sign " (.getAbsolutePath target) ": no secret key")
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (stub-sh {["gpg"] {:exit 2 :out "" :err "no secret key"}})]
                                  (sut/sign-file! "FPR" (.getAbsolutePath target))))))

            (it "throws when gpg reports success but wrote no signature"
                ;; A silently empty .asc would be published as a valid-looking
                ;; signature that verifies against nothing.
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))]
                  (should-throw clojure.lang.ExceptionInfo
                                (str "gpg reported success but wrote no signature for " (.getAbsolutePath target))
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (stub-sh {})]
                                  (sut/sign-file! "FPR" (.getAbsolutePath target))))))

            (it "throws when gpg wrote an empty signature file"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))
                      asc    (java.io.File. (str (.getAbsolutePath target) ".asc"))]
                  (.deleteOnExit asc)
                  (should-throw clojure.lang.ExceptionInfo
                                (str "gpg wrote an empty signature for " (.getAbsolutePath target))
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (fn [& _] (spit asc "") {:exit 0 :out "" :err ""})]
                                  (sut/sign-file! "FPR" (.getAbsolutePath target))))))))

(run-specs)
