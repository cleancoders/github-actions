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

(def colon-output
  (str "sec:u:255:22:AAAA1111BBBB2222:1700000000:::u:::scESC:::+::ed25519:::0:\n"
       "fpr:::::::::1111222233334444555566667777888899990000:\n"
       "uid:u::::1700000000::ABC::Release Signing Key <releases@example.com>::::::::::0:\n"))

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

          (context "import-key!"
            (before (reset! commands []))

            (it "imports the key, primes the agent, and returns the fingerprint"
                (let [id (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}
                                       shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                           (sut/import-key!))]
                  (should= "1111222233334444555566667777888899990000" id)))

            (it "feeds the key material on stdin, never as an argument"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "SECRET-KEY-MATERIAL" "GPG_PASSPHRASE" "pw"}
                              shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (let [flat (pr-str (remove #(= :in %) (flatten @commands)))]
                  (should-not-contain "SECRET-KEY-MATERIAL" (pr-str (take-while #(not= :in %) (args-for "gpg"))))
                  (should-contain "SECRET-KEY-MATERIAL" flat)))

            (it "never puts the passphrase in an argument vector"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "s3cret-pass"}
                              shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (doseq [command @commands]
                  (let [positional (take-while #(not= :in %) command)]
                    (should-not-contain "s3cret-pass" (pr-str positional)))))

            (it "configures git to sign with the imported key"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}
                              shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
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

            (it "throws when the import fails"
                (should-throw clojure.lang.ExceptionInfo "could not import the signing key: bad key"
                              (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}
                                            shell/sh   (stub-sh {["gpg" "--import"] {:exit 2 :out "" :err "bad key"}})]
                                (sut/import-key!))))

            (it "throws when no secret key is present after a successful import"
                (should-throw clojure.lang.ExceptionInfo
                              (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}
                                            shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out "" :err ""}})]
                                (sut/import-key!))))

            (it "throws when the agent will not accept the passphrase"
                (should-throw clojure.lang.ExceptionInfo
                              (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "wrong"}
                                            shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}
                                                                 ["gpg" "--detach-sign"]     {:exit 2 :out "" :err "bad passphrase"}})]
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
                                 (sut/sign-file! (.getAbsolutePath target)))]
                    (should= (.getAbsolutePath asc) result)
                    (should-contain "--detach-sign" (args-for "gpg"))
                    (should-contain "--armor" (args-for "gpg")))))

            (it "throws when gpg fails"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))]
                  (should-throw clojure.lang.ExceptionInfo
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (stub-sh {["gpg"] {:exit 2 :out "" :err "no secret key"}})]
                                  (sut/sign-file! (.getAbsolutePath target))))))

            (it "throws when gpg reports success but wrote no signature"
                ;; A silently empty .asc would be published as a valid-looking
                ;; signature that verifies against nothing.
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))]
                  (should-throw clojure.lang.ExceptionInfo
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (stub-sh {})]
                                  (sut/sign-file! (.getAbsolutePath target))))))

            (it "throws when gpg wrote an empty signature file"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))
                      asc    (java.io.File. (str (.getAbsolutePath target) ".asc"))]
                  (.deleteOnExit asc)
                  (should-throw clojure.lang.ExceptionInfo
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (fn [& _] (spit asc "") {:exit 0 :out "" :err ""})]
                                  (sut/sign-file! (.getAbsolutePath target))))))))

(run-specs)
