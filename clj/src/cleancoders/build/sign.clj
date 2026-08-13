(ns cleancoders.build.sign
  "GPG key handling and detached signatures.

   The passphrase always travels on a process's stdin, never in an argument
   vector: arguments are visible in a process listing and get echoed back in
   error messages, and this one unlocks the organization's release key.

   import-key! primes the gpg agent by signing a scratch file. That is
   load-bearing rather than decorative -- once the agent holds the passphrase,
   both sign-file! and `git tag -s` work with no further passphrase plumbing,
   which is what lets artifact signing and tag signing share one mechanism."
  (:require [cleancoders.build.shell :as shell]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def ^:private key-var "GPG_PRIVATE_KEY")
(def ^:private passphrase-var "GPG_PASSPHRASE")

(defn getenv
  "Indirection over System/getenv so specs can control the environment."
  [name]
  (System/getenv name))

(defn configured?
  "True when both signing variables hold something."
  []
  (not-any? #(str/blank? (str (getenv %))) [key-var passphrase-var]))

(defn- fail!
  [msg detail]
  (throw (ex-info (str msg (when-not (str/blank? (str detail)) (str ": " (str/trim (str detail))))) {})))

(defn key-id
  "Fingerprint of the first secret key in `gpg --list-secret-keys --with-colons`
   output. Reads the fpr record following a sec record: a public-only keyring
   also has fpr records, and signing with one is impossible."
  [colon-out]
  (->> (str/split-lines (str colon-out))
       (drop-while #(not (str/starts-with? % "sec:")))
       (some #(second (re-find #"^fpr:+([0-9A-F]+):" %)))))

(defn- uid-email
  "Email from the key's uid record, used as the git identity so tag objects
   carry the same identity that signed them."
  [colon-out]
  (->> (str/split-lines (str colon-out))
       (keep #(second (re-find #"^uid:.*<([^>]+)>" %)))
       first))

(defn- uid-name
  [colon-out]
  (->> (str/split-lines (str colon-out))
       (keep #(second (re-find #"^uid:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^<:]+)<" %)))
       first
       str/trim
       not-empty))

(defn- agent-conf!
  "Enables loopback pinentry and lengthens the passphrase cache. The default
   600-second cache can expire between signing the artifacts and signing the
   tag, which would stall a release waiting for a prompt no one can answer."
  []
  (let [dir (io/file (System/getProperty "user.home") ".gnupg")]
    (.mkdirs dir)
    (spit (io/file dir "gpg-agent.conf")
          "allow-loopback-pinentry\ndefault-cache-ttl 7200\nmax-cache-ttl 7200\n")
    (shell/sh "gpg-connect-agent" "reloadagent" "/bye")))

(defn- gpg-sign!
  "Detached-signs path, returning the sh result. The passphrase goes to stdin."
  [path]
  (shell/sh "gpg" "--detach-sign" "--armor" "--batch" "--yes" "--pinentry-mode" "loopback"
            "--passphrase-fd" "0" path
            :in (str (getenv passphrase-var))))

(defn sign-file!
  "Writes <path>.asc and returns that path. Verifies the signature file exists
   and is non-empty: gpg exiting zero having written nothing would publish a
   valid-looking signature that verifies against nothing."
  [path]
  (let [{:keys [exit err]} (gpg-sign! path)
        asc                (io/file (str path ".asc"))]
    (when-not (zero? exit)
      (fail! (str "could not sign " path) err))
    (when-not (.exists asc)
      (fail! (str "gpg reported success but wrote no signature for " path) nil))
    (when (zero? (.length asc))
      (fail! (str "gpg wrote an empty signature for " path) nil))
    (.getAbsolutePath asc)))

(defn import-key!
  "Imports the release key, primes the agent, points git at it, and returns the
   fingerprint."
  []
  (println "importing the signing key")
  (agent-conf!)
  (let [{:keys [exit err]} (shell/sh "gpg" "--import" "--batch" :in (str (getenv key-var)))]
    (when-not (zero? exit)
      (fail! "could not import the signing key" err)))
  (let [{:keys [exit out err]} (shell/sh "gpg" "--list-secret-keys" "--with-colons")]
    (when-not (zero? exit)
      (fail! "could not list the imported key" err))
    (let [id (key-id out)]
      (when-not id
        (fail! "no secret key present after import; is GPG_PRIVATE_KEY a private key?" nil))
      ;; Prime the agent, and prove the passphrase is right, before anything is
      ;; built. A wrong passphrase discovered at tag time strands a release.
      (let [scratch (doto (java.io.File/createTempFile "release-sign-check" ".txt") (.deleteOnExit))]
        (spit scratch "priming the gpg agent")
        (io/delete-file (io/file (str (.getAbsolutePath scratch) ".asc")) true)
        (let [{:keys [exit err]} (gpg-sign! (.getAbsolutePath scratch))]
          (when-not (zero? exit)
            (fail! "the signing key passphrase was rejected" err))
          (io/delete-file (io/file (str (.getAbsolutePath scratch) ".asc")) true)))
      (shell/sh "git" "config" "user.signingkey" id)
      (when-let [email (uid-email out)]
        (shell/sh "git" "config" "user.email" email))
      (when-let [name (uid-name out)]
        (shell/sh "git" "config" "user.name" name))
      id)))
