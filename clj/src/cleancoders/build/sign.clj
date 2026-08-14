(ns cleancoders.build.sign
  "GPG key handling and detached signatures.

   The passphrase always travels on a process's stdin, never in an argument
   vector: arguments are visible in a process listing and get echoed back in
   error messages, and this one unlocks the organization's release key.

   import-key! primes the gpg agent by signing a scratch file. That is
   load-bearing rather than decorative -- once the agent holds the passphrase,
   both sign-file! and `git tag -s` work with no further passphrase plumbing,
   which is what lets artifact signing and tag signing share one mechanism.

   The gpg home directory honors GNUPGHOME, the same variable gpg itself
   reads, rather than always writing to ~/.gnupg -- so CI, and specs, can
   point the whole flow at a scratch directory instead of an operator's real
   keyring."
  (:require [cleancoders.build.shell :as shell]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def ^:private key-var "GPG_PRIVATE_KEY")
(def ^:private passphrase-var "GPG_PASSPHRASE")
(def ^:private gnupg-home-var "GNUPGHOME")

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
  (some-> (->> (str/split-lines (str colon-out))
               (keep #(second (re-find #"^uid:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^<:]+)<" %)))
               first)
          str/trim
          not-empty))

(defn gnupg-home
  "Directory gpg treats as its home. Honors GNUPGHOME the same way gpg itself
   does, so CI and specs can point the whole flow at a scratch directory
   instead of the operator's real ~/.gnupg. Public, like getenv, so specs can
   redefine it directly for the whole import-key! context -- a structural
   guard so a future spec whose own env stub forgets GNUPGHOME still cannot
   reach a real keyring."
  []
  (let [configured (getenv gnupg-home-var)]
    (if (str/blank? (str configured))
      (io/file (System/getProperty "user.home") ".gnupg")
      (io/file configured))))

(defn- git-config!
  "Sets a git config value, failing loudly rather than letting import-key!
   report success with the identity silently unconfigured. shell/sh never
   throws, so a missing git or a rejected write would otherwise surface much
   later inside `git tag -a`, with a message that does not point back here --
   and GitHub runners have no identity of their own to fall back on."
  [k v]
  (let [{:keys [exit err]} (shell/sh "git" "config" k v)]
    (when-not (zero? exit)
      (fail! (str "could not configure git " k) err))))

(defn- agent-conf!
  "Enables loopback pinentry and lengthens the passphrase cache. The default
   600-second cache can expire between signing the artifacts and signing the
   tag, which would stall a release waiting for a prompt no one can answer."
  []
  (let [dir (gnupg-home)]
    (.mkdirs dir)
    (spit (io/file dir "gpg-agent.conf")
          "allow-loopback-pinentry\ndefault-cache-ttl 7200\nmax-cache-ttl 7200\n")
    (let [{:keys [exit err]} (shell/sh "gpg-connect-agent" "reloadagent" "/bye")]
      (when-not (zero? exit)
        (fail! "could not reload the gpg agent" err)))))

(defn- gpg-sign!
  "Detached-signs path with the named key, returning the sh result.

   --local-user is not optional: without it gpg signs with whatever its default
   key is. On a CI runner the keyring is fresh and the imported key is the only
   one in it, so the omission is invisible there -- but a break-glass release
   runs on a developer's machine, where gpg's default is that developer's own
   key (verified: gpg picks the older secret key, which is theirs) while
   `git tag -s` uses the user.signingkey import-key! configured. The release
   would then ship artifact signatures and a tag signature that disagree about
   who made it.

   The passphrase still goes to stdin, never into this vector: arguments are
   visible in a process listing and get echoed back in error messages."
  [key-fingerprint path]
  (shell/sh "gpg" "--detach-sign" "--armor" "--batch" "--yes" "--pinentry-mode" "loopback"
            "--local-user" key-fingerprint
            "--passphrase-fd" "0" path
            :in (str (getenv passphrase-var))))

(defn sign-file!
  "Writes <path>.asc and returns that path, signing with key-fingerprint rather
   than gpg's default key. Verifies the signature file exists and is non-empty:
   gpg exiting zero having written nothing would publish a valid-looking
   signature that verifies against nothing.

   Takes the fingerprint as a required argument rather than defaulting to gpg's
   choice -- a defaulted arity would silently reintroduce the exact bug this
   parameter exists to close."
  [key-fingerprint path]
  (let [{:keys [exit err]} (gpg-sign! key-fingerprint path)
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
      ;; sign-file! -- not gpg-sign! -- does the proof, so it enforces the same
      ;; non-empty-signature guarantee a real release signature gets.
      (let [scratch (doto (java.io.File/createTempFile "release-sign-check" ".txt") (.deleteOnExit))]
        (spit scratch "priming the gpg agent")
        (io/delete-file (io/file (str (.getAbsolutePath scratch) ".asc")) true)
        (try
          (sign-file! id (.getAbsolutePath scratch))
          (catch clojure.lang.ExceptionInfo e
            (fail! "the signing key could not sign a test file; check GPG_PASSPHRASE" (ex-message e)))
          (finally
            (io/delete-file (io/file (str (.getAbsolutePath scratch) ".asc")) true))))
      ;; A uid missing a name or an email would leave the git identity half
      ;; configured; git tag -a would then discover that much later with an
      ;; unrelated error, so fail here instead, while the cause is obvious.
      (let [email (uid-email out)
            uname (uid-name out)]
        (when (or (str/blank? (str email)) (str/blank? (str uname)))
          (fail! "the signing key's user id must include a name and an email address" nil))
        (git-config! "user.signingkey" id)
        (git-config! "user.email" email)
        (git-config! "user.name" uname))
      id)))
