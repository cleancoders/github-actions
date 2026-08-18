(ns cleancoders.build.api
  "The entry point a consuming repo targets with :ns-default, so a
   single-artifact repo needs no build script of its own. Every fn takes the
   config map the :build alias supplies as :exec-args.

   A consumer whose build does not fit this shape writes its own build script
   and points :ns-default at that instead, consuming jar and release directly.
   That escape hatch is why this namespace stays small: the answer to an
   unsupported requirement is a local script, not another config key."
  (:require [cleancoders.build.jar :as jar-flow]
            [cleancoders.build.release :as release]
            [clojure.string :as str]))

(def ^:private required-keys [:group :lib-name :repo :ci-workflow :license-url])

(def ^:private optional-keys
  "Every key a consumer may omit. :sbom and :sign are the opt-in feature flags,
   and they are declared here rather than assumed so a misspelling still aborts
   -- otherwise :sbomb would read as \"SBOM off\" and look like it worked.

   :repo-url redirects both the upload and the post-publish verification at a
   different repository. It exists for staging rehearsals: a Clojars deploy is
   permanent, with no self-service deletion for any version, so rehearsing a
   release against the real thing leaves a public artifact behind forever."
  #{:version-file :emergency-var :sbom :sign :repo-url})

(def ^:private default-version-file "VERSION")

(defn- blank-workflow?
  "True when :ci-workflow gates on nothing: absent, blank, an empty vector, or
   a vector with a blank entry. A blank entry would be formatted into the API
   path, and a 404 there must not be mistakable for a passing gate."
  [ci-workflow]
  (if (coll? ci-workflow)
    (or (empty? ci-workflow) (some #(str/blank? (str %)) ci-workflow))
    (str/blank? (str ci-workflow))))

(defn- validate!
  "Aborts naming every missing key, and separately naming every key that is
   neither required nor optional. Configuration used to be code, where a typo
   was a compile error; as :exec-args data a misspelled key would otherwise
   sail through and build target/-2.14.0.jar, or (for a misspelled optional
   key) silently fall back to that key's default."
  [args]
  (let [missing (filter #(str/blank? (str (get args %))) (remove #{:ci-workflow} required-keys))
        missing (cond-> missing (blank-workflow? (:ci-workflow args)) (conj :ci-workflow))
        unknown (remove (into (set required-keys) optional-keys) (keys args))]
    (when (seq missing)
      (release/abort! "missing or blank :build :exec-args keys:"
                      (str/join ", " missing)))
    (when (seq unknown)
      (release/abort! "unknown :build :exec-args keys:"
                      (str/join ", " unknown)))))

(defn config
  "Derives the jar config from :exec-args, reading the version from
   :version-file (default VERSION) relative to the working directory."
  [{:keys [group lib-name license-url version-file sbom sign repo-url] :as args}]
  (validate! args)
  ;; not-empty, not a bare or: "" is truthy in Clojure, so a blank :version-file
  ;; would otherwise survive as the slurp target and throw FileNotFoundException
  ;; instead of reading the default VERSION file.
  (jar-flow/config {:group       group
                    :lib-name    lib-name
                    :license-url license-url
                    :sbom        sbom
                    :sign        sign
                    :repo-url    repo-url
                    :version     (str/trim (slurp (or (not-empty version-file) default-version-file)))}))

(defn clean [args] (jar-flow/clean! (config args)))
(defn pom [args] (jar-flow/pom! (config args)))
(defn jar [args] (jar-flow/build! (config args)))
(defn install [args] (jar-flow/install! (config args)))

(defn- sign-thunk
  "A :sign! thunk only when the consumer turned signing on. Omitted rather than
   supplied-and-inert: release/deploy! reads its absence as \"this consumer has
   not opted into signing\" and skips the signing-key gate too, which is what
   keeps a repo without GPG secrets releasing."
  [cfg]
  (when (:sign? cfg) #(jar-flow/sign-all! cfg)))

(defn deploy
  "The release path. Refuses to run outside CI, verifies every named workflow is
   green for this commit, verifies the published bytes, and tags only after all
   of that. Signs what it publishes when :sign is on, which also makes a
   configured signing key a precondition of the release."
  [{:keys [repo ci-workflow] :as args}]
  (let [cfg (config args)]
    (release/deploy! {:repo        repo
                      :ci-workflow ci-workflow
                      :version     (:version cfg)
                      :jar!        #(jar-flow/build! cfg)
                      :sign!       (sign-thunk cfg)
                      :publish!    #(jar-flow/publish! cfg)
                      ;; Always supplied, unlike :sign!: api derives the list
                      ;; itself, so post-publish verification and the digest
                      ;; record cost a consumer no configuration and no secrets.
                      :artifacts   #(jar-flow/artifacts cfg)})))

(defn emergency-publish
  "Break glass. Skips the CI check; requires the break-glass variable to name
   the exact version being released. Does not skip signing when :sign is on --
   an emergency is not a reason to ship bytes a consumer cannot verify."
  [{:keys [emergency-var] :as args}]
  (let [cfg (config args)]
    (release/emergency-deploy! {:version       (:version cfg)
                                :emergency-var emergency-var
                                :jar!          #(jar-flow/build! cfg)
                                :sign!         (sign-thunk cfg)
                                :publish!      #(jar-flow/publish! cfg)
                                :artifacts     #(jar-flow/artifacts cfg)})))
