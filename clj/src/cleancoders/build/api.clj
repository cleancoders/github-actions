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

(def ^:private default-version-file "VERSION")

(defn- validate!
  "Aborts naming every missing key. Configuration used to be code, where a typo
   was a compile error; as :exec-args data a misspelled key would otherwise
   sail through and build target/-2.14.0.jar."
  [args]
  (let [missing (filter #(str/blank? (str (get args %))) required-keys)]
    (when (seq missing)
      (release/abort! "missing or blank :build :exec-args keys:"
                      (str/join ", " missing)))))

(defn config
  "Derives the jar config from :exec-args, reading the version from
   :version-file (default VERSION) relative to the working directory."
  [{:keys [group lib-name license-url version-file] :as args}]
  (validate! args)
  ;; not-empty, not a bare or: "" is truthy in Clojure, so a blank :version-file
  ;; would otherwise survive as the slurp target and throw FileNotFoundException
  ;; instead of reading the default VERSION file.
  (jar-flow/config {:group       group
                    :lib-name    lib-name
                    :license-url license-url
                    :version     (str/trim (slurp (or (not-empty version-file) default-version-file)))}))

(defn clean [args] (jar-flow/clean! (config args)))
(defn pom [args] (jar-flow/pom! (config args)))
(defn jar [args] (jar-flow/build! (config args)))
(defn install [args] (jar-flow/install! (config args)))

(defn deploy
  "The release path. Refuses to run outside CI, verifies the named workflow is
   green for this commit, and tags only after a successful publish."
  [{:keys [repo ci-workflow] :as args}]
  (let [cfg (config args)]
    (release/deploy! {:repo        repo
                      :ci-workflow ci-workflow
                      :version     (:version cfg)
                      :jar!        #(jar-flow/build! cfg)
                      :publish!    #(jar-flow/publish! cfg)})))

(defn emergency-publish
  "Break glass. Skips the CI check; requires the break-glass variable to name
   the exact version being released."
  [{:keys [emergency-var] :as args}]
  (let [cfg (config args)]
    (release/emergency-deploy! {:version       (:version cfg)
                                :emergency-var emergency-var
                                :jar!          #(jar-flow/build! cfg)
                                :publish!      #(jar-flow/publish! cfg)})))
