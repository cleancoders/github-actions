(ns cleancoders.build.jar
  "The single-artifact build flow. A consumer publishing more than one artifact
   supplies its own jar/publish thunks instead."
  (:require [cemerick.pomegranate.aether :as aether]
            [cleancoders.build.digest :as digest]
            [cleancoders.build.publish-verify :as publish-verify]
            [cleancoders.build.sbom :as sbom]
            [cleancoders.build.sign :as sign]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.build.api :as b]))

(defn config
  "Derives every path and coordinate a one-jar library needs.

   :sbom and :sign are opt-in and default off. Both were added after the first
   consumers onboarded, and turning either on costs those consumers something:
   an SBOM hashes the whole resolved dependency closure on every build, and
   signing requires GPG secrets on the release environment that a repo set up
   before signing existed does not have. Defaulting them on would mean a
   consumer bumping the pinned :git/sha for an unrelated fix inherits both."
  [{:keys [group lib-name version license-url sbom sign repo-url]}]
  (let [class-dir  "target/classes"
        jar-file   (format "target/%s-%s.jar" lib-name version)
        sbom-file  (format "target/%s-%s-cyclonedx.json" lib-name version)
        lib        (symbol group lib-name)
        ;; not-empty, not a bare or: "" is truthy in Clojure, so a blank
        ;; override would otherwise survive as the upload target.
        staging    (not-empty (str repo-url))
        deploy-url (or staging "https://clojars.org/repo")
        repo-id    (if staging "staging" "clojars")]
    {:lib       lib
     :version   version
     :sbom?     (boolean sbom)
     :sign?     (boolean sign)
     :repo-url  staging
     :class-dir class-dir
     :jar-file  jar-file
     :sbom-file sbom-file
     :basis     (b/create-basis {:project "deps.edn"})
     :pom-data  [[:licenses
                  [:license
                   [:name "MIT License"]
                   [:url license-url]]]]
     :deploy    {:coordinates       [lib version]
                 :jar-file          jar-file
                 :pom-file          (str/join "/" [class-dir "META-INF/maven" group lib-name "pom.xml"])
                 :repository        {repo-id {:url      deploy-url
                                              :username (System/getenv "CLOJARS_USERNAME")
                                              :password (System/getenv "CLOJARS_PASSWORD")}}
                 :transfer-listener :stdout}}))

(defn clean! [_cfg]
  (println "cleaning")
  (b/delete {:path "target"}))

(defn pom! [{:keys [basis class-dir lib version pom-data]}]
  (println "writing pom.xml")
  (b/write-pom {:basis     basis
                :class-dir class-dir
                :lib       lib
                :version   version
                :pom-data  pom-data}))

(def ^:private manifest-name "META-INF/MANIFEST.MF")

(def ^:private fixed-time
  ;; 1980-02-01T00:00:00 -- deliberately NOT 1980-01-01, the zip format's
  ;; earliest storable instant. That value packs to the exact DOS timestamp
  ;; the JDK reserves as its DOSTIME_BEFORE_1980 sentinel, so setTimeLocal
  ;; can't record it as a real time: ZipEntry keeps an mtime resolved through
  ;; ZoneId.systemDefault() instead, and ZipOutputStream serializes that as an
  ;; Info-ZIP 0x5455 "UT" extra field -- reintroducing, through the back door,
  ;; the exact zone dependence setTimeLocal exists to remove. Confirmed by
  ;; building the same source under UTC/America/Chicago/Asia/Tokyo: 1980-01-01
  ;; produced three different digests, 1980-02-01 produced one.
  (java.time.LocalDateTime/of 1980 2 1 0 0 0))

(defn- read-entries
  "Every entry of a jar as [name bytes]."
  [jar-file]
  (with-open [zip (java.util.zip.ZipFile. (io/file jar-file))]
    (->> (enumeration-seq (.entries zip))
         (mapv (fn [entry]
                 (let [out (java.io.ByteArrayOutputStream.)]
                   (with-open [in (.getInputStream zip entry)]
                     (io/copy in out))
                   [(.getName entry) (.toByteArray out)]))))))

(def ^:private latin1 java.nio.charset.StandardCharsets/ISO_8859_1)

(defn- drop-lines-with-prefix
  "Drops every line of a byte array that starts with the given ASCII prefix.
   Round-trips through ISO-8859-1, not UTF-8: ISO-8859-1 maps every byte 0-255
   to exactly one codepoint and back, so decoding and re-encoding through it
   can't corrupt content written in any other encoding -- unlike UTF-8, which
   turns any byte sequence that isn't valid UTF-8 (e.g. Latin-1 text, which is
   what java.util.Properties/store actually writes) into the replacement
   character. The prefixes matched here are plain ASCII, which every encoding
   in play agrees on."
  [^bytes bytes prefix]
  (let [lines (str/split (String. bytes ^java.nio.charset.Charset latin1) #"\n" -1)
        kept  (remove #(str/starts-with? % prefix) lines)]
    (.getBytes (str/join "\n" kept) ^java.nio.charset.Charset latin1)))

(defn- strip-properties-comments
  "Drops comment lines from a .properties entry. java.util.Properties/store
   writes the current date as a leading comment, which would change the jar's
   digest on every build. Comments carry no meaning to a properties reader."
  [name bytes]
  (if (str/ends-with? name ".properties")
    (drop-lines-with-prefix bytes "#")
    bytes))

(defn- strip-build-jdk-spec
  "Drops the Build-Jdk-Spec line tools.build writes into the manifest. Left in
   place, the digest would move with the JDK major version that built the
   jar, breaking the rebuild-and-compare check a consumer runs on their own
   JDK. Every other manifest attribute is untouched."
  [name bytes]
  (if (= name manifest-name)
    (drop-lines-with-prefix bytes "Build-Jdk-Spec:")
    bytes))

(defn- ordered
  "Manifest first, then every other entry by name. Sorting alone would be
   deterministic, but the jar spec expects the manifest first and some tools
   read it without scanning the central directory."
  [entries]
  (sort-by (fn [[name _]] [(if (= manifest-name name) 0 1) name]) entries))

(defn normalize!
  "Rewrites a jar deterministically: entries in a fixed order, every timestamp
   fixed, no preserved file metadata. Two builds of the same source then produce
   byte-identical jars, which is what makes a recorded digest meaningful --
   deploy rebuilds the artifact CI tested rather than promoting it."
  [jar-file]
  (println "normalizing" jar-file)
  (let [entries (ordered (read-entries jar-file))
        target  (java.io.File/createTempFile "normalized" ".jar")]
    (with-open [out (java.util.zip.ZipOutputStream. (io/output-stream target))]
      (doseq [[name bytes] entries]
        (.putNextEntry out (doto (java.util.zip.ZipEntry. ^String name)
                             (.setTimeLocal fixed-time)))
        (.write out ^bytes (->> bytes
                                (strip-properties-comments name)
                                (strip-build-jdk-spec name)))
        (.closeEntry out)))
    (java.nio.file.Files/move (.toPath target)
                              (.toPath (io/file jar-file))
                              (into-array java.nio.file.CopyOption
                                          [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    jar-file))

(defn- sbom!
  "Writes the SBOM for the jar that was just built. Takes the jar's digest so
   the SBOM names the exact bytes it describes."
  [{:keys [lib version basis jar-file sbom-file]}]
  (sbom/write! {:lib        lib
                :version    version
                :basis      basis
                :jar-digest (digest/sha256 jar-file)
                :sbom-file  sbom-file}))

(defn build! [{:keys [basis class-dir jar-file] :as cfg}]
  (clean! cfg)
  (pom! cfg)
  (println "building" jar-file)
  (b/copy-dir {:src-dirs   (:paths basis)
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file  jar-file})
  (normalize! jar-file)
  (when (:sbom? cfg)
    (sbom! cfg))
  jar-file)

(defn signable
  "The files a release signs, in upload order. The SBOM appears only when the
   consumer asked for one -- gpg fails on a path that does not exist, so this
   list follows the flags rather than the config's derived paths."
  [{:keys [jar-file sbom-file sbom? deploy]}]
  (cond-> [jar-file (:pom-file deploy)]
    sbom? (conj sbom-file)))

(defn sign-all!
  "Imports the release key once, then detach-signs every published file with
   it. Threads the fingerprint import-key! returns into each signature rather
   than discarding it: gpg would otherwise sign with whatever its default key
   is, which in a break-glass release from a developer's machine is that
   developer's own key -- while the tag is signed with the release key
   import-key! configured as user.signingkey."
  [cfg]
  (let [key-fingerprint (sign/import-key!)]
    (mapv #(sign/sign-file! key-fingerprint %) (signable cfg))))

(defn artifact-map
  "The pomegranate :artifact-map naming every file this build produced. Built
   here rather than in config because install! must not require signatures that
   only a release produces.

   Names only what the flags actually produced. aether/deploy fails on a path
   that does not exist, so an unconditional entry for the SBOM or a .asc would
   make publish! unusable to any consumer who had not opted into that feature --
   including one calling it from their own build script."
  [{:keys [jar-file sbom-file sbom? sign? deploy]}]
  (let [pom-file (:pom-file deploy)]
    (cond-> {[:extension "jar"] jar-file
             [:extension "pom"] pom-file}
      sign?           (assoc [:extension "jar.asc"] (str jar-file ".asc")
                             [:extension "pom.asc"] (str pom-file ".asc"))
      sbom?           (assoc [:classifier "cyclonedx" :extension "json"] sbom-file)
      (and sbom?
           sign?)     (assoc [:classifier "cyclonedx" :extension "json.asc"] (str sbom-file ".asc")))))

(defn artifacts
  "What this release shipped, for the digest record and post-publish
   verification. Only the jar carries a :url: it is the artifact whose bytes a
   consumer actually executes, and one fetch is enough to detect a
   registry-side substitution."
  [{:keys [lib version jar-file sbom-file sbom? repo-url deploy]}]
  (let [pom-file (:pom-file deploy)
        name-of  #(.getName (java.io.File. (str %)))]
    (cond-> [{:name (name-of jar-file) :path jar-file :digest (digest/sha256 jar-file)
              ;; The same :repo-url the upload went to. Redirecting only the
              ;; upload would publish to a staging repository and then verify
              ;; against Clojars, where the artifact does not exist.
              :url  (publish-verify/artifact-url {:lib lib :version version :repo-url repo-url})}
             {:name (format "%s-%s.pom" (name lib) version) :path pom-file :digest (digest/sha256 pom-file)}]
      ;; Only when one was written: digest/sha256 throws on a missing file, and
      ;; this runs after publish!, where a throw means the artifact is already
      ;; live with nothing verified and nothing recorded.
      sbom? (conj {:name (name-of sbom-file) :path sbom-file :digest (digest/sha256 sbom-file)}))))

(defn install! [{:keys [deploy] :as cfg}]
  (build! cfg)
  (println "installing" (:coordinates deploy))
  (aether/install deploy))

(defn publish! [{:keys [deploy] :as cfg}]
  (println "deploying" (:coordinates deploy))
  (aether/deploy (assoc deploy :artifact-map (artifact-map cfg))))
