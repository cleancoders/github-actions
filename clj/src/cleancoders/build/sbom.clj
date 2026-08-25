(ns cleancoders.build.sbom
  "CycloneDX SBOM built from the tools.build basis. The basis is the right
   source: it holds the fully resolved transitive closure with exact versions,
   including the :git/sha coordinates a jar scanner cannot see because they
   never appear in the pom.

   The document is deterministic -- no timestamp, and a serial number derived
   from the jar digest -- so the same source produces the same SBOM. Release
   time is recorded by the tag and the attestation, which is where it belongs."
  (:require [cleancoders.build.digest :as digest]
            [clojure.data.json :as json]
            [clojure.string :as str]))

(defn- maven-purl
  "pkg:maven purl for a library symbol. A single-segment symbol has no
   namespace, and Maven has no such thing as a groupless artifact, so the name
   serves as both -- the same convention Clojure tooling already applies."
  [lib version]
  (str "pkg:maven/" (or (namespace lib) (name lib)) "/" (name lib) "@" version))

(defn- github-purl
  "pkg:github purl from a git url and sha. Strips the scheme, any credentials,
   the host, and the .git suffix, leaving owner/repo."
  [url sha]
  (let [path (-> (str url)
                 (str/replace #"^\w+://[^/]+/" "")
                 (str/replace #"^git@[^:]+:" "")
                 (str/replace #"\.git$" ""))]
    (str "pkg:github/" path "@" sha)))

(defn- jar-hashes
  "SHA-256 of each resolved jar on a dependency's classpath. This is the
   cryptographic floor deps.edn does not provide: versions are pinned, digests
   are not, so recording them here makes a later upstream substitution
   detectable after the fact. Non-jar paths are source trees from git deps,
   whose :git/sha already identifies the bytes."
  [paths]
  (let [jars (filter #(str/ends-with? (str %) ".jar") paths)]
    (when (seq jars)
      (mapv (fn [jar] {:alg "SHA-256" :content (digest/sha256 jar)}) jars))))

(defn- component
  "One CycloneDX component for one entry of the basis :libs map."
  [[lib coord]]
  (let [sha     (:git/sha coord)
        version (or (:mvn/version coord) sha)
        purl    (if sha
                  (github-purl (:git/url coord) sha)
                  (maven-purl lib version))
        hashes  (when-not sha (jar-hashes (:paths coord)))]
    (cond-> {:type    "library"
             :group   (or (namespace lib) (name lib))
             :name    (name lib)
             :version version
             :purl    purl
             :bom-ref purl}
      hashes (assoc :hashes hashes))))

(defn- serial-number
  "urn:uuid derived from the jar digest, so two builds of the same source get
   the same serial number and two different releases do not. Not an RFC 4122
   version-4 UUID -- it is deliberately a function of the artifact -- but it
   matches the shape CycloneDX validates."
  [jar-digest]
  (let [h (subs (str jar-digest) 0 32)]
    (str "urn:uuid:" (subs h 0 8) "-" (subs h 8 12) "-" (subs h 12 16) "-"
         (subs h 16 20) "-" (subs h 20 32))))

(defn cyclonedx
  "The CycloneDX 1.6 document for one released artifact."
  [{:keys [lib version basis jar-digest]}]
  (let [purl (maven-purl lib version)]
    {:bomFormat    "CycloneDX"
     :specVersion  "1.6"
     :version      1
     :serialNumber (serial-number jar-digest)
     :metadata     {:tools     [{:name "cleancoders.build.sbom"}]
                    :component {:type    "library"
                                :group   (or (namespace lib) (name lib))
                                :name    (name lib)
                                :version version
                                :purl    purl
                                :bom-ref purl
                                :hashes  [{:alg "SHA-256" :content jar-digest}]}}
     :components   (vec (sort-by :purl (map component (:libs basis))))}))

(defn write!
  "Writes the SBOM to :sbom-file and returns that path."
  [{:keys [sbom-file] :as cfg}]
  (println "writing" sbom-file)
  (spit sbom-file (json/write-str (cyclonedx cfg)))
  sbom-file)
