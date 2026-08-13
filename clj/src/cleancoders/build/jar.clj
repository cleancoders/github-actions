(ns cleancoders.build.jar
  "The single-artifact build flow. A consumer publishing more than one artifact
   supplies its own jar/publish thunks instead."
  (:require [cemerick.pomegranate.aether :as aether]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.build.api :as b]))

(defn config
  "Derives every path and coordinate a one-jar library needs."
  [{:keys [group lib-name version license-url]}]
  (let [class-dir "target/classes"
        jar-file  (format "target/%s-%s.jar" lib-name version)
        lib       (symbol group lib-name)]
    {:lib       lib
     :version   version
     :class-dir class-dir
     :jar-file  jar-file
     :basis     (b/create-basis {:project "deps.edn"})
     :pom-data  [[:licenses
                  [:license
                   [:name "MIT License"]
                   [:url license-url]]]]
     :deploy    {:coordinates       [lib version]
                 :jar-file          jar-file
                 :pom-file          (str/join "/" [class-dir "META-INF/maven" group lib-name "pom.xml"])
                 :repository        {"clojars" {:url      "https://clojars.org/repo"
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
  ;; 1980-01-01T00:00:00, the earliest instant the zip format can store. Set
  ;; with setTimeLocal, not setTime: setTime converts epoch millis to the DOS
  ;; timestamp using the local zone, so the same source would produce different
  ;; bytes in UTC and in CST. setTimeLocal writes the field with no conversion.
  (java.time.LocalDateTime/of 1980 1 1 0 0 0))

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

(defn- strip-properties-comments
  "Drops comment lines from a .properties entry. java.util.Properties/store
   writes the current date as a leading comment, which would change the jar's
   digest on every build. Comments carry no meaning to a properties reader."
  [name bytes]
  (if (str/ends-with? name ".properties")
    (let [lines (str/split-lines (String. ^bytes bytes "UTF-8"))
          kept  (remove #(str/starts-with? % "#") lines)]
      (.getBytes (str (str/join "\n" kept) "\n") "UTF-8"))
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
        (.write out ^bytes (strip-properties-comments name bytes))
        (.closeEntry out)))
    (java.nio.file.Files/move (.toPath target)
                              (.toPath (io/file jar-file))
                              (into-array java.nio.file.CopyOption
                                          [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    jar-file))

(defn build! [{:keys [basis class-dir jar-file] :as cfg}]
  (clean! cfg)
  (pom! cfg)
  (println "building" jar-file)
  (b/copy-dir {:src-dirs   (:paths basis)
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file  jar-file})
  (normalize! jar-file))

(defn install! [{:keys [deploy] :as cfg}]
  (build! cfg)
  (println "installing" (:coordinates deploy))
  (aether/install deploy))

(defn publish! [{:keys [deploy]}]
  (println "deploying" (:coordinates deploy))
  (aether/deploy deploy))
