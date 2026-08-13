(ns cleancoders.build.jar-spec
  (:require [cleancoders.build.jar :as sut]
            [cleancoders.build.digest :as digest]
            [cemerick.pomegranate.aether :as aether]
            [clojure.java.io :as io]
            [clojure.tools.build.api :as b]
            [speclj.core :refer :all]))

(defn- cfg []
  (with-redefs [clojure.tools.build.api/create-basis (constantly {:paths ["src"]})]
    (sut/config {:group       "com.cleancoders.c3kit"
                 :lib-name    "bucket"
                 :version     "2.14.0"
                 :license-url "https://github.com/cleancoders/c3kit-bucket/blob/master/LICENSE"})))

(defn- write-jar!
  "Writes a jar with the given [name content] entries, timestamped now."
  [path entries]
  (with-open [out (java.util.zip.ZipOutputStream. (io/output-stream path))]
    (doseq [[name content] entries]
      (.putNextEntry out (doto (java.util.zip.ZipEntry. ^String name)
                           (.setTime (System/currentTimeMillis))))
      (.write out (.getBytes (str content) "UTF-8"))
      (.closeEntry out))))

(defn- entry-names [path]
  (with-open [zip (java.util.zip.ZipFile. (io/file path))]
    (mapv #(.getName %) (enumeration-seq (.entries zip)))))

(defn- entry-content [path entry-name]
  (with-open [zip (java.util.zip.ZipFile. (io/file path))]
    (slurp (.getInputStream zip (.getEntry zip entry-name)))))

(defn- temp-jar []
  (.getAbsolutePath (doto (java.io.File/createTempFile "jar-spec" ".jar") (.deleteOnExit))))

(defn- write-jar-bytes!
  "Like write-jar!, but writes raw byte-array content with no string coercion --
   needed to inject a byte that isn't valid UTF-8, which write-jar!'s (str content)
   can't produce."
  [path entries]
  (with-open [out (java.util.zip.ZipOutputStream. (io/output-stream path))]
    (doseq [[name ^bytes content] entries]
      (.putNextEntry out (doto (java.util.zip.ZipEntry. ^String name)
                           (.setTime (System/currentTimeMillis))))
      (.write out content)
      (.closeEntry out))))

(defn- entry-bytes [path entry-name]
  (with-open [zip (java.util.zip.ZipFile. (io/file path))]
    (let [out (java.io.ByteArrayOutputStream.)]
      (io/copy (.getInputStream zip (.getEntry zip entry-name)) out)
      (.toByteArray out))))

(describe "jar"

          (context "config"
            (it "builds the maven coordinate from group and lib-name"
                (should= 'com.cleancoders.c3kit/bucket (:lib (cfg))))

            (it "names the jar after lib-name and version"
                (should= "target/bucket-2.14.0.jar" (:jar-file (cfg))))

            (it "points the pom-file at the generated maven path"
                (should= "target/classes/META-INF/maven/com.cleancoders.c3kit/bucket/pom.xml"
                         (get-in (cfg) [:deploy :pom-file])))

            (it "carries the coordinate into the deploy config"
                (should= ['com.cleancoders.c3kit/bucket "2.14.0"] (get-in (cfg) [:deploy :coordinates])))

            (it "embeds the license url in the pom data"
                (should-contain "c3kit-bucket" (pr-str (:pom-data (cfg)))))

            (it "targets clojars"
                (should= "https://clojars.org/repo"
                         (get-in (cfg) [:deploy :repository "clojars" :url]))))

          (context "install!"
            (it "builds the jar before installing it"
                (let [calls (atom [])]
                  (with-redefs [b/delete       (fn [_] (swap! calls conj :clean))
                                b/write-pom    (fn [_] (swap! calls conj :pom))
                                b/copy-dir     (fn [_] (swap! calls conj :copy-dir))
                                b/jar          (fn [_] (swap! calls conj :jar))
                                sut/normalize! (fn [_] (swap! calls conj :normalize))
                                aether/install (fn [_] (swap! calls conj :install))]
                    (sut/install! (cfg)))
                  (should= [:clean :pom :copy-dir :jar :normalize :install] @calls))))

          (context "normalize!"
            (it "produces identical bytes for two jars whose entry timestamps differ"
                (let [entries [["b.txt" "bee"] ["a.txt" "ay"] ["META-INF/MANIFEST.MF" "Manifest-Version: 1.0"]]
                      first'  (temp-jar)
                      second' (temp-jar)]
                  (write-jar! first' entries)
                  (Thread/sleep 1100)                       ; DOS timestamps have 2-second resolution
                  (write-jar! second' entries)
                  (sut/normalize! first')
                  (sut/normalize! second')
                  (should= (digest/sha256 first') (digest/sha256 second'))))

            (it "produces identical bytes regardless of the order entries were written in"
                (let [forward (temp-jar)
                      reverse' (temp-jar)]
                  (write-jar! forward [["a.txt" "ay"] ["b.txt" "bee"]])
                  (write-jar! reverse' [["b.txt" "bee"] ["a.txt" "ay"]])
                  (sut/normalize! forward)
                  (sut/normalize! reverse')
                  (should= (digest/sha256 forward) (digest/sha256 reverse'))))

            (it "writes the manifest first, then the remaining entries in name order"
                (let [path (temp-jar)]
                  (write-jar! path [["z.txt" "zed"] ["a.txt" "ay"] ["META-INF/MANIFEST.MF" "Manifest-Version: 1.0"]])
                  (sut/normalize! path)
                  (should= ["META-INF/MANIFEST.MF" "a.txt" "z.txt"] (entry-names path))))

            (it "preserves every entry's content"
                (let [path (temp-jar)]
                  (write-jar! path [["a.txt" "ay"] ["nested/b.txt" "bee"]])
                  (sut/normalize! path)
                  (should= "ay" (entry-content path "a.txt"))
                  (should= "bee" (entry-content path "nested/b.txt"))))

            (it "strips the comment line Properties.store writes, which carries a timestamp"
                (let [path (temp-jar)]
                  (write-jar! path [["META-INF/maven/g/a/pom.properties"
                                     "#Wed Aug 12 09:00:00 CDT 2026\nversion=2.14.0\n"]])
                  (sut/normalize! path)
                  (let [content (entry-content path "META-INF/maven/g/a/pom.properties")]
                    (should-not-contain "#Wed Aug" content)
                    (should-contain "version=2.14.0" content))))

            (it "returns the path it normalized"
                (let [path (temp-jar)]
                  (write-jar! path [["a.txt" "ay"]])
                  (should= path (sut/normalize! path))))

            (it "produces identical bytes regardless of the JVM's default time zone"
                (let [entries  [["a.txt" "ay"]]
                      original (java.util.TimeZone/getDefault)]
                  (try
                    (java.util.TimeZone/setDefault (java.util.TimeZone/getTimeZone "UTC"))
                    (let [utc (temp-jar)]
                      (write-jar! utc entries)
                      (sut/normalize! utc)
                      (java.util.TimeZone/setDefault (java.util.TimeZone/getTimeZone "Asia/Tokyo"))
                      (let [tokyo (temp-jar)]
                        (write-jar! tokyo entries)
                        (sut/normalize! tokyo)
                        (should= (digest/sha256 utc) (digest/sha256 tokyo))))
                    (finally
                      (java.util.TimeZone/setDefault original)))))

            (it "preserves a non-ASCII byte in a .properties entry without corrupting it"
                (let [raw  (.getBytes "greeting=café\n" "ISO-8859-1")
                      path (temp-jar)]
                  (write-jar-bytes! path [["META-INF/maven/g/a/pom.properties" raw]])
                  (sut/normalize! path)
                  (should= (seq raw) (seq (entry-bytes path "META-INF/maven/g/a/pom.properties")))))

            (it "strips the Build-Jdk-Spec manifest attribute but leaves the rest alone"
                (let [manifest (str "Manifest-Version: 1.0\n"
                                    "Created-By: org.clojure/tools.build\n"
                                    "Build-Jdk-Spec: 25\n")
                      path     (temp-jar)]
                  (write-jar! path [["META-INF/MANIFEST.MF" manifest]])
                  (sut/normalize! path)
                  (let [content (entry-content path "META-INF/MANIFEST.MF")]
                    (should-not-contain "Build-Jdk-Spec" content)
                    (should-contain "Manifest-Version: 1.0" content)
                    (should-contain "Created-By: org.clojure/tools.build" content))))))

(run-specs)
