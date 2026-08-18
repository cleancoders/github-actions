(ns cleancoders.build.jar-spec
  (:require [cleancoders.build.jar :as sut]
            [cleancoders.build.digest :as digest]
            [cleancoders.build.sbom :as sbom]
            [cleancoders.build.sign :as sign]
            [cleancoders.build.publish-verify :as pv]
            [cemerick.pomegranate.aether :as aether]
            [clojure.java.io :as io]
            [clojure.tools.build.api :as b]
            [speclj.core :refer :all]))

(defn- cfg
  "The config a consumer gets by default. Extra keys stand in for the opt-in
   flags, so a spec that wants signing or the SBOM asks for it the same way a
   consumer's :exec-args would."
  [& {:as flags}]
  (with-redefs [clojure.tools.build.api/create-basis (constantly {:paths ["src"]})]
    (sut/config (merge {:group       "com.cleancoders.c3kit"
                        :lib-name    "bucket"
                        :version     "2.14.0"
                        :license-url "https://github.com/cleancoders/c3kit-bucket/blob/master/LICENSE"}
                       flags))))

(defn- signing-cfg [] (cfg :sign true))
(defn- sbom-cfg [] (cfg :sbom true))
(defn- full-cfg [] (cfg :sign true :sbom true))

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
                         (get-in (cfg) [:deploy :repository "clojars" :url])))

            (it "names the sbom after lib-name and version, with the cyclonedx classifier"
                (should= "target/bucket-2.14.0-cyclonedx.json" (:sbom-file (cfg))))

            ;; One override, both directions. Clojars uploads to clojars.org/repo
            ;; and serves from repo.clojars.org, so a rehearsal that redirected
            ;; only the upload would publish to a throwaway repository and then
            ;; verify against the real Clojars, where the artifact does not
            ;; exist -- reporting "not readable" for a rehearsal that worked.
            ;; Asserts the url and the repo id only -- never the whole
            ;; repository map. It carries :username/:password read from the
            ;; environment, and a failed `should=` prints both sides, so
            ;; comparing the map would dump a real Clojars deploy token into
            ;; the test output of anyone who has one exported.
            (it "sends uploads to an overridden repository"
                (let [repository (get-in (cfg :repo-url "file:///tmp/staging") [:deploy :repository])]
                  (should= ["staging"] (keys repository))
                  (should= "file:///tmp/staging" (get-in repository ["staging" :url]))))

            (it "verifies against the same overridden repository it uploaded to"
                (let [staged (cfg :repo-url "file:///tmp/staging")]
                  (should= "file:///tmp/staging/com/cleancoders/c3kit/bucket/2.14.0/bucket-2.14.0.jar"
                           (:url (first (with-redefs [digest/sha256 (constantly "1f3a")]
                                          (sut/artifacts staged)))))))

            (it "targets clojars in both directions when nothing is overridden"
                (should= "https://clojars.org/repo"
                         (get-in (cfg) [:deploy :repository "clojars" :url]))
                (should-contain "repo.clojars.org"
                                (:url (first (with-redefs [digest/sha256 (constantly "1f3a")]
                                               (sut/artifacts (cfg))))))))

          (context "install!"
            (it "builds the jar before installing it"
                (let [calls (atom [])]
                  (with-redefs [b/delete       (fn [_] (swap! calls conj :clean))
                                b/write-pom    (fn [_] (swap! calls conj :pom))
                                b/copy-dir     (fn [_] (swap! calls conj :copy-dir))
                                b/jar          (fn [_] (swap! calls conj :jar))
                                sut/normalize! (fn [_] (swap! calls conj :normalize))
                                sbom/write!    (fn [_] (swap! calls conj :sbom))
                                digest/sha256  (constantly "1f3a")
                                aether/install (fn [_] (swap! calls conj :install))]
                    (sut/install! (cfg)))
                  (should= [:clean :pom :copy-dir :jar :normalize :install] @calls)))

            (it "writes the sbom before installing when the consumer opted in"
                (let [calls (atom [])]
                  (with-redefs [b/delete       (fn [_] (swap! calls conj :clean))
                                b/write-pom    (fn [_] (swap! calls conj :pom))
                                b/copy-dir     (fn [_] (swap! calls conj :copy-dir))
                                b/jar          (fn [_] (swap! calls conj :jar))
                                sut/normalize! (fn [_] (swap! calls conj :normalize))
                                sbom/write!    (fn [_] (swap! calls conj :sbom))
                                digest/sha256  (constantly "1f3a")
                                aether/install (fn [_] (swap! calls conj :install))]
                    (sut/install! (sbom-cfg)))
                  (should= [:clean :pom :copy-dir :jar :normalize :sbom :install] @calls))))

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
                    (should-contain "Created-By: org.clojure/tools.build" content)))))

          (context "build!"
            (it "writes no sbom unless the consumer opted in"
                ;; Generating one hashes every jar in the resolved dependency
                ;; closure. A consumer who never asked for an SBOM should not
                ;; pay for that on every local `clj -T:build jar`.
                (let [calls (atom [])]
                  (with-redefs [b/delete       (constantly nil)
                                b/write-pom    (constantly nil)
                                b/copy-dir     (constantly nil)
                                b/jar          (constantly nil)
                                sut/normalize! (constantly nil)
                                digest/sha256  (constantly "1f3a")
                                sbom/write!    (fn [_] (swap! calls conj :sbom))]
                    (sut/build! (cfg)))
                  (should= [] @calls)))

            (it "writes the sbom for the normalized jar's digest"
                (let [captured (atom nil)]
                  (with-redefs [b/delete       (constantly nil)
                                b/write-pom    (constantly nil)
                                b/copy-dir     (constantly nil)
                                b/jar          (constantly nil)
                                sut/normalize! (constantly nil)
                                digest/sha256  (constantly "1f3a")
                                sbom/write!    (fn [c] (reset! captured c) (:sbom-file c))]
                    (sut/build! (sbom-cfg)))
                  (should= "1f3a" (:jar-digest @captured))
                  (should= "target/bucket-2.14.0-cyclonedx.json" (:sbom-file @captured))
                  (should= 'com.cleancoders.c3kit/bucket (:lib @captured)))))

          (context "sign-all!"
            (it "signs only the files that were built, skipping an sbom nobody asked for"
                ;; gpg would fail on a path that does not exist, and the SBOM
                ;; only exists when :sbom is on, so the signable list has to
                ;; follow the flags rather than the config's derived paths.
                (let [signed (atom [])]
                  (with-redefs [sign/import-key! (constantly "FPR")
                                sign/sign-file!  (fn [_ p] (swap! signed conj p) (str p ".asc"))]
                    (sut/sign-all! (signing-cfg)))
                  (should= ["target/bucket-2.14.0.jar"
                            "target/classes/META-INF/maven/com.cleancoders.c3kit/bucket/pom.xml"]
                           @signed)))

            (it "signs the jar, the pom, and the sbom"
                (let [signed (atom [])]
                  (with-redefs [sign/import-key! (constantly "FPR")
                                sign/sign-file!  (fn [_ p] (swap! signed conj p) (str p ".asc"))]
                    (sut/sign-all! (full-cfg)))
                  (should= ["target/bucket-2.14.0.jar"
                            "target/classes/META-INF/maven/com.cleancoders.c3kit/bucket/pom.xml"
                            "target/bucket-2.14.0-cyclonedx.json"]
                           @signed)))

            (it "imports the key once, before signing anything"
                (let [calls (atom [])]
                  (with-redefs [sign/import-key! (fn [] (swap! calls conj :import) "FPR")
                                sign/sign-file!  (fn [_ p] (swap! calls conj :sign) (str p ".asc"))]
                    (sut/sign-all! (full-cfg)))
                  (should= [:import :sign :sign :sign] @calls)))

            ;; import-key! returns the imported key's fingerprint, and it used
            ;; to be discarded -- so the artifacts were signed by gpg's default
            ;; key while the tag was signed with user.signingkey. Identical in
            ;; CI, where the imported key is the only one; not identical on a
            ;; developer's machine during a break-glass release.
            (it "signs every file with the fingerprint import-key! returned, not gpg's default key"
                (let [signed (atom [])]
                  (with-redefs [sign/import-key! (constantly "1111222233334444555566667777888899990000")
                                sign/sign-file!  (fn [fpr p] (swap! signed conj fpr) (str p ".asc"))]
                    (sut/sign-all! (full-cfg)))
                  (should= ["1111222233334444555566667777888899990000"
                            "1111222233334444555566667777888899990000"
                            "1111222233334444555566667777888899990000"]
                           @signed))))

          (context "artifact-map"
            (with amap (sut/artifact-map (full-cfg)))

            ;; This map is why publish! could not be reused by a consumer that
            ;; had not opted into signing: naming a .asc path that no one wrote
            ;; makes aether/deploy fail on a missing file. It now names only
            ;; what the flags say was produced.
            (it "uploads the jar and the pom alone by default"
                (let [plain (sut/artifact-map (cfg))]
                  (should= 2 (count plain))
                  (should= "target/bucket-2.14.0.jar" (get plain [:extension "jar"]))
                  (should-contain "pom.xml" (get plain [:extension "pom"]))))

            (it "adds a signature for each file when signing is on, and nothing else"
                (let [signed (sut/artifact-map (signing-cfg))]
                  (should= 4 (count signed))
                  (should= "target/bucket-2.14.0.jar.asc" (get signed [:extension "jar.asc"]))
                  (should-contain "pom.xml.asc" (get signed [:extension "pom.asc"]))
                  (should-be-nil (get signed [:classifier "cyclonedx" :extension "json"]))))

            (it "adds the sbom when it is on, unsigned when signing is off"
                (let [with-sbom (sut/artifact-map (sbom-cfg))]
                  (should= 3 (count with-sbom))
                  (should= "target/bucket-2.14.0-cyclonedx.json"
                           (get with-sbom [:classifier "cyclonedx" :extension "json"]))
                  (should-be-nil (get with-sbom [:classifier "cyclonedx" :extension "json.asc"]))))

            (it "uploads the jar and its signature"
                (should= "target/bucket-2.14.0.jar" (get @amap [:extension "jar"]))
                (should= "target/bucket-2.14.0.jar.asc" (get @amap [:extension "jar.asc"])))

            (it "uploads the pom and its signature"
                (should-contain "pom.xml" (get @amap [:extension "pom"]))
                (should-contain "pom.xml.asc" (get @amap [:extension "pom.asc"])))

            (it "uploads the sbom under the cyclonedx classifier and its signature"
                (should= "target/bucket-2.14.0-cyclonedx.json"
                         (get @amap [:classifier "cyclonedx" :extension "json"]))
                (should= "target/bucket-2.14.0-cyclonedx.json.asc"
                         (get @amap [:classifier "cyclonedx" :extension "json.asc"])))

            (it "uploads exactly those six files with both flags on"
                (should= 6 (count @amap))))

          (context "artifacts"
            (with entries (with-redefs [digest/sha256 (fn [p] (str "sha-of:" p))]
                            (sut/artifacts (sbom-cfg))))

            (it "records no sbom digest when no sbom was written"
                ;; digest/sha256 on a missing file would throw, and this runs
                ;; after publish! where a throw means the artifact is already
                ;; live with nothing recorded.
                (let [plain (with-redefs [digest/sha256 (fn [p] (str "sha-of:" p))]
                              (sut/artifacts (cfg)))]
                  (should= ["bucket-2.14.0.jar" "bucket-2.14.0.pom"] (map :name plain))))

            (it "records a digest for the jar, the pom, and the sbom"
                (should= ["bucket-2.14.0.jar" "bucket-2.14.0.pom" "bucket-2.14.0-cyclonedx.json"]
                         (map :name @entries))
                (should= "sha-of:target/bucket-2.14.0.jar" (:digest (first @entries))))

            (it "gives only the jar a verification url, which is what Clojars is asked for"
                (should= (pv/artifact-url {:lib 'com.cleancoders.c3kit/bucket :version "2.14.0"})
                         (:url (first @entries)))
                (should-be-nil (:url (second @entries)))
                (should-be-nil (:url (last @entries)))))

          (context "publish!"
            (it "deploys with the signed artifact map"
                (let [captured (atom nil)]
                  (with-redefs [aether/deploy (fn [opts] (reset! captured opts))]
                    (sut/publish! (full-cfg)))
                  (should= (sut/artifact-map (full-cfg)) (:artifact-map @captured))
                  (should= ['com.cleancoders.c3kit/bucket "2.14.0"] (:coordinates @captured))))))

(run-specs)
