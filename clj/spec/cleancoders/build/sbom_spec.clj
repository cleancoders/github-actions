(ns cleancoders.build.sbom-spec
  (:require [cleancoders.build.digest :as digest]
            [cleancoders.build.sbom :as sut]
            [clojure.data.json :as json]
            [speclj.core :refer :all]))

(def jar-digest "1f3a0000000000000000000000000000000000000000000000000000000000ab")

(def basis
  {:libs {'org.clojure/clojure               {:mvn/version "1.12.0"
                                              :paths       ["/m2/org/clojure/clojure/1.12.0/clojure-1.12.0.jar"]}
          'com.cleancoders.c3kit/apron       {:mvn/version "2.0.5"
                                              :paths       ["/m2/apron-2.0.5.jar"]}
          'io.github.cleancoders/some-lib    {:git/url "https://github.com/cleancoders/some-lib.git"
                                              :git/sha "9fe1c0aabbccddeeff00112233445566778899aa"
                                              :paths   ["/gitlibs/some-lib/src"]}}})

(defn- bom []
  (with-redefs [digest/sha256 (fn [path] (str "sha-of:" path))]
    (sut/cyclonedx {:lib        'com.cleancoders.c3kit/bucket
                    :version    "2.14.0"
                    :basis      basis
                    :jar-digest jar-digest})))

(defn- component-named [name]
  (first (filter #(= name (:name %)) (:components (bom)))))

(describe "sbom"

          (context "document shape"
            (it "declares CycloneDX 1.6"
                (should= "CycloneDX" (:bomFormat (bom)))
                (should= "1.6" (:specVersion (bom))))

            (it "describes the released artifact as the metadata component"
                (should= "pkg:maven/com.cleancoders.c3kit/bucket@2.14.0"
                         (get-in (bom) [:metadata :component :purl])))

            (it "records the released jar's digest on the metadata component"
                (should= [{:alg "SHA-256" :content jar-digest}]
                         (get-in (bom) [:metadata :component :hashes])))

            (it "names the tool that produced it"
                (should-contain "cleancoders" (pr-str (get-in (bom) [:metadata :tools])))))

          (context "reproducibility"
            (it "omits the timestamp, which would differ on every build"
                (should-be-nil (get-in (bom) [:metadata :timestamp])))

            (it "derives a stable serial number from the jar digest"
                (should= (:serialNumber (bom)) (:serialNumber (bom))))

            (it "formats the serial number as a urn:uuid CycloneDX accepts"
                (should (re-matches #"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                                    (:serialNumber (bom)))))

            (it "gives a different release a different serial number"
                (let [other (with-redefs [digest/sha256 (constantly "x")]
                              (sut/cyclonedx {:lib        'com.cleancoders.c3kit/bucket
                                              :version    "2.14.1"
                                              :basis      basis
                                              :jar-digest (apply str (repeat 64 "c"))}))]
                  (should-not= (:serialNumber (bom)) (:serialNumber other))))

            (it "orders components deterministically"
                (should= (map :purl (:components (bom)))
                         (sort (map :purl (:components (bom)))))))

          (context "maven components"
            (it "includes every resolved dependency"
                (should= 3 (count (:components (bom)))))

            (it "builds a maven purl from the coordinate"
                (should= "pkg:maven/org.clojure/clojure@1.12.0" (:purl (component-named "clojure"))))

            (it "splits group and name out of the symbol"
                (should= "org.clojure" (:group (component-named "clojure")))
                (should= "1.12.0" (:version (component-named "clojure"))))

            (it "records the resolved jar's digest, which deps.edn does not pin"
                (should= [{:alg "SHA-256" :content "sha-of:/m2/org/clojure/clojure/1.12.0/clojure-1.12.0.jar"}]
                         (:hashes (component-named "clojure"))))

            (it "uses the purl as the bom-ref so references are stable"
                (should= (:purl (component-named "clojure")) (:bom-ref (component-named "clojure"))))

            (it "treats a single-segment coordinate as group and artifact alike"
                (let [one (sut/cyclonedx {:lib        'bucket
                                          :version    "1.0.0"
                                          :basis      {:libs {}}
                                          :jar-digest jar-digest})]
                  (should= "pkg:maven/bucket/bucket@1.0.0" (get-in one [:metadata :component :purl])))))

          (context "git components"
            (it "builds a github purl from the url and sha"
                (should= "pkg:github/cleancoders/some-lib@9fe1c0aabbccddeeff00112233445566778899aa"
                         (:purl (component-named "some-lib"))))

            (it "uses the sha as the version"
                (should= "9fe1c0aabbccddeeff00112233445566778899aa" (:version (component-named "some-lib"))))

            (it "omits hashes, because a git dep resolves to a source tree and the sha is the digest"
                (should-be-nil (:hashes (component-named "some-lib")))))

          (context "write!"
            (it "writes parseable JSON and returns the path"
                (let [path (.getAbsolutePath (java.io.File/createTempFile "sbom-spec" ".json"))
                      out  (with-redefs [digest/sha256 (constantly "deadbeef")]
                             (sut/write! {:lib        'com.cleancoders.c3kit/bucket
                                          :version    "2.14.0"
                                          :basis      basis
                                          :jar-digest jar-digest
                                          :sbom-file  path}))]
                  (should= path out)
                  (should= "CycloneDX" (get (json/read-str (slurp path)) "bomFormat"))))))

(run-specs)
