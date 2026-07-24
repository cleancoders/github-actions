(ns c3kit.build.jar-spec
  (:require [c3kit.build.jar :as sut]
            [cemerick.pomegranate.aether :as aether]
            [clojure.tools.build.api :as b]
            [speclj.core :refer :all]))

(defn- cfg []
  (with-redefs [clojure.tools.build.api/create-basis (constantly {:paths ["src"]})]
    (sut/config {:group       "com.cleancoders.c3kit"
                 :lib-name    "bucket"
                 :version     "2.14.0"
                 :license-url "https://github.com/cleancoders/c3kit-bucket/blob/master/LICENSE"})))

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
                                aether/install (fn [_] (swap! calls conj :install))]
                    (sut/install! (cfg)))
                  (should= [:clean :pom :copy-dir :jar :install] @calls)))))

(run-specs)
