(ns c3kit.build.jar
  "The single-artifact build flow shared by apron, bucket, and scaffold. wire has
   two artifacts and supplies its own jar/publish thunks instead."
  (:require [cemerick.pomegranate.aether :as aether]
            [clojure.string :as str]
            [clojure.tools.build.api :as b]))

(defn config
  "Derives every path and coordinate a one-jar c3kit library needs."
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

(defn build! [{:keys [basis class-dir jar-file] :as cfg}]
  (clean! cfg)
  (pom! cfg)
  (println "building" jar-file)
  (b/copy-dir {:src-dirs   (:paths basis)
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file  jar-file}))

(defn install! [{:keys [deploy] :as cfg}]
  (build! cfg)
  (println "installing" (:coordinates deploy))
  (aether/install deploy))

(defn publish! [{:keys [deploy]}]
  (println "deploying" (:coordinates deploy))
  (aether/deploy deploy))
