(ns cleancoders.build.api-spec
  (:require [cleancoders.build.jar :as jar-flow]
            [cleancoders.build.release :as release]
            [cleancoders.build.api :as sut]
            [clojure.string :as cstr]
            [clojure.tools.build.api :as b]
            [speclj.core :refer :all]))

(def base-args
  {:group       "com.cleancoders.c3kit"
   :lib-name    "bucket"
   :repo        "cleancoders/c3kit-bucket"
   :ci-workflow "test.yml"
   :license-url "https://github.com/cleancoders/c3kit-bucket/blob/master/LICENSE"})

(def aborted (atom nil))

(defn- capturing
  "Runs f with abort! captured rather than exiting. Returns the abort message,
   or nil when f completed without aborting."
  [f]
  (reset! aborted nil)
  (with-redefs [release/abort! (fn [& msg]
                                 (reset! aborted (cstr/join " " msg))
                                 (throw (ex-info "aborted" {:aborted true})))]
    (try (f) (catch clojure.lang.ExceptionInfo _ nil)))
  @aborted)

(describe "tool"

          (context "config"

            (it "reads the version from VERSION by default"
                (let [slurped (atom nil)]
                  (with-redefs [slurp            (fn [p] (reset! slurped p) "2.14.0\n")
                                b/create-basis   (constantly {:paths ["src"]})]
                    (should= "target/bucket-2.14.0.jar" (:jar-file (sut/config base-args))))
                  (should= "VERSION" @slurped)))

            (it "reads the version from :version-file when given"
                (let [slurped (atom nil)]
                  (with-redefs [slurp          (fn [p] (reset! slurped p) "3.0.1\n")
                                b/create-basis (constantly {:paths ["src"]})]
                    (should= "target/apron-3.0.1.jar"
                             (:jar-file (sut/config (assoc base-args
                                                           :lib-name     "apron"
                                                           :version-file "resources/c3kit/apron/VERSION")))))
                  (should= "resources/c3kit/apron/VERSION" @slurped)))

            (it "treats a blank :version-file as absent, falling back to VERSION"
                (let [slurped (atom nil)]
                  (with-redefs [slurp          (fn [p] (reset! slurped p) "2.14.0\n")
                                b/create-basis (constantly {:paths ["src"]})]
                    (should= "target/bucket-2.14.0.jar"
                             (:jar-file (sut/config (assoc base-args :version-file "")))))
                  (should= "VERSION" @slurped)))

            (it "builds the maven coordinate from group and lib-name"
                (with-redefs [slurp          (constantly "2.14.0\n")
                              b/create-basis (constantly {:paths ["src"]})]
                  (should= 'com.cleancoders.c3kit/bucket (:lib (sut/config base-args))))))

          (context "validation"

            (it "aborts naming a single missing key"
                (should-contain ":lib-name"
                                (capturing #(sut/config (dissoc base-args :lib-name)))))

            (it "aborts naming every missing key"
                (let [msg (capturing #(sut/config (dissoc base-args :repo :ci-workflow)))]
                  (should-contain ":repo" msg)
                  (should-contain ":ci-workflow" msg)))

            (it "treats a blank value as missing"
                (should-contain ":lib-name"
                                (capturing #(sut/config (assoc base-args :lib-name "   ")))))

            (it "does not abort when every required key is present"
                (should-be-nil
                 (capturing #(with-redefs [slurp          (constantly "2.14.0\n")
                                           b/create-basis (constantly {:paths ["src"]})]
                               (sut/config base-args)))))

            (it "aborts naming an unknown key"
                (should-contain ":version-fle"
                                (capturing #(sut/config (assoc base-args :version-fle "resources/VERSION")))))

            (it "aborts naming every unknown key"
                (let [msg (capturing #(sut/config (assoc base-args :version-fle "x" :emergency-vr "y")))]
                  (should-contain ":version-fle" msg)
                  (should-contain ":emergency-vr" msg)))

            (it "does not abort when the known optional keys are present"
                (should-be-nil
                 (capturing #(with-redefs [slurp          (constantly "2.14.0\n")
                                           b/create-basis (constantly {:paths ["src"]})]
                               (sut/config (assoc base-args
                                                  :version-file  "VERSION"
                                                  :emergency-var "MY_VAR")))))))

          (context "deploy"

            (it "forwards repo, ci-workflow, and version to deploy!"
                (let [captured (atom nil)]
                  (with-redefs [slurp            (constantly "2.14.0\n")
                                b/create-basis   (constantly {:paths ["src"]})
                                release/deploy!  (fn [m] (reset! captured m))]
                    (sut/deploy base-args))
                  (should= "cleancoders/c3kit-bucket" (:repo @captured))
                  (should= "test.yml" (:ci-workflow @captured))
                  (should= "2.14.0" (:version @captured))))

            (it "passes jar and publish as zero-arg thunks"
                (let [captured (atom nil)
                      calls    (atom [])]
                  (with-redefs [slurp             (constantly "2.14.0\n")
                                b/create-basis    (constantly {:paths ["src"]})
                                jar-flow/build!   (fn [_] (swap! calls conj :jar))
                                jar-flow/publish! (fn [_] (swap! calls conj :publish))
                                release/deploy!   (fn [m] (reset! captured m))]
                    (sut/deploy base-args)
                    ((:jar! @captured))
                    ((:publish! @captured)))
                  (should= [:jar :publish] @calls))))

          (context "emergency-publish"

            (it "forwards the version and the custom :emergency-var"
                (let [captured (atom nil)]
                  (with-redefs [slurp                     (constantly "2.14.0\n")
                                b/create-basis            (constantly {:paths ["src"]})
                                release/emergency-deploy! (fn [m] (reset! captured m))]
                    (sut/emergency-publish (assoc base-args :emergency-var "MY_VAR")))
                  (should= "2.14.0" (:version @captured))
                  (should= "MY_VAR" (:emergency-var @captured))))

            (it "does not forward a name when :emergency-var is absent, leaving the default to release"
                (let [captured (atom nil)]
                  (with-redefs [slurp                     (constantly "2.14.0\n")
                                b/create-basis            (constantly {:paths ["src"]})
                                release/emergency-deploy! (fn [m] (reset! captured m))]
                    (sut/emergency-publish base-args))
                  (should-be-nil (:emergency-var @captured)))))

          (context "delegation"

            (it "clean calls jar-flow/clean! and only that"
                (let [calls (atom [])]
                  (with-redefs [slurp             (constantly "2.14.0\n")
                                b/create-basis    (constantly {:paths ["src"]})
                                jar-flow/clean!   (fn [_] (swap! calls conj :clean))
                                jar-flow/pom!     (fn [_] (swap! calls conj :pom))
                                jar-flow/build!   (fn [_] (swap! calls conj :jar))
                                jar-flow/install! (fn [_] (swap! calls conj :install))]
                    (sut/clean base-args))
                  (should= [:clean] @calls)))

            (it "pom calls jar-flow/pom! and only that"
                (let [calls (atom [])]
                  (with-redefs [slurp             (constantly "2.14.0\n")
                                b/create-basis    (constantly {:paths ["src"]})
                                jar-flow/clean!   (fn [_] (swap! calls conj :clean))
                                jar-flow/pom!     (fn [_] (swap! calls conj :pom))
                                jar-flow/build!   (fn [_] (swap! calls conj :jar))
                                jar-flow/install! (fn [_] (swap! calls conj :install))]
                    (sut/pom base-args))
                  (should= [:pom] @calls)))

            (it "jar calls jar-flow/build! and only that"
                (let [calls (atom [])]
                  (with-redefs [slurp             (constantly "2.14.0\n")
                                b/create-basis    (constantly {:paths ["src"]})
                                jar-flow/clean!   (fn [_] (swap! calls conj :clean))
                                jar-flow/pom!     (fn [_] (swap! calls conj :pom))
                                jar-flow/build!   (fn [_] (swap! calls conj :jar))
                                jar-flow/install! (fn [_] (swap! calls conj :install))]
                    (sut/jar base-args))
                  (should= [:jar] @calls)))

            (it "install calls jar-flow/install! and only that"
                (let [calls (atom [])]
                  (with-redefs [slurp             (constantly "2.14.0\n")
                                b/create-basis    (constantly {:paths ["src"]})
                                jar-flow/clean!   (fn [_] (swap! calls conj :clean))
                                jar-flow/pom!     (fn [_] (swap! calls conj :pom))
                                jar-flow/build!   (fn [_] (swap! calls conj :jar))
                                jar-flow/install! (fn [_] (swap! calls conj :install))]
                    (sut/install base-args))
                  (should= [:install] @calls)))))

(run-specs)
