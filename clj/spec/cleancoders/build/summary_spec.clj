(ns cleancoders.build.summary-spec
  (:require [cleancoders.build.summary :as sut]
            [speclj.core :refer :all]))

(def artifacts
  [{:name "bucket-2.14.0.jar" :digest "1f3a"}
   {:name "bucket-2.14.0.pom" :digest "8c02"}
   {:name "bucket-2.14.0-cyclonedx.json" :digest "b71d"}])

(describe "summary"

          (context "render"
            (with text (sut/render {:version "2.14.0" :commit "9fe1c0a" :artifacts artifacts}))

            (it "names the version and the commit"
                (should-contain "2.14.0" @text)
                (should-contain "9fe1c0a" @text))

            (it "records every artifact's digest"
                (should-contain "bucket-2.14.0.jar" @text)
                (should-contain "1f3a" @text)
                (should-contain "bucket-2.14.0.pom" @text)
                (should-contain "8c02" @text)
                (should-contain "bucket-2.14.0-cyclonedx.json" @text)
                (should-contain "b71d" @text)))

          (context "emergency-banner"
            (with text (sut/emergency-banner {:version       "2.14.0"
                                              :commit        "9fe1c0a"
                                              :actor         "someone"
                                              :emergency-var "EMERGENCY_RELEASE"}))

            (it "says CI verification was skipped"
                (should-contain "CI verification" @text)
                (should-contain "skipped" @text))

            (it "names who released it, what, and from where"
                (should-contain "someone" @text)
                (should-contain "2.14.0" @text)
                (should-contain "9fe1c0a" @text)
                (should-contain "EMERGENCY_RELEASE" @text))

            (it "tolerates an unknown actor outside CI"
                (should-contain "unknown"
                                (sut/emergency-banner {:version "2.14.0" :commit "abc" :actor nil
                                                       :emergency-var "EMERGENCY_RELEASE"}))))

          (context "emit!"
            (it "appends to the job summary when GitHub provides one"
                (let [file (doto (java.io.File/createTempFile "summary-spec" ".md") (.deleteOnExit))]
                  (spit file "existing\n")
                  (with-redefs [sut/getenv {"GITHUB_STEP_SUMMARY" (.getAbsolutePath file)}]
                    (sut/emit! "added"))
                  (should-contain "existing" (slurp file))
                  (should-contain "added" (slurp file))))

            (it "prints to stdout when there is no job summary, so a local release still records"
                (with-redefs [sut/getenv (constantly nil)]
                  (should-contain "added" (with-out-str (sut/emit! "added")))))

            (it "prints to stdout rather than throwing when the summary file cannot be written"
                (with-redefs [sut/getenv {"GITHUB_STEP_SUMMARY" "/nope/nothing/here.md"}]
                  (should-contain "added" (with-out-str (sut/emit! "added")))))))

(run-specs)
