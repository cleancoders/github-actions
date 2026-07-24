(ns c3kit.build.shell-spec
  (:require [c3kit.build.shell :as sut]
            [speclj.core :refer :all]))

(describe "sh"
          (it "runs a real command and reports success"
              (let [{:keys [exit out]} (sut/sh "echo" "hello")]
                (should= 0 exit)
                (should-contain "hello" out)))

          (it "reports a non-zero exit rather than throwing"
              (should= 1 (:exit (sut/sh "sh" "-c" "exit 1"))))

          (it "turns a missing binary into exit 127 instead of an exception"
              (let [{:keys [exit err]} (sut/sh "definitely-not-a-real-binary-xyz")]
                (should= 127 exit)
                (should-contain "definitely-not-a-real-binary-xyz" err))))

(run-specs)
