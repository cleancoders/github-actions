(ns cleancoders.build.publish-verify-spec
  (:require [cleancoders.build.digest :as digest]
            [cleancoders.build.publish-verify :as sut]
            [cleancoders.build.shell :as shell]
            [speclj.core :refer :all]))

(def commands (atom []))
(def waits (atom []))

(defn- stub-sh [results]
  (let [remaining (atom results)]
    (fn [& args]
      (swap! commands conj (vec args))
      (let [result (or (first @remaining) {:exit 0 :out "" :err ""})]
        (swap! remaining rest)
        result))))

(defn- verify [{:keys [results digests]}]
  (reset! commands [])
  (reset! waits [])
  (let [answers (atom digests)]
    (with-redefs [shell/sh      (stub-sh results)
                  digest/sha256 (fn [_] (let [d (first @answers)] (swap! answers rest) d))]
      (sut/verify! {:url      "https://repo.clojars.org/x/bucket/2.14.0/bucket-2.14.0.jar"
                    :digest   "aaaa"
                    :attempts 3
                    :wait-ms  5
                    :sleep!   #(swap! waits conj %)}))))

(describe "publish-verify"

          (context "artifact-url"
            (it "builds the maven layout path Clojars serves"
                (should= "https://repo.clojars.org/com/cleancoders/c3kit/bucket/2.14.0/bucket-2.14.0.jar"
                         (sut/artifact-url {:lib 'com.cleancoders.c3kit/bucket :version "2.14.0"})))

            (it "handles a single-segment coordinate"
                (should= "https://repo.clojars.org/bucket/bucket/1.0.0/bucket-1.0.0.jar"
                         (sut/artifact-url {:lib 'bucket :version "1.0.0"}))))

          (context "verdict"
            (it "passes when the digests match"
                (should-be-nil (sut/verdict "aaaa" "aaaa")))

            (it "reports an unreadable artifact"
                (should-contain "not readable" (sut/verdict "" "aaaa"))
                (should-contain "not readable" (sut/verdict nil "aaaa")))

            (it "reports a mismatch naming both digests"
                (let [reason (sut/verdict "bbbb" "aaaa")]
                  (should-contain "mismatch" reason)
                  (should-contain "bbbb" reason)
                  (should-contain "aaaa" reason))))

          (context "verify!"
            (it "passes on the first attempt when Clojars already has the artifact"
                (should-be-nil (verify {:results [{:exit 0 :out "" :err ""}]
                                        :digests ["aaaa"]}))
                (should= [] @waits))

            (it "retries a fetch failure and passes once the artifact appears"
                (should-be-nil (verify {:results [{:exit 22 :out "" :err "404"}
                                                  {:exit 0 :out "" :err ""}]
                                        :digests ["aaaa"]}))
                (should= 1 (count @waits)))

            (it "backs off between attempts rather than hammering the CDN"
                (verify {:results [{:exit 22} {:exit 22} {:exit 22}] :digests []})
                (should= 2 (count @waits))
                (should< (first @waits) (second @waits)))

            (it "gives up after the attempt cap and reports it"
                (should-contain "not readable"
                                (verify {:results [{:exit 22} {:exit 22} {:exit 22}] :digests []})))

            (it "reports a mismatch immediately and does not retry into a pass"
                ;; A mismatch means registry-side substitution or the wrong
                ;; artifact. Retrying could turn a real finding into a pass.
                (should-contain "mismatch"
                                (verify {:results [{:exit 0 :out "" :err ""} {:exit 0 :out "" :err ""}]
                                         :digests ["bbbb" "aaaa"]}))
                (should= [] @waits))

            (it "fetches to a file with curl rather than parsing bytes out of stdout"
                (verify {:results [{:exit 0 :out "" :err ""}] :digests ["aaaa"]})
                (let [args (first @commands)]
                  (should= "curl" (first args))
                  (should-contain "-o" args)
                  (should-contain "https://repo.clojars.org/x/bucket/2.14.0/bucket-2.14.0.jar" args)))))

(run-specs)
