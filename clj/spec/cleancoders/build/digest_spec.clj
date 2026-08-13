(ns cleancoders.build.digest-spec
  (:require [cleancoders.build.digest :as sut]
            [clojure.java.io :as io]
            [speclj.core :refer :all]))

(defn- temp-file-with
  "Writes content to a fresh temp file and returns its path."
  [content]
  (let [file (java.io.File/createTempFile "digest-spec" ".txt")]
    (.deleteOnExit file)
    (spit file content)
    (.getAbsolutePath file)))

(describe "digest"

          (context "hex"
            (it "renders each byte as two lowercase characters"
                (should= "000f7f" (sut/hex (byte-array [0 15 127]))))

            (it "renders a byte-array's high bytes unsigned"
                (should= "ff" (sut/hex (byte-array [-1]))))

            (it "masks a seq of Longs, which would otherwise render -1 as sixteen f's"
                (should= "ff" (sut/hex [-1])))

            (it "is empty for no bytes"
                (should= "" (sut/hex (byte-array 0)))))

          (context "sha256"
            (it "matches the published digest of the empty input"
                (should= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                         (sut/sha256 (temp-file-with ""))))

            (it "matches the published digest of abc"
                (should= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                         (sut/sha256 (temp-file-with "abc"))))

            (it "matches an independently computed digest across two buffer-fuls"
                (let [content       (apply str (repeat 20000 "x"))
                      content-bytes (.getBytes content "UTF-8")
                      oracle        (.digest (java.security.MessageDigest/getInstance "SHA-256") content-bytes)]
                  (should= (sut/hex oracle) (sut/sha256 (temp-file-with content)))))

            (it "accepts a java.io.File as well as a path string"
                (let [path (temp-file-with "abc")]
                  (should= (sut/sha256 path) (sut/sha256 (io/file path)))))))

(run-specs)
