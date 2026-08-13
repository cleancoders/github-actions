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

            (it "renders high bytes unsigned rather than as a negative int"
                ;; A byte is signed in Java. Formatting -1 without masking yields
                ;; "ffffffff", which silently lengthens the digest and makes it
                ;; compare unequal to the same bytes hashed anywhere else.
                (should= "ff" (sut/hex (byte-array [-1]))))

            (it "is empty for no bytes"
                (should= "" (sut/hex (byte-array 0)))))

          (context "sha256"
            (it "matches the published digest of the empty input"
                (should= "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                         (sut/sha256 (temp-file-with ""))))

            (it "matches the published digest of abc"
                (should= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                         (sut/sha256 (temp-file-with "abc"))))

            (it "reads a file larger than one buffer"
                (let [content (apply str (repeat 20000 "x"))]
                  (should= (sut/sha256 (temp-file-with content))
                           (sut/sha256 (temp-file-with content)))))

            (it "accepts a java.io.File as well as a path string"
                (let [path (temp-file-with "abc")]
                  (should= (sut/sha256 path) (sut/sha256 (io/file path)))))))

(run-specs)
