(ns cleancoders.build.digest
  "SHA-256 as lowercase hex. Its own namespace because the release path hashes
   jars, poms, SBOMs, and bytes fetched back from Clojars, and a digest is only
   useful if all four agree on the encoding."
  (:require [clojure.java.io :as io])
  (:import (java.security MessageDigest)))

(defn hex
  "Lowercase hex for a byte array. Masks each byte to 0-255 first: a byte is
   signed in Java, so formatting -1 directly yields \"ffffffff\" and produces a
   longer string that compares unequal to the same bytes hashed elsewhere."
  [bytes]
  (apply str (map #(format "%02x" (bit-and % 0xff)) bytes)))

(defn sha256
  "SHA-256 of a file's contents, as lowercase hex. Streams the file rather than
   slurping it: a jar with its dependencies is not guaranteed to be small."
  [file]
  (with-open [in (io/input-stream (io/file file))]
    (let [digest (MessageDigest/getInstance "SHA-256")
          buffer (byte-array 8192)]
      (loop []
        (let [read (.read in buffer)]
          (when (pos? read)
            (.update digest buffer 0 read)
            (recur))))
      (hex (.digest digest)))))
