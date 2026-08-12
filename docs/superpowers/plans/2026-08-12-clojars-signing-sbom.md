# Release Signing, SBOM, and Artifact Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every Clojars release from this library a GPG signature, a CycloneDX SBOM, a reproducible jar, a verified post-publish digest, a signed annotated tag, and a durable audit record.

**Architecture:** Five new single-purpose namespaces under `clj/src/cleancoders/build/` (`digest`, `sbom`, `sign`, `publish-verify`, `summary`), each pure or confined to the existing `shell/sh` seam so it is unit-testable. `jar.clj` gains jar normalization, SBOM generation, and the signed `:artifact-map`. `release.clj` gains new gates in its sequence and signs its tags. `api.clj` wires them and validates the widened `:ci-workflow`.

**Tech Stack:** Clojure, `tools.build`, `clj-commons/pomegranate` (aether), `org.clojure/data.json` (new), Speclj, `gpg`, `curl`, `git`, `gh`, GitHub Actions attestations.

**Spec:** `docs/superpowers/specs/2026-08-12-clojars-signing-sbom-design.md`

## Global Constraints

- Work happens in `clj/`. Run every command from `clj/` unless a step says otherwise.
- Tests: `clojure -M:test:spec` (all specs). Never `clj` — the wrapper needs `rlwrap`.
- Lint: `clj-kondo --lint src spec --fail-level error` must stay clean.
- All process spawning goes through `cleancoders.build.shell/sh`, never `clojure.java.shell` directly. That is the only stub point specs have.
- Specs follow the existing house style: `describe` with contexts, `stub-sh`/`capturing` helpers as in `release_spec.clj`, `(run-specs)` last.
- No new external binaries beyond `gpg` and `curl` (both present on `ubuntu-latest` and macOS).
- New Clojure dependency, exactly one: `org.clojure/data.json {:mvn/version "2.5.1"}`. Declare it explicitly; never rely on a transitive copy.
- Formatting: multi-line maps column-align keys and values. `cond` keeps predicate and result on one line. 120-column limit.
- Signing is mandatory on both publish paths. Nothing may make it optional.
- Never put a passphrase in an argument vector. It goes to a process's stdin via `:in`.
- Commit after every task, using the repo's Conventional Commits style. No `Co-Authored-By` lines.

---

### Task 1: `digest` — SHA-256 as lowercase hex

**Files:**
- Create: `clj/src/cleancoders/build/digest.clj`
- Test: `clj/spec/cleancoders/build/digest_spec.clj`

**Interfaces:**
- Consumes: nothing
- Produces: `(digest/sha256 path)` → lowercase hex string; `(digest/hex bytes)` → lowercase hex string

- [ ] **Step 1: Write the failing test**

`clj/spec/cleancoders/build/digest_spec.clj`:

```clojure
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
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — `Could not locate cleancoders/build/digest__init.class`

- [ ] **Step 3: Write the implementation**

`clj/src/cleancoders/build/digest.clj`:

```clojure
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
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS, all specs green

- [ ] **Step 5: Lint**

Run: `clj-kondo --lint src spec --fail-level error`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add clj/src/cleancoders/build/digest.clj clj/spec/cleancoders/build/digest_spec.clj
git commit -m "feat: add sha256 digest helper for release artifacts"
```

---

### Task 2: `sbom` — CycloneDX from the basis

**Files:**
- Create: `clj/src/cleancoders/build/sbom.clj`
- Test: `clj/spec/cleancoders/build/sbom_spec.clj`
- Modify: `clj/deps.edn` (add `org.clojure/data.json`)

**Interfaces:**
- Consumes: `digest/sha256` from Task 1
- Produces: `(sbom/cyclonedx {:lib sym :version str :basis map :jar-digest hex})` → map;
  `(sbom/write! {:lib :version :basis :jar-digest :sbom-file})` → the path written

**Background the implementer needs:** a `tools.build` basis has a `:libs` map whose keys are library symbols and whose values are resolved coordinates. A Maven dep looks like `{:mvn/version "1.12.0" :paths ["/root/.m2/.../clojure-1.12.0.jar"]}`. A git dep looks like `{:git/url "https://github.com/cleancoders/c3kit-apron.git" :git/sha "abc..." :paths ["/root/.gitlibs/.../src"]}`. Maven group and artifact come from the symbol: `org.clojure/clojure` → group `org.clojure`, name `clojure`. A single-segment symbol like `bucket` means group and artifact are both `bucket`, which is the Maven convention Clojure tooling follows.

- [ ] **Step 1: Add the JSON dependency**

Edit `clj/deps.edn`, `:deps` map only:

```clojure
 :deps    {io.github.clojure/tools.build {:mvn/version "0.10.14"}
           clj-commons/pomegranate       {:mvn/version "1.3.27"}
           org.clojure/data.json         {:mvn/version "2.5.1"}}
```

- [ ] **Step 2: Write the failing test**

`clj/spec/cleancoders/build/sbom_spec.clj`:

```clojure
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
```

- [ ] **Step 3: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — cannot locate `cleancoders.build.sbom`

- [ ] **Step 4: Write the implementation**

`clj/src/cleancoders/build/sbom.clj`:

```clojure
(ns cleancoders.build.sbom
  "CycloneDX SBOM built from the tools.build basis. The basis is the right
   source: it holds the fully resolved transitive closure with exact versions,
   including the :git/sha coordinates a jar scanner cannot see because they
   never appear in the pom.

   The document is deterministic -- no timestamp, and a serial number derived
   from the jar digest -- so the same source produces the same SBOM. Release
   time is recorded by the tag and the attestation, which is where it belongs."
  (:require [cleancoders.build.digest :as digest]
            [clojure.data.json :as json]
            [clojure.string :as str]))

(defn- maven-purl
  "pkg:maven purl for a library symbol. A single-segment symbol has no
   namespace, and Maven has no such thing as a groupless artifact, so the name
   serves as both -- the same convention Clojure tooling already applies."
  [lib version]
  (str "pkg:maven/" (or (namespace lib) (name lib)) "/" (name lib) "@" version))

(defn- github-purl
  "pkg:github purl from a git url and sha. Strips the scheme, any credentials,
   the host, and the .git suffix, leaving owner/repo."
  [url sha]
  (let [path (-> (str url)
                 (str/replace #"^\w+://[^/]+/" "")
                 (str/replace #"^git@[^:]+:" "")
                 (str/replace #"\.git$" ""))]
    (str "pkg:github/" path "@" sha)))

(defn- jar-hashes
  "SHA-256 of each resolved jar on a dependency's classpath. This is the
   cryptographic floor deps.edn does not provide: versions are pinned, digests
   are not, so recording them here makes a later upstream substitution
   detectable after the fact. Non-jar paths are source trees from git deps,
   whose :git/sha already identifies the bytes."
  [paths]
  (let [jars (filter #(str/ends-with? (str %) ".jar") paths)]
    (when (seq jars)
      (mapv (fn [jar] {:alg "SHA-256" :content (digest/sha256 jar)}) jars))))

(defn- component
  "One CycloneDX component for one entry of the basis :libs map."
  [[lib coord]]
  (let [sha     (:git/sha coord)
        version (or (:mvn/version coord) sha)
        purl    (if sha
                  (github-purl (:git/url coord) sha)
                  (maven-purl lib version))
        hashes  (when-not sha (jar-hashes (:paths coord)))]
    (cond-> {:type    "library"
             :group   (or (namespace lib) (name lib))
             :name    (name lib)
             :version version
             :purl    purl
             :bom-ref purl}
            hashes (assoc :hashes hashes))))

(defn- serial-number
  "urn:uuid derived from the jar digest, so two builds of the same source get
   the same serial number and two different releases do not. Not an RFC 4122
   version-4 UUID -- it is deliberately a function of the artifact -- but it
   matches the shape CycloneDX validates."
  [jar-digest]
  (let [h (subs (str jar-digest) 0 32)]
    (str "urn:uuid:" (subs h 0 8) "-" (subs h 8 12) "-" (subs h 12 16) "-"
         (subs h 16 20) "-" (subs h 20 32))))

(defn cyclonedx
  "The CycloneDX 1.6 document for one released artifact."
  [{:keys [lib version basis jar-digest]}]
  {:bomFormat    "CycloneDX"
   :specVersion  "1.6"
   :version      1
   :serialNumber (serial-number jar-digest)
   :metadata     {:tools     [{:name "cleancoders.build.sbom"}]
                  :component {:type    "library"
                              :group   (or (namespace lib) (name lib))
                              :name    (name lib)
                              :version version
                              :purl    (maven-purl lib version)
                              :bom-ref (maven-purl lib version)
                              :hashes  [{:alg "SHA-256" :content jar-digest}]}}
   :components   (vec (sort-by :purl (map component (:libs basis))))})

(defn write!
  "Writes the SBOM to :sbom-file and returns that path."
  [{:keys [sbom-file] :as cfg}]
  (println "writing" sbom-file)
  (spit sbom-file (json/write-str (cyclonedx cfg)))
  sbom-file)
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS. If `should-match` on the serial number fails, the jar digest fixture is shorter than 32 characters — fix the fixture, not the regex.

- [ ] **Step 6: Lint and commit**

```bash
clj-kondo --lint src spec --fail-level error
git add clj/deps.edn clj/src/cleancoders/build/sbom.clj clj/spec/cleancoders/build/sbom_spec.clj
git commit -m "feat: generate a CycloneDX SBOM from the build basis"
```

---

### Task 3: `sign` — GPG key import and detached signatures

**Files:**
- Create: `clj/src/cleancoders/build/sign.clj`
- Test: `clj/spec/cleancoders/build/sign_spec.clj`

**Interfaces:**
- Consumes: `shell/sh`
- Produces: `(sign/configured?)` → boolean; `(sign/key-id colon-output)` → fingerprint string or nil; `(sign/import-key!)` → fingerprint; `(sign/sign-file! path)` → `"<path>.asc"`. `import-key!` and `sign-file!` throw `ex-info` on failure. `(sign/getenv name)` exists so specs can control the environment, mirroring `release/getenv`.

**Background:** `gpg --list-secret-keys --with-colons` emits records one per line, colon-delimited. A secret key block starts with a `sec:` record and its fingerprint is the `fpr:` record that follows, field 10. Signing needs the passphrase; passing it on stdin with `--passphrase-fd 0 --pinentry-mode loopback` keeps it out of the process listing. Priming the agent once means `git tag -s` works afterwards with no further passphrase plumbing.

- [ ] **Step 1: Write the failing test**

`clj/spec/cleancoders/build/sign_spec.clj`:

```clojure
(ns cleancoders.build.sign-spec
  (:require [cleancoders.build.shell :as shell]
            [cleancoders.build.sign :as sut]
            [speclj.core :refer :all]))

(def commands (atom []))

(defn- stub-sh
  "Records invocations and answers from responses, keyed by the first two args
   or the first arg. Unlisted commands succeed silently."
  [responses]
  (fn [& args]
    (swap! commands conj (vec args))
    (get responses (vec (take 2 args))
         (get responses [(first args)] {:exit 0 :out "" :err ""}))))

(def colon-output
  (str "sec:u:255:22:AAAA1111BBBB2222:1700000000:::u:::scESC:::+::ed25519:::0:\n"
       "fpr:::::::::1111222233334444555566667777888899990000:\n"
       "uid:u::::1700000000::ABC::Clean Coders Release <release@cleancoders.com>::::::::::0:\n"))

(defn- args-for [command]
  (first (filter #(= command (first %)) @commands)))

(describe "sign"

          (context "configured?"
            (it "is true when both variables are present"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}]
                  (should= true (sut/configured?))))

            (it "is false when the key is missing"
                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}]
                  (should= false (sut/configured?))))

            (it "is false when the passphrase is missing"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY"}]
                  (should= false (sut/configured?))))

            (it "is false when either is blank rather than absent"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "   "}]
                  (should= false (sut/configured?)))))

          (context "key-id"
            (it "reads the fingerprint of the imported secret key"
                (should= "1111222233334444555566667777888899990000" (sut/key-id colon-output)))

            (it "is nil when no secret key is present"
                (should-be-nil (sut/key-id "")))

            (it "is nil when a public key exists but no secret key does"
                (should-be-nil (sut/key-id "pub:u:255:22:X:1700000000:::u:::scESC:::+::ed25519:::0:\n"))))

          (context "import-key!"
            (before (reset! commands []))

            (it "imports the key, primes the agent, and returns the fingerprint"
                (let [id (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}
                                       shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                           (sut/import-key!))]
                  (should= "1111222233334444555566667777888899990000" id)))

            (it "feeds the key material on stdin, never as an argument"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "SECRET-KEY-MATERIAL" "GPG_PASSPHRASE" "pw"}
                              shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (let [flat (pr-str (remove #(= :in %) (flatten @commands)))]
                  (should-not-contain "SECRET-KEY-MATERIAL" (pr-str (take-while #(not= :in %) (args-for "gpg"))))
                  (should-contain "SECRET-KEY-MATERIAL" flat)))

            (it "never puts the passphrase in an argument vector"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "s3cret-pass"}
                              shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (doseq [command @commands]
                  (let [positional (take-while #(not= :in %) command)]
                    (should-not-contain "s3cret-pass" (pr-str positional)))))

            (it "configures git to sign with the imported key"
                (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}
                              shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}})]
                  (sut/import-key!))
                (let [configs (filter #(= ["git" "config"] (vec (take 2 %))) @commands)
                      flat    (pr-str configs)]
                  (should-contain "user.signingkey" flat)
                  (should-contain "1111222233334444555566667777888899990000" flat)
                  ;; git tag -a refuses to run without an identity, and GitHub
                  ;; runners have none configured.
                  (should-contain "user.name" flat)
                  (should-contain "user.email" flat)
                  (should-contain "release@cleancoders.com" flat)))

            (it "throws when the import fails"
                (should-throw clojure.lang.ExceptionInfo "could not import the signing key: bad key"
                              (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}
                                            shell/sh   (stub-sh {["gpg" "--import"] {:exit 2 :out "" :err "bad key"}})]
                                (sut/import-key!))))

            (it "throws when no secret key is present after a successful import"
                (should-throw clojure.lang.ExceptionInfo
                              (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "pw"}
                                            shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out "" :err ""}})]
                                (sut/import-key!))))

            (it "throws when the agent will not accept the passphrase"
                (should-throw clojure.lang.ExceptionInfo
                              (with-redefs [sut/getenv {"GPG_PRIVATE_KEY" "KEY" "GPG_PASSPHRASE" "wrong"}
                                            shell/sh   (stub-sh {["gpg" "--list-secret-keys"] {:exit 0 :out colon-output :err ""}
                                                                 ["gpg" "--detach-sign"]     {:exit 2 :out "" :err "bad passphrase"}})]
                                (sut/import-key!)))))

          (context "sign-file!"
            (before (reset! commands []))

            (it "produces a detached armored signature and returns its path"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))
                      asc    (java.io.File. (str (.getAbsolutePath target) ".asc"))]
                  (.deleteOnExit asc)
                  (let [result (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                             shell/sh   (fn [& args]
                                                          (swap! commands conj (vec args))
                                                          (spit asc "-----BEGIN PGP SIGNATURE-----")
                                                          {:exit 0 :out "" :err ""})]
                                (sut/sign-file! (.getAbsolutePath target)))]
                    (should= (.getAbsolutePath asc) result)
                    (should-contain "--detach-sign" (args-for "gpg"))
                    (should-contain "--armor" (args-for "gpg")))))

            (it "throws when gpg fails"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))]
                  (should-throw clojure.lang.ExceptionInfo
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (stub-sh {["gpg"] {:exit 2 :out "" :err "no secret key"}})]
                                  (sut/sign-file! (.getAbsolutePath target))))))

            (it "throws when gpg reports success but wrote no signature"
                ;; A silently empty .asc would be published as a valid-looking
                ;; signature that verifies against nothing.
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))]
                  (should-throw clojure.lang.ExceptionInfo
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (stub-sh {})]
                                  (sut/sign-file! (.getAbsolutePath target))))))

            (it "throws when gpg wrote an empty signature file"
                (let [target (doto (java.io.File/createTempFile "sign-spec" ".jar") (.deleteOnExit))
                      asc    (java.io.File. (str (.getAbsolutePath target) ".asc"))]
                  (.deleteOnExit asc)
                  (should-throw clojure.lang.ExceptionInfo
                                (with-redefs [sut/getenv {"GPG_PASSPHRASE" "pw"}
                                              shell/sh   (fn [& _] (spit asc "") {:exit 0 :out "" :err ""})]
                                  (sut/sign-file! (.getAbsolutePath target))))))))

(run-specs)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — cannot locate `cleancoders.build.sign`

- [ ] **Step 3: Write the implementation**

`clj/src/cleancoders/build/sign.clj`:

```clojure
(ns cleancoders.build.sign
  "GPG key handling and detached signatures.

   The passphrase always travels on a process's stdin, never in an argument
   vector: arguments are visible in a process listing and get echoed back in
   error messages, and this one unlocks the organization's release key.

   import-key! primes the gpg agent by signing a scratch file. That is
   load-bearing rather than decorative -- once the agent holds the passphrase,
   both sign-file! and `git tag -s` work with no further passphrase plumbing,
   which is what lets artifact signing and tag signing share one mechanism."
  (:require [cleancoders.build.shell :as shell]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def ^:private key-var "GPG_PRIVATE_KEY")
(def ^:private passphrase-var "GPG_PASSPHRASE")

(defn getenv
  "Indirection over System/getenv so specs can control the environment."
  [name]
  (System/getenv name))

(defn configured?
  "True when both signing variables hold something."
  []
  (not-any? #(str/blank? (str (getenv %))) [key-var passphrase-var]))

(defn- fail!
  [msg detail]
  (throw (ex-info (str msg (when-not (str/blank? (str detail)) (str ": " (str/trim (str detail))))) {})))

(defn key-id
  "Fingerprint of the first secret key in `gpg --list-secret-keys --with-colons`
   output. Reads the fpr record following a sec record: a public-only keyring
   also has fpr records, and signing with one is impossible."
  [colon-out]
  (->> (str/split-lines (str colon-out))
       (drop-while #(not (str/starts-with? % "sec:")))
       (some #(second (re-find #"^fpr:+([0-9A-F]+):" %)))))

(defn- uid-email
  "Email from the key's uid record, used as the git identity so tag objects
   carry the same identity that signed them."
  [colon-out]
  (->> (str/split-lines (str colon-out))
       (keep #(second (re-find #"^uid:.*<([^>]+)>" %)))
       first))

(defn- uid-name
  [colon-out]
  (->> (str/split-lines (str colon-out))
       (keep #(second (re-find #"^uid:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^<:]+)<" %)))
       first
       str/trim
       not-empty))

(defn- agent-conf!
  "Enables loopback pinentry and lengthens the passphrase cache. The default
   600-second cache can expire between signing the artifacts and signing the
   tag, which would stall a release waiting for a prompt no one can answer."
  []
  (let [dir (io/file (System/getProperty "user.home") ".gnupg")]
    (.mkdirs dir)
    (spit (io/file dir "gpg-agent.conf")
          "allow-loopback-pinentry\ndefault-cache-ttl 7200\nmax-cache-ttl 7200\n")
    (shell/sh "gpg-connect-agent" "reloadagent" "/bye")))

(defn- gpg-sign!
  "Detached-signs path, returning the sh result. The passphrase goes to stdin."
  [path]
  (shell/sh "gpg" "--batch" "--yes" "--pinentry-mode" "loopback" "--passphrase-fd" "0"
            "--detach-sign" "--armor" path
            :in (str (getenv passphrase-var))))

(defn sign-file!
  "Writes <path>.asc and returns that path. Verifies the signature file exists
   and is non-empty: gpg exiting zero having written nothing would publish a
   valid-looking signature that verifies against nothing."
  [path]
  (let [{:keys [exit err]} (gpg-sign! path)
        asc                (io/file (str path ".asc"))]
    (when-not (zero? exit)
      (fail! (str "could not sign " path) err))
    (when-not (.exists asc)
      (fail! (str "gpg reported success but wrote no signature for " path) nil))
    (when (zero? (.length asc))
      (fail! (str "gpg wrote an empty signature for " path) nil))
    (.getAbsolutePath asc)))

(defn import-key!
  "Imports the release key, primes the agent, points git at it, and returns the
   fingerprint."
  []
  (println "importing the signing key")
  (agent-conf!)
  (let [{:keys [exit err]} (shell/sh "gpg" "--batch" "--import" :in (str (getenv key-var)))]
    (when-not (zero? exit)
      (fail! "could not import the signing key" err)))
  (let [{:keys [exit out err]} (shell/sh "gpg" "--list-secret-keys" "--with-colons")]
    (when-not (zero? exit)
      (fail! "could not list the imported key" err))
    (let [id (key-id out)]
      (when-not id
        (fail! "no secret key present after import; is GPG_PRIVATE_KEY a private key?" nil))
      ;; Prime the agent, and prove the passphrase is right, before anything is
      ;; built. A wrong passphrase discovered at tag time strands a release.
      (let [scratch (doto (java.io.File/createTempFile "release-sign-check" ".txt") (.deleteOnExit))]
        (spit scratch "priming the gpg agent")
        (io/delete-file (io/file (str (.getAbsolutePath scratch) ".asc")) true)
        (let [{:keys [exit err]} (gpg-sign! (.getAbsolutePath scratch))]
          (when-not (zero? exit)
            (fail! "the signing key passphrase was rejected" err))
          (io/delete-file (io/file (str (.getAbsolutePath scratch) ".asc")) true)))
      (shell/sh "git" "config" "user.signingkey" id)
      (when-let [email (uid-email out)]
        (shell/sh "git" "config" "user.email" email))
      (when-let [name (uid-name out)]
        (shell/sh "git" "config" "user.name" name))
      id)))
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS. `uid-name` parsing is the fragile part — if the name assertion fails, print the uid record in the spec and adjust the field count. Do not weaken the assertion that `user.name` and `user.email` get configured.

- [ ] **Step 5: Lint and commit**

```bash
clj-kondo --lint src spec --fail-level error
git add clj/src/cleancoders/build/sign.clj clj/spec/cleancoders/build/sign_spec.clj
git commit -m "feat: import the release key and produce detached signatures"
```

---

### Task 4: `publish-verify` — re-fetch from Clojars and compare digests

**Files:**
- Create: `clj/src/cleancoders/build/publish_verify.clj`
- Test: `clj/spec/cleancoders/build/publish_verify_spec.clj`

**Interfaces:**
- Consumes: `shell/sh`, `digest/sha256`
- Produces: `(publish-verify/artifact-url {:lib sym :version str :jar-name str})` → url string;
  `(publish-verify/verdict fetched-digest local-digest)` → nil or reason string;
  `(publish-verify/verify! {:url :digest :attempts :wait-ms :sleep!})` → nil or reason string

**Note the namespace/file mismatch rule:** the namespace is `cleancoders.build.publish-verify`, so the file must be `publish_verify.clj` with an underscore.

- [ ] **Step 1: Write the failing test**

`clj/spec/cleancoders/build/publish_verify_spec.clj`:

```clojure
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
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — cannot locate `cleancoders.build.publish-verify`

- [ ] **Step 3: Write the implementation**

`clj/src/cleancoders/build/publish_verify.clj`:

```clojure
(ns cleancoders.build.publish-verify
  "Re-fetches a published artifact from Clojars and compares its digest to the
   jar that was uploaded. This is the only detection this release path has for
   registry-side substitution or a wrong-artifact publish, so it runs before
   any tag exists.

   Clojars is eventually consistent, so a fetch failure is retried. A digest
   mismatch never is: retrying a mismatch could turn a real finding into a pass."
  (:require [cleancoders.build.digest :as digest]
            [cleancoders.build.shell :as shell]
            [clojure.string :as str]))

(def ^:private repo-url "https://repo.clojars.org")

(defn artifact-url
  "Maven-layout URL Clojars serves the jar from. The group's dots become path
   separators; a single-segment coordinate is its own group."
  [{:keys [lib version]}]
  (let [group (str/replace (or (namespace lib) (name lib)) "." "/")
        name' (name lib)]
    (str repo-url "/" group "/" name' "/" version "/" name' "-" version ".jar")))

(defn verdict
  "nil when the fetched digest matches the local one, otherwise the reason."
  [fetched local]
  (cond (str/blank? (str fetched)) "the published artifact is not readable on Clojars"
        (= fetched local)          nil
        :else                      (str "digest mismatch: Clojars has sha256:" fetched
                                        " but the published jar is sha256:" local)))

(defn- fetch-digest
  "Downloads url to a temp file and returns its digest, or nil when the fetch
   failed. Downloads to a file rather than capturing stdout: jar bytes run
   through a string decoder come out corrupted and would fail every compare."
  [url]
  (let [target (doto (java.io.File/createTempFile "publish-verify" ".jar") (.deleteOnExit))
        {:keys [exit]} (shell/sh "curl" "-fsSL" "--max-time" "60" "-o" (.getAbsolutePath target) url)]
    (when (zero? exit)
      (digest/sha256 target))))

(defn verify!
  "Polls until the artifact is readable, then compares digests. Returns nil on
   success or the reason it failed."
  [{:keys [url digest attempts wait-ms sleep!] :or {attempts 6 wait-ms 5000 sleep! #(Thread/sleep %)}}]
  (loop [attempt 1 wait wait-ms]
    (println (format "verifying published artifact (attempt %d/%d)" attempt attempts))
    (let [fetched (fetch-digest url)]
      (cond
        fetched               (let [reason (verdict fetched digest)]
                                (if reason
                                  reason
                                  (do (println "  sha256 match") nil)))
        (< attempt attempts)  (do (println (format "  not readable yet, retrying in %dms" wait))
                                  (sleep! wait)
                                  (recur (inc attempt) (* 2 wait)))
        :else                 (verdict nil digest)))))
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS

- [ ] **Step 5: Lint and commit**

```bash
clj-kondo --lint src spec --fail-level error
git add clj/src/cleancoders/build/publish_verify.clj clj/spec/cleancoders/build/publish_verify_spec.clj
git commit -m "feat: verify a published artifact's digest against the local jar"
```

---

### Task 5: `summary` — the durable release record

**Files:**
- Create: `clj/src/cleancoders/build/summary.clj`
- Test: `clj/spec/cleancoders/build/summary_spec.clj`

**Interfaces:**
- Consumes: nothing
- Produces: `(summary/render {:version :commit :artifacts})` → markdown string;
  `(summary/emergency-banner {:version :commit :actor :emergency-var})` → markdown string;
  `(summary/emit! text)` → nil; `(summary/getenv name)` for spec control.
  `:artifacts` is a seq of `{:name "bucket-2.14.0.jar" :digest "1f3a…"}`.

- [ ] **Step 1: Write the failing test**

`clj/spec/cleancoders/build/summary_spec.clj`:

```clojure
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
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — cannot locate `cleancoders.build.summary`

- [ ] **Step 3: Write the implementation**

`clj/src/cleancoders/build/summary.clj`:

```clojure
(ns cleancoders.build.summary
  "The durable record of what a release shipped. Digests go to the job summary,
   which survives longer than a log line and is readable without re-running
   anything. Falls back to stdout, so a local break-glass release still leaves
   a record, and never throws: losing the record must not fail a release that
   otherwise succeeded."
  (:require [clojure.string :as str]))

(defn getenv
  "Indirection over System/getenv so specs can control the environment."
  [name]
  (System/getenv name))

(defn- digest-rows
  [artifacts]
  (str/join "\n" (map #(format "| `%s` | `sha256:%s` |" (:name %) (:digest %)) artifacts)))

(defn render
  "Markdown for a normal release."
  [{:keys [version commit artifacts]}]
  (str "### Released " version "\n\n"
       "commit `" commit "`\n\n"
       "| artifact | digest |\n|---|---|\n"
       (digest-rows artifacts)
       "\n"))

(defn emergency-banner
  "Markdown for a break-glass release. Names the actor, because the whole point
   of this record is answering who shipped what without CI verification."
  [{:keys [version commit actor emergency-var]}]
  (str "### :warning: EMERGENCY RELEASE " version "\n\n"
       "CI verification was **skipped**.\n\n"
       "- released by: `" (or (not-empty (str actor)) "unknown") "`\n"
       "- commit: `" commit "`\n"
       "- authorized by: `" emergency-var "=" version "`\n"))

(defn emit!
  "Appends text to $GITHUB_STEP_SUMMARY, or prints it when there is none."
  [text]
  (let [path (getenv "GITHUB_STEP_SUMMARY")]
    (if (str/blank? (str path))
      (println text)
      (try
        (spit path (str text "\n") :append true)
        (catch Exception _
          (println text))))))
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS

- [ ] **Step 5: Lint and commit**

```bash
clj-kondo --lint src spec --fail-level error
git add clj/src/cleancoders/build/summary.clj clj/spec/cleancoders/build/summary_spec.clj
git commit -m "feat: record release digests in the job summary"
```

---

### Task 6: Reproducible jar normalization

**Files:**
- Modify: `clj/src/cleancoders/build/jar.clj` (add `normalize!`, call it from `build!`)
- Test: `clj/spec/cleancoders/build/jar_spec.clj` (add a `normalize!` context)

**Interfaces:**
- Consumes: nothing new
- Produces: `(jar/normalize! jar-file)` → the jar path, rewritten in place

**Why `setTimeLocal`:** `ZipEntry.setTime` converts epoch millis to the zip format's DOS timestamp *using the local time zone*, so the same source would produce different bytes on a runner in UTC and a laptop in CST. `setTimeLocal` writes the DOS field from a `LocalDateTime` with no conversion, which is what makes the output machine-independent. Java 21 is the floor, so it is available.

- [ ] **Step 1: Write the failing test**

Add to `clj/spec/cleancoders/build/jar_spec.clj`. Extend the `:require` to `[cleancoders.build.digest :as digest]`, `[clojure.java.io :as io]`.

First, these four helpers at the **top level** of the spec file, next to the existing `cfg` helper — not inside a `context`, where a `defn-` would run at describe-registration time and clj-kondo would flag it:

```clojure
(defn- write-jar!
  "Writes a jar with the given [name content] entries, timestamped now."
  [path entries]
  (with-open [out (java.util.zip.ZipOutputStream. (io/output-stream path))]
    (doseq [[name content] entries]
      (.putNextEntry out (doto (java.util.zip.ZipEntry. ^String name)
                           (.setTime (System/currentTimeMillis))))
      (.write out (.getBytes (str content) "UTF-8"))
      (.closeEntry out))))

(defn- entry-names [path]
  (with-open [zip (java.util.zip.ZipFile. (io/file path))]
    (mapv #(.getName %) (enumeration-seq (.entries zip)))))

(defn- entry-content [path entry-name]
  (with-open [zip (java.util.zip.ZipFile. (io/file path))]
    (slurp (.getInputStream zip (.getEntry zip entry-name)))))

(defn- temp-jar []
  (.getAbsolutePath (doto (java.io.File/createTempFile "jar-spec" ".jar") (.deleteOnExit))))
```

Then this context, before the final `)` of `describe`:

```clojure
          (context "normalize!"
            (it "produces identical bytes for two jars whose entry timestamps differ"
                (let [entries [["b.txt" "bee"] ["a.txt" "ay"] ["META-INF/MANIFEST.MF" "Manifest-Version: 1.0"]]
                      first'  (temp-jar)
                      second' (temp-jar)]
                  (write-jar! first' entries)
                  (Thread/sleep 1100)                       ; DOS timestamps have 2-second resolution
                  (write-jar! second' entries)
                  (sut/normalize! first')
                  (sut/normalize! second')
                  (should= (digest/sha256 first') (digest/sha256 second'))))

            (it "produces identical bytes regardless of the order entries were written in"
                (let [forward (temp-jar)
                      reverse' (temp-jar)]
                  (write-jar! forward [["a.txt" "ay"] ["b.txt" "bee"]])
                  (write-jar! reverse' [["b.txt" "bee"] ["a.txt" "ay"]])
                  (sut/normalize! forward)
                  (sut/normalize! reverse')
                  (should= (digest/sha256 forward) (digest/sha256 reverse'))))

            (it "writes the manifest first, then the remaining entries in name order"
                (let [path (temp-jar)]
                  (write-jar! path [["z.txt" "zed"] ["a.txt" "ay"] ["META-INF/MANIFEST.MF" "Manifest-Version: 1.0"]])
                  (sut/normalize! path)
                  (should= ["META-INF/MANIFEST.MF" "a.txt" "z.txt"] (entry-names path))))

            (it "preserves every entry's content"
                (let [path (temp-jar)]
                  (write-jar! path [["a.txt" "ay"] ["nested/b.txt" "bee"]])
                  (sut/normalize! path)
                  (should= "ay" (entry-content path "a.txt"))
                  (should= "bee" (entry-content path "nested/b.txt"))))

            (it "strips the comment line Properties.store writes, which carries a timestamp"
                (let [path (temp-jar)]
                  (write-jar! path [["META-INF/maven/g/a/pom.properties"
                                     "#Wed Aug 12 09:00:00 CDT 2026\nversion=2.14.0\n"]])
                  (sut/normalize! path)
                  (let [content (entry-content path "META-INF/maven/g/a/pom.properties")]
                    (should-not-contain "#Wed Aug" content)
                    (should-contain "version=2.14.0" content))))

            (it "returns the path it normalized"
                (let [path (temp-jar)]
                  (write-jar! path [["a.txt" "ay"]])
                  (should= path (sut/normalize! path)))))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — `No such var: sut/normalize!`

- [ ] **Step 3: Write the implementation**

Add to `clj/src/cleancoders/build/jar.clj`. Extend the `:require` with `[clojure.java.io :as io]` and add these before `install!`:

```clojure
(def ^:private manifest-name "META-INF/MANIFEST.MF")

(def ^:private fixed-time
  ;; 1980-01-01T00:00:00, the earliest instant the zip format can store. Set
  ;; with setTimeLocal, not setTime: setTime converts epoch millis to the DOS
  ;; timestamp using the local zone, so the same source would produce different
  ;; bytes in UTC and in CST. setTimeLocal writes the field with no conversion.
  (java.time.LocalDateTime/of 1980 1 1 0 0 0))

(defn- read-entries
  "Every entry of a jar as [name bytes]."
  [jar-file]
  (with-open [zip (java.util.zip.ZipFile. (io/file jar-file))]
    (->> (enumeration-seq (.entries zip))
         (mapv (fn [entry]
                 (let [out (java.io.ByteArrayOutputStream.)]
                   (with-open [in (.getInputStream zip entry)]
                     (io/copy in out))
                   [(.getName entry) (.toByteArray out)]))))))

(defn- strip-properties-comments
  "Drops comment lines from a .properties entry. java.util.Properties/store
   writes the current date as a leading comment, which would change the jar's
   digest on every build. Comments carry no meaning to a properties reader."
  [name bytes]
  (if (str/ends-with? name ".properties")
    (let [lines (str/split-lines (String. ^bytes bytes "UTF-8"))
          kept  (remove #(str/starts-with? % "#") lines)]
      (.getBytes (str (str/join "\n" kept) "\n") "UTF-8"))
    bytes))

(defn- ordered
  "Manifest first, then every other entry by name. Sorting alone would be
   deterministic, but the jar spec expects the manifest first and some tools
   read it without scanning the central directory."
  [entries]
  (sort-by (fn [[name _]] [(if (= manifest-name name) 0 1) name]) entries))

(defn normalize!
  "Rewrites a jar deterministically: entries in a fixed order, every timestamp
   fixed, no preserved file metadata. Two builds of the same source then produce
   byte-identical jars, which is what makes a recorded digest meaningful --
   deploy rebuilds the artifact CI tested rather than promoting it."
  [jar-file]
  (println "normalizing" jar-file)
  (let [entries (ordered (read-entries jar-file))
        target  (java.io.File/createTempFile "normalized" ".jar")]
    (with-open [out (java.util.zip.ZipOutputStream. (io/output-stream target))]
      (doseq [[name bytes] entries]
        (.putNextEntry out (doto (java.util.zip.ZipEntry. ^String name)
                             (.setTimeLocal fixed-time)))
        (.write out ^bytes (strip-properties-comments name bytes))
        (.closeEntry out)))
    (java.nio.file.Files/move (.toPath target)
                              (.toPath (io/file jar-file))
                              (into-array java.nio.file.CopyOption
                                          [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    jar-file))
```

Then call it from `build!`:

```clojure
(defn build! [{:keys [basis class-dir jar-file] :as cfg}]
  (clean! cfg)
  (pom! cfg)
  (println "building" jar-file)
  (b/copy-dir {:src-dirs   (:paths basis)
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file  jar-file})
  (normalize! jar-file))
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS — except the pre-existing `install!` call-order case, which stubs `b/jar`
so no jar file exists for `normalize!` to open. Add `sut/normalize! (constantly nil)` to
that spec's `with-redefs`, and add `:normalize` to its expected call vector if you would
rather assert the new step is present:

```clojure
                  (with-redefs [b/delete       (fn [_] (swap! calls conj :clean))
                                b/write-pom    (fn [_] (swap! calls conj :pom))
                                b/copy-dir     (fn [_] (swap! calls conj :copy-dir))
                                b/jar          (fn [_] (swap! calls conj :jar))
                                sut/normalize! (fn [_] (swap! calls conj :normalize))
                                aether/install (fn [_] (swap! calls conj :install))]
                    (sut/install! (cfg)))
                  (should= [:clean :pom :copy-dir :jar :normalize :install] @calls)
```

- [ ] **Step 5: Prove reproducibility end to end**

Run, from the repo root:

```bash
cd clj && clojure -T:build 2>/dev/null || true
```

That alias does not exist here, so instead verify with a real jar via the REPL:

```bash
cd clj && clojure -M:test -e "
(require '[cleancoders.build.jar :as jar] '[cleancoders.build.digest :as digest])
(let [cfg (jar/config {:group \"com.cleancoders\" :lib-name \"selftest\" :version \"0.0.1\"
                       :license-url \"https://example.com/LICENSE\"})]
  (jar/build! cfg)
  (let [a (digest/sha256 (:jar-file cfg))]
    (jar/build! cfg)
    (println :first a)
    (println :second (digest/sha256 (:jar-file cfg)))
    (println :reproducible (= a (digest/sha256 (:jar-file cfg))))))"
```

Expected: `:reproducible true`. If it prints `false`, find the differing entry with
`unzip -l` on both jars plus a diff of each entry's bytes, and extend `normalize!` to
neutralize whatever varies. Do not proceed until this prints true — the digest recording
in later tasks is only meaningful if it does.

- [ ] **Step 6: Lint and commit**

```bash
clj-kondo --lint src spec --fail-level error
git add clj/src/cleancoders/build/jar.clj clj/spec/cleancoders/build/jar_spec.clj
git commit -m "feat: normalize jars so a release rebuild is byte-reproducible"
```

---

### Task 7: SBOM, signing, and the signed `:artifact-map` in `jar`

**Files:**
- Modify: `clj/src/cleancoders/build/jar.clj`
- Test: `clj/spec/cleancoders/build/jar_spec.clj`

**Interfaces:**
- Consumes: `digest/sha256`, `sbom/write!`, `sign/sign-file!`, `publish-verify/artifact-url`
- Produces: `(jar/config …)` now also returns `:sbom-file`;
  `(jar/sign-all! cfg)` → vector of `.asc` paths;
  `(jar/artifacts cfg)` → vector of `{:name :path :digest :url}` (`:url` present on the jar only);
  `(jar/artifact-map cfg)` → the pomegranate `:artifact-map`;
  `publish!` now uploads signatures and the SBOM.

**Background on `:artifact-map`:** pomegranate's `aether/deploy` and `aether/install` accept `:artifact-map`, whose keys are coordinate-modifier vectors and whose values are file paths — `{[:extension "jar"] "target/x.jar" [:extension "jar.asc"] "target/x.jar.asc"}`. This is how Leiningen ships signatures. The classifier form is `[:classifier "cyclonedx" :extension "json"]`. Step 5 verifies the shape against a real local install rather than trusting that description.

- [ ] **Step 1: Write the failing test**

Add to `clj/spec/cleancoders/build/jar_spec.clj`, requiring `[cleancoders.build.sbom :as sbom]`, `[cleancoders.build.sign :as sign]`, `[cleancoders.build.publish-verify :as pv]`:

```clojure
          (context "config"
            (it "names the sbom after lib-name and version, with the cyclonedx classifier"
                (should= "target/bucket-2.14.0-cyclonedx.json" (:sbom-file (cfg)))))

          (context "build!"
            (it "writes the sbom for the normalized jar's digest"
                (let [captured (atom nil)]
                  (with-redefs [b/delete       (constantly nil)
                                b/write-pom    (constantly nil)
                                b/copy-dir     (constantly nil)
                                b/jar          (constantly nil)
                                sut/normalize! (constantly nil)
                                digest/sha256  (constantly "1f3a")
                                sbom/write!    (fn [c] (reset! captured c) (:sbom-file c))]
                    (sut/build! (cfg)))
                  (should= "1f3a" (:jar-digest @captured))
                  (should= "target/bucket-2.14.0-cyclonedx.json" (:sbom-file @captured))
                  (should= 'com.cleancoders.c3kit/bucket (:lib @captured)))))

          (context "sign-all!"
            (it "signs the jar, the pom, and the sbom"
                (let [signed (atom [])]
                  (with-redefs [sign/import-key! (constantly "FPR")
                                sign/sign-file!  (fn [p] (swap! signed conj p) (str p ".asc"))]
                    (sut/sign-all! (cfg)))
                  (should= ["target/bucket-2.14.0.jar"
                            "target/classes/META-INF/maven/com.cleancoders.c3kit/bucket/pom.xml"
                            "target/bucket-2.14.0-cyclonedx.json"]
                           @signed)))

            (it "imports the key once, before signing anything"
                (let [calls (atom [])]
                  (with-redefs [sign/import-key! (fn [] (swap! calls conj :import) "FPR")
                                sign/sign-file!  (fn [p] (swap! calls conj :sign) (str p ".asc"))]
                    (sut/sign-all! (cfg)))
                  (should= [:import :sign :sign :sign] @calls))))

          (context "artifact-map"
            (with amap (sut/artifact-map (cfg)))

            (it "uploads the jar and its signature"
                (should= "target/bucket-2.14.0.jar" (get @amap [:extension "jar"]))
                (should= "target/bucket-2.14.0.jar.asc" (get @amap [:extension "jar.asc"])))

            (it "uploads the pom and its signature"
                (should-contain "pom.xml" (get @amap [:extension "pom"]))
                (should-contain "pom.xml.asc" (get @amap [:extension "pom.asc"])))

            (it "uploads the sbom under the cyclonedx classifier and its signature"
                (should= "target/bucket-2.14.0-cyclonedx.json"
                         (get @amap [:classifier "cyclonedx" :extension "json"]))
                (should= "target/bucket-2.14.0-cyclonedx.json.asc"
                         (get @amap [:classifier "cyclonedx" :extension "json.asc"])))

            (it "uploads exactly those six files"
                (should= 6 (count @amap))))

          (context "artifacts"
            (with entries (with-redefs [digest/sha256 (fn [p] (str "sha-of:" p))]
                            (sut/artifacts (cfg))))

            (it "records a digest for the jar, the pom, and the sbom"
                (should= ["bucket-2.14.0.jar" "bucket-2.14.0.pom" "bucket-2.14.0-cyclonedx.json"]
                         (map :name @entries))
                (should= "sha-of:target/bucket-2.14.0.jar" (:digest (first @entries))))

            (it "gives only the jar a verification url, which is what Clojars is asked for"
                (should= (pv/artifact-url {:lib 'com.cleancoders.c3kit/bucket :version "2.14.0"})
                         (:url (first @entries)))
                (should-be-nil (:url (second @entries)))
                (should-be-nil (:url (last @entries)))))

          (context "publish!"
            (it "deploys with the signed artifact map"
                (let [captured (atom nil)]
                  (with-redefs [aether/deploy (fn [opts] (reset! captured opts))]
                    (sut/publish! (cfg)))
                  (should= (sut/artifact-map (cfg)) (:artifact-map @captured))
                  (should= ['com.cleancoders.c3kit/bucket "2.14.0"] (:coordinates @captured)))))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — `No such var: sut/sign-all!`

- [ ] **Step 3: Write the implementation**

In `clj/src/cleancoders/build/jar.clj`: extend `:require` with `[cleancoders.build.digest :as digest]`, `[cleancoders.build.publish-verify :as publish-verify]`, `[cleancoders.build.sbom :as sbom]`, `[cleancoders.build.sign :as sign]`.

In `config`, add `sbom-file` alongside `jar-file`:

```clojure
  (let [class-dir "target/classes"
        jar-file  (format "target/%s-%s.jar" lib-name version)
        sbom-file (format "target/%s-%s-cyclonedx.json" lib-name version)
        lib       (symbol group lib-name)]
    {:lib       lib
     :version   version
     :class-dir class-dir
     :jar-file  jar-file
     :sbom-file sbom-file
     ...
```

Then, after `normalize!`:

```clojure
(defn- sbom!
  "Writes the SBOM for the jar that was just built. Takes the jar's digest so
   the SBOM names the exact bytes it describes."
  [{:keys [lib version basis jar-file sbom-file]}]
  (sbom/write! {:lib        lib
                :version    version
                :basis      basis
                :jar-digest (digest/sha256 jar-file)
                :sbom-file  sbom-file}))

(defn build! [{:keys [basis class-dir jar-file] :as cfg}]
  (clean! cfg)
  (pom! cfg)
  (println "building" jar-file)
  (b/copy-dir {:src-dirs   (:paths basis)
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file  jar-file})
  (normalize! jar-file)
  (sbom! cfg))

(defn signable
  "The files a release signs, in upload order."
  [{:keys [jar-file sbom-file deploy]}]
  [jar-file (:pom-file deploy) sbom-file])

(defn sign-all!
  "Imports the release key once, then detach-signs every published file."
  [cfg]
  (sign/import-key!)
  (mapv sign/sign-file! (signable cfg)))

(defn artifact-map
  "The pomegranate :artifact-map that uploads the jar, the pom, the SBOM, and a
   detached signature for each. Built here rather than in config because
   install! must not require signatures that only a release produces."
  [{:keys [jar-file sbom-file deploy]}]
  (let [pom-file (:pom-file deploy)]
    {[:extension "jar"]                            jar-file
     [:extension "jar.asc"]                        (str jar-file ".asc")
     [:extension "pom"]                            pom-file
     [:extension "pom.asc"]                        (str pom-file ".asc")
     [:classifier "cyclonedx" :extension "json"]   sbom-file
     [:classifier "cyclonedx" :extension "json.asc"] (str sbom-file ".asc")}))

(defn artifacts
  "What this release shipped, for the digest record and post-publish
   verification. Only the jar carries a :url: it is the artifact whose bytes a
   consumer actually executes, and one fetch is enough to detect a
   registry-side substitution."
  [{:keys [lib version jar-file sbom-file deploy]}]
  (let [pom-file (:pom-file deploy)
        name-of  #(.getName (java.io.File. (str %)))]
    [{:name (name-of jar-file)  :path jar-file  :digest (digest/sha256 jar-file)
      :url  (publish-verify/artifact-url {:lib lib :version version})}
     {:name (format "%s-%s.pom" (name lib) version) :path pom-file :digest (digest/sha256 pom-file)}
     {:name (name-of sbom-file) :path sbom-file :digest (digest/sha256 sbom-file)}]))
```

And change `publish!` to upload the map:

```clojure
(defn publish! [{:keys [deploy] :as cfg}]
  (println "deploying" (:coordinates deploy))
  (aether/deploy (assoc deploy :artifact-map (artifact-map cfg))))
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS — with one more fix to the pre-existing `install!` case, which now reaches
`sbom!` and would hash a jar the stubbed `b/jar` never wrote. Extend its `with-redefs`:

```clojure
                                sbom/write!    (fn [_] (swap! calls conj :sbom))
                                digest/sha256  (constantly "1f3a")
```

and add `:sbom` to the expected vector, after `:normalize`.

- [ ] **Step 5: Prove the `:artifact-map` shape against a real install**

This is the one claim in this task that rests on library behavior rather than our own
code. Verify it, do not assume it:

```bash
cd clj && clojure -M:test -e "
(require '[cleancoders.build.jar :as jar] '[cemerick.pomegranate.aether :as aether])
(let [cfg (jar/config {:group \"com.cleancoders\" :lib-name \"selftest\" :version \"0.0.1\"
                       :license-url \"https://example.com/LICENSE\"})]
  (jar/build! cfg)
  (doseq [f (jar/signable cfg)] (spit (str f \".asc\") \"-----BEGIN PGP SIGNATURE-----\"))
  (aether/install (assoc (:deploy cfg)
                         :artifact-map (jar/artifact-map cfg)
                         :local-repo \"/tmp/selftest-repo\"))
  (println (sort (map #(.getName %) (file-seq (clojure.java.io/file \"/tmp/selftest-repo/com/cleancoders/selftest/0.0.1\"))))))"
```

Expected: the listing contains `selftest-0.0.1.jar`, `selftest-0.0.1.jar.asc`,
`selftest-0.0.1.pom`, `selftest-0.0.1.pom.asc`, `selftest-0.0.1-cyclonedx.json`, and
`selftest-0.0.1-cyclonedx.json.asc`.

If pomegranate rejects the map, the exception names the offending key. Two known
adjustments: keep `:jar-file` and `:pom-file` in the deploy map alongside
`:artifact-map`, and if `[:classifier "cyclonedx" :extension "json.asc"]` is refused,
use `[:classifier "cyclonedx" :extension "json.asc"]`'s two-part form
`[:classifier "cyclonedx" :extension "json"]` for the SBOM and publish its signature as
`[:classifier "cyclonedx-asc" :extension "json"]`. Update the spec to match whatever
the real install accepts, and note the reason in a comment.

- [ ] **Step 6: Clean up and commit**

```bash
rm -rf /tmp/selftest-repo clj/target
clj-kondo --lint src spec --fail-level error
git add clj/src/cleancoders/build/jar.clj clj/spec/cleancoders/build/jar_spec.clj
git commit -m "feat: publish detached signatures and the SBOM alongside the jar"
```

---

### Task 8: `verify-ci!` accepts several workflows

**Files:**
- Modify: `clj/src/cleancoders/build/release.clj`
- Test: `clj/spec/cleancoders/build/release_spec.clj`

**Interfaces:**
- Consumes: nothing new
- Produces: `verify-ci!` accepts `:ci-workflow` as a string or a collection of strings; unchanged for a string.

- [ ] **Step 1: Write the failing test**

Add to the existing `verify-ci!` context in `release_spec.clj`:

```clojure
            (it "checks every workflow when given a vector"
                (should-be-nil
                 (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                              ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                               (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                                :ci-workflow ["build.yml" "security.yml"]}))))
                (should= 2 (count (filter #(= "gh" (first %)) @commands))))

            (it "queries each named workflow"
                (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                             ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                              (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                               :ci-workflow ["build.yml" "security.yml"]})))
                (let [paths (map #(nth % 2) (filter #(= "gh" (first %)) @commands))]
                  (should-contain "/actions/workflows/build.yml/runs" (first paths))
                  (should-contain "/actions/workflows/security.yml/runs" (second paths))))

            (it "aborts naming the workflow that was not green"
                (let [msg (capturing
                           #(with-redefs [shell/sh (fn [& args]
                                                     (swap! commands conj (vec args))
                                                     (cond (= "git" (first args)) {:exit 0 :out "abc123\n" :err ""}
                                                           (re-find #"security\.yml" (str args)) {:exit 0 :out "completed failure" :err ""}
                                                           :else {:exit 0 :out "completed success" :err ""}))]
                              (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                               :ci-workflow ["build.yml" "security.yml"]})))]
                  (should-contain "concluded failure" msg)
                  (should-contain "security.yml" msg)))

            (it "reads HEAD once no matter how many workflows are named"
                (capturing #(with-redefs [shell/sh (stub-sh {["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}
                                                             ["gh"]              {:exit 0 :out "completed success" :err ""}})]
                              (sut/verify-ci! {:repo        "cleancoders/c3kit-wire"
                                               :ci-workflow ["build.yml" "security.yml" "lint.yml"]})))
                (should= 1 (count (filter #(= ["git" "rev-parse"] (vec (take 2 %))) @commands))))
```

Add `(before (reset! commands []))` is already present in that context — leave it.

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — the vector is formatted into the API path, producing one `gh` call against a nonsense workflow name

- [ ] **Step 3: Write the implementation**

Replace `verify-ci!` in `clj/src/cleancoders/build/release.clj`:

```clojure
(defn- workflow-names
  "One or many. :ci-workflow started as a single workflow name and accepts a
   vector without breaking the consumers that pass a string."
  [ci-workflow]
  (if (coll? ci-workflow) (vec ci-workflow) [ci-workflow]))

(defn- workflow-verdict
  "nil when this workflow's newest run at sha succeeded, otherwise the reason."
  [repo sha workflow]
  (let [path (format "/repos/%s/actions/workflows/%s/runs?head_sha=%s&per_page=1"
                     repo workflow sha)
        {:keys [exit out err]} (shell/sh "gh" "api" path "--jq" run-projection)]
    (if (zero? exit)
      (run-verdict out)
      (str "could not query CI status: " (str/trim (str err))))))

(defn verify-ci!
  "Aborts unless the newest run of every named workflow for the current commit
   succeeded. Reads HEAD once, then queries each workflow, so an abort names
   which one was not green.

   Scoped to named workflows rather than the commit's check-runs on purpose: the
   release run registers its own check-run against the same commit, so an
   all-check-runs-green query would observe itself as in_progress and deadlock."
  [{:keys [repo ci-workflow]}]
  (let [sha (head-sha)]
    (doseq [workflow (workflow-names ci-workflow)]
      (when-let [reason (workflow-verdict repo sha workflow)]
        (abort! (str reason " (" workflow " @ " sha ")"))))
    (println "CI green for" sha)))
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS, including every pre-existing `verify-ci!` case. The "could not query CI status" case now arrives through `workflow-verdict`, so its message still contains that text.

- [ ] **Step 5: Lint and commit**

```bash
clj-kondo --lint src spec --fail-level error
git add clj/src/cleancoders/build/release.clj clj/spec/cleancoders/build/release_spec.clj
git commit -m "feat: gate a release on every named CI workflow, not just one"
```

---

### Task 9: Signed annotated tags carrying the digests

**Files:**
- Modify: `clj/src/cleancoders/build/release.clj`
- Test: `clj/spec/cleancoders/build/release_spec.clj`

**Interfaces:**
- Consumes: nothing new
- Produces: `(release/tag-message version sha artifacts)` → string; `(release/tag! version message)` → nil. `tag!` now takes two arguments.

- [ ] **Step 1: Write the failing test**

Replace the existing `tag!` context in `release_spec.clj` with:

```clojure
          (context "tag-message"
            (with artifacts [{:name "bucket-2.14.0.jar" :digest "1f3a"}
                             {:name "bucket-2.14.0.pom" :digest "8c02"}])

            (it "starts with the version, which git shows as the tag subject"
                (should-start-with "4.2.1" (sut/tag-message "4.2.1" "abc123" @artifacts)))

            (it "records the commit and every artifact digest, so a clone answers what shipped"
                (let [msg (sut/tag-message "4.2.1" "abc123" @artifacts)]
                  (should-contain "abc123" msg)
                  (should-contain "bucket-2.14.0.jar" msg)
                  (should-contain "sha256:1f3a" msg)
                  (should-contain "bucket-2.14.0.pom" msg)
                  (should-contain "sha256:8c02" msg))))

          (context "tag!"
            (before (reset! commands []))

            (it "creates a signed annotated tag and pushes it"
                (should-be-nil
                 (capturing #(with-redefs [shell/sh (stub-sh {})] (sut/tag! "4.2.1" "4.2.1\n\nmessage"))))
                (should= ["git" "tag" "-s" "-a" "4.2.1" "-m" "4.2.1\n\nmessage"] (first @commands))
                (should= ["git" "push" "origin" "refs/tags/4.2.1"] (second @commands)))

            (it "aborts when git tag fails"
                (should-contain "already exists"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "tag"] {:exit 128 :out "" :err "already exists"}})]
                                              (sut/tag! "4.2.1" "msg")))))

            (it "aborts when the tag push fails"
                (should-contain "rejected"
                                (capturing #(with-redefs [shell/sh (stub-sh {["git" "push"] {:exit 1 :out "" :err "rejected"}})]
                                              (sut/tag! "4.2.1" "msg")))))

            (it "states the release is already live, and repairs with a signed tag"
                (let [msg (capturing #(with-redefs [shell/sh (stub-sh {["git" "push"]       {:exit 1 :out "" :err "rejected"}
                                                                       ["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}})]
                                        (sut/tag! "4.2.1" "msg")))]
                  (should-contain "published 4.2.1" msg)
                  (should-contain "live on Clojars" msg)
                  (should-contain "git tag -s -a 4.2.1 abc123" msg)
                  (should-contain "git push origin refs/tags/4.2.1" msg)
                  (should-contain "rejected" msg)))

            (it "states the release is already live when git tag itself fails"
                (let [msg (capturing #(with-redefs [shell/sh (stub-sh {["git" "tag"]        {:exit 128 :out "" :err "already exists"}
                                                                       ["git" "rev-parse"] {:exit 0 :out "abc123\n" :err ""}})]
                                        (sut/tag! "4.2.1" "msg")))]
                  (should-contain "published 4.2.1" msg)
                  (should-contain "git tag -s -a 4.2.1 abc123" msg))))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — `tag!` takes one argument

- [ ] **Step 3: Write the implementation**

In `clj/src/cleancoders/build/release.clj`, add `tag-message` and rewrite `tag!` and
`tag-failure-message`:

```clojure
(defn tag-message
  "The annotated tag's message. The first line is the subject git displays;
   the digests follow so \"what bits did we ship\" is answerable from a clone
   alone, with no API call and no log retention window."
  [version sha artifacts]
  (str version "\n\n"
       "commit: " sha "\n"
       (str/join "\n" (map #(format "%s: sha256:%s" (:name %) (:digest %)) artifacts))
       "\n"))

(defn- tag-failure-message
  "tag! runs only after a successful publish, so any failure here means the
   artifact is already live and immutable and only the tag is missing. Say that
   explicitly -- a maintainer reading this mid-incident must not conclude the
   release failed and retry it."
  [version err]
  (str "published " version " but could not tag it.\n"
       "  The artifact is live on Clojars and cannot be republished. Only the\n"
       "  tag is missing; the release is otherwise complete. Finish it with:\n"
       "    git tag -s -a " version " " (released-sha) " -m \"" version "\"\n"
       "    git push origin refs/tags/" version "\n"
       "  git reported: " err))

(defn tag!
  "Creates and pushes a signed annotated tag. Signed because the tag is the
   release record and a lightweight tag is forgeable by anyone holding
   contents: write. Pushes an explicit refspec rather than --tags so only this
   tag moves, and checks the exit of both calls."
  [version message]
  (println "tagging" version)
  (let [{:keys [exit err]} (shell/sh "git" "tag" "-s" "-a" version "-m" message)]
    (when-not (zero? exit)
      (abort! (tag-failure-message version err))))
  (let [{:keys [exit err]} (shell/sh "git" "push" "origin" (str "refs/tags/" version))]
    (when-not (zero? exit)
      (abort! (tag-failure-message version err)))))
```

`deploy!` and `emergency-deploy!` will not compile against the new arity until Task 10.
That is expected; the specs for those two contexts fail at this point. Fix them in
Task 10, not by weakening this task.

- [ ] **Step 4: Run the tests**

Run: `clojure -M:test:spec`
Expected: the new `tag!` and `tag-message` cases PASS; the `deploy!` and
`emergency-deploy!` contexts fail on arity. Do not commit yet — Task 10 finishes the
sequence. Move straight on.

---

### Task 10: The new gates in `deploy!` and `emergency-deploy!`

**Files:**
- Modify: `clj/src/cleancoders/build/release.clj`
- Test: `clj/spec/cleancoders/build/release_spec.clj`

**Interfaces:**
- Consumes: `sign/configured?`, `publish-verify/verify!`, `summary/render`, `summary/emergency-banner`, `summary/emit!`, `release/tag-message`
- Produces:
  `(release/assert-signing-key!)`;
  `(release/sign! thunk)`;
  `(release/verify-published! artifacts)`;
  `(release/record! {:version :sha :artifacts})`;
  `(release/deploy! {:repo :ci-workflow :version :jar! :sign! :publish! :artifacts})` where `:artifacts` is a zero-arg thunk called after `jar!`;
  `(release/emergency-deploy! {:version :jar! :sign! :publish! :artifacts :emergency-var})`

- [ ] **Step 1: Write the failing test**

Replace the `deploy!` and `emergency-deploy!` contexts in `release_spec.clj` with the
following, and add `[cleancoders.build.publish-verify :as pv]`, `[cleancoders.build.sign :as sign]`,
`[cleancoders.build.summary :as summary]` to the `:require`:

```clojure
          (context "assert-signing-key!"
            (it "proceeds when a key is configured"
                (should-be-nil (capturing #(with-redefs [sign/configured? (constantly true)]
                                             (sut/assert-signing-key!)))))

            (it "aborts naming both variables and says nothing was built"
                (let [msg (capturing #(with-redefs [sign/configured? (constantly false)]
                                        (sut/assert-signing-key!)))]
                  (should-contain "GPG_PRIVATE_KEY" msg)
                  (should-contain "GPG_PASSPHRASE" msg)
                  (should-contain "clojars environment" msg)
                  (should-contain "no release occurred" msg))))

          (context "sign!"
            (it "returns the thunk's value when signing succeeds"
                (should= [:asc] (capturing-value #(sut/sign! (constantly [:asc])))))

            (it "aborts with the reason when signing throws, before anything is published"
                (should-contain "could not sign target/bucket-2.14.0.jar"
                                (capturing #(sut/sign! (fn [] (throw (ex-info "could not sign target/bucket-2.14.0.jar" {}))))))))

          (context "verify-published!"
            (it "verifies every artifact that carries a url"
                (let [checked (atom [])]
                  (should-be-nil
                   (capturing #(with-redefs [pv/verify! (fn [opts] (swap! checked conj (:url opts)) nil)]
                                 (sut/verify-published! "4.2.1"
                                                        [{:name "a.jar" :digest "1f3a" :url "https://clojars/a.jar"}
                                                         {:name "a.pom" :digest "8c02"}]))))
                  (should= ["https://clojars/a.jar"] @checked)))

            (it "passes the local digest to the verifier"
                (let [captured (atom nil)]
                  (capturing #(with-redefs [pv/verify! (fn [opts] (reset! captured opts) nil)]
                                (sut/verify-published! "4.2.1"
                                                       [{:name "a.jar" :digest "1f3a" :url "https://clojars/a.jar"}])))
                  (should= "1f3a" (:digest @captured))))

            (it "aborts saying the artifact is live and gives the manual check"
                (let [msg (capturing #(with-redefs [pv/verify!   (constantly "digest mismatch: Clojars has sha256:bbbb")
                                                    sut/head-sha (constantly "abc123")]
                                        (sut/verify-published! "2.14.0"
                                                               [{:name "bucket-2.14.0.jar" :digest "1f3a"
                                                                 :url  "https://clojars/bucket-2.14.0.jar"}])))]
                  (should-contain "digest mismatch" msg)
                  (should-contain "published 2.14.0" msg)
                  (should-contain "cannot be republished" msg)
                  (should-contain "https://clojars/bucket-2.14.0.jar" msg)
                  (should-contain "1f3a" msg))))

          (context "record!"
            (it "emits the rendered summary"
                (let [emitted (atom nil)]
                  (with-redefs [summary/emit! (fn [text] (reset! emitted text))]
                    (sut/record! {:version   "2.14.0"
                                  :sha       "abc123"
                                  :artifacts [{:name "bucket-2.14.0.jar" :digest "1f3a"}]}))
                  (should-contain "2.14.0" @emitted)
                  (should-contain "abc123" @emitted)
                  (should-contain "1f3a" @emitted))))

          (context "deploy!"
            (it "runs every gate in order: key, CI, tag check, jar, sign, publish, verify, record, tag"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!           (fn [] (swap! calls conj :assert-ci))
                                sut/assert-signing-key!  (fn [] (swap! calls conj :assert-signing-key))
                                sut/verify-ci!           (fn [_] (swap! calls conj :verify-ci))
                                sut/assert-untagged!     (fn [_] (swap! calls conj :assert-untagged))
                                sut/verify-published!    (fn [_ _] (swap! calls conj :verify-published))
                                sut/record!              (fn [_] (swap! calls conj :record))
                                sut/head-sha             (constantly "abc123")
                                sut/tag!                 (fn [_ _] (swap! calls conj :tag))]
                    (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                  :ci-workflow "build.yml"
                                  :version     "4.2.1"
                                  :jar!        #(swap! calls conj :jar)
                                  :sign!       #(swap! calls conj :sign)
                                  :publish!    #(swap! calls conj :publish)
                                  :artifacts   (fn [] [])}))
                  (should= [:assert-ci :assert-signing-key :verify-ci :assert-untagged
                            :jar :sign :publish :verify-published :record :tag]
                           @calls)))

            (it "checks for the signing key before spending CI queries or building"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!    (constantly nil)
                                sign/configured?  (constantly false)
                                sut/verify-ci!    (fn [_] (swap! calls conj :verify-ci))]
                    (capturing #(sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                              :ci-workflow "build.yml"
                                              :version     "4.2.1"
                                              :jar!        #(swap! calls conj :jar)
                                              :sign!       (constantly nil)
                                              :publish!    #(swap! calls conj :publish)
                                              :artifacts   (fn [] [])})))
                  (should= [] @calls)))

            (it "reads the artifact list after the jar is built, not before"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/verify-published!   (constantly nil)
                                sut/record!             (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                sut/tag!                (fn [_ _] nil)]
                    (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                  :ci-workflow "build.yml"
                                  :version     "4.2.1"
                                  :jar!        #(swap! calls conj :jar)
                                  :sign!       (constantly nil)
                                  :publish!    (constantly nil)
                                  :artifacts   (fn [] (swap! calls conj :artifacts) [])}))
                  (should= [:jar :artifacts] @calls)))

            (it "puts the digests in the tag message"
                (let [tagged (atom nil)]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/verify-published!   (constantly nil)
                                sut/record!             (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                sut/tag!                (fn [_ message] (reset! tagged message))]
                    (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                  :ci-workflow "build.yml"
                                  :version     "4.2.1"
                                  :jar!        (constantly nil)
                                  :sign!       (constantly nil)
                                  :publish!    (constantly nil)
                                  :artifacts   (fn [] [{:name "wire-4.2.1.jar" :digest "1f3a"}])}))
                  (should-contain "wire-4.2.1.jar" @tagged)
                  (should-contain "sha256:1f3a" @tagged)))

            (it "does not publish when signing fails"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/tag!                (fn [_ _] (swap! calls conj :tag))]
                    (capturing #(sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                              :ci-workflow "build.yml"
                                              :version     "4.2.1"
                                              :jar!        (constantly nil)
                                              :sign!       (fn [] (throw (ex-info "no secret key" {})))
                                              :publish!    #(swap! calls conj :publish)
                                              :artifacts   (fn [] [])})))
                  (should= [] @calls)))

            (it "does not tag when publishing throws"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/tag!                (fn [_ _] (swap! calls conj :tag))]
                    (should-throw Exception
                                  (sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                                :ci-workflow "build.yml"
                                                :version     "4.2.1"
                                                :jar!        (constantly nil)
                                                :sign!       (constantly nil)
                                                :publish!    #(throw (ex-info "clojars said no" {}))
                                                :artifacts   (fn [] [])})))
                  (should= [] @calls)))

            (it "does not tag when post-publish verification fails"
                (let [calls (atom [])]
                  (with-redefs [sut/assert-ci!          (constantly nil)
                                sut/assert-signing-key! (constantly nil)
                                sut/verify-ci!          (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                pv/verify!              (constantly "digest mismatch: Clojars has sha256:bbbb")
                                sut/tag!                (fn [_ _] (swap! calls conj :tag))]
                    (capturing #(sut/deploy! {:repo        "cleancoders/c3kit-wire"
                                              :ci-workflow "build.yml"
                                              :version     "4.2.1"
                                              :jar!        (constantly nil)
                                              :sign!       (constantly nil)
                                              :publish!    (constantly nil)
                                              :artifacts   (fn [] [{:name "wire-4.2.1.jar" :digest "1f3a"
                                                                    :url  "https://clojars/wire-4.2.1.jar"}])})))
                  (should= [] @calls))))

          (context "emergency-deploy!"
            (it "refuses when the break-glass variable is unset"
                (let [calls (atom [])]
                  (should-contain "EMERGENCY_RELEASE"
                                  (capturing (fn [] (with-redefs [sut/getenv (constantly nil)]
                                                      (sut/emergency-deploy! {:version   "4.2.1"
                                                                              :jar!      #(swap! calls conj :jar)
                                                                              :sign!     (constantly nil)
                                                                              :publish!  #(swap! calls conj :publish)
                                                                              :artifacts (fn [] [])})))))
                  (should= [] @calls)))

            (it "refuses when the break-glass variable names a different version"
                (let [calls (atom [])]
                  (should-contain "EMERGENCY_RELEASE"
                                  (capturing (fn [] (with-redefs [sut/getenv (constantly "4.2.0")]
                                                      (sut/emergency-deploy! {:version   "4.2.1"
                                                                              :jar!      #(swap! calls conj :jar)
                                                                              :sign!     (constantly nil)
                                                                              :publish!  #(swap! calls conj :publish)
                                                                              :artifacts (fn [] [])})))))
                  (should= [] @calls)))

            (it "still requires a signing key: an emergency is no reason to ship unverifiable bytes"
                (let [calls (atom [])
                      msg   (capturing (fn [] (with-redefs [sut/getenv       (constantly "4.2.1")
                                                            sign/configured? (constantly false)]
                                                (sut/emergency-deploy! {:version   "4.2.1"
                                                                        :jar!      #(swap! calls conj :jar)
                                                                        :sign!     (constantly nil)
                                                                        :publish!  #(swap! calls conj :publish)
                                                                        :artifacts (fn [] [])}))))]
                  (should-contain "GPG_PRIVATE_KEY" msg)
                  (should= [] @calls)))

            (it "proceeds when the variable names the exact version, skipping only the CI check"
                (let [calls (atom [])]
                  (with-redefs [sut/getenv              (constantly "4.2.1")
                                sut/assert-signing-key! (fn [] (swap! calls conj :assert-signing-key))
                                sut/assert-clean-tree!  (fn [] (swap! calls conj :clean-tree))
                                sut/assert-untagged!    (fn [_] (swap! calls conj :assert-untagged))
                                sut/verify-published!   (fn [_ _] (swap! calls conj :verify-published))
                                sut/record!             (fn [_] (swap! calls conj :record))
                                sut/head-sha            (constantly "abc123")
                                sut/verify-ci!          (fn [_] (swap! calls conj :verify-ci))
                                summary/emit!           (constantly nil)
                                sut/tag!                (fn [_ _] (swap! calls conj :tag))]
                    (sut/emergency-deploy! {:version   "4.2.1"
                                            :jar!      #(swap! calls conj :jar)
                                            :sign!     #(swap! calls conj :sign)
                                            :publish!  #(swap! calls conj :publish)
                                            :artifacts (fn [] [])}))
                  (should= [:assert-signing-key :clean-tree :assert-untagged :jar :sign
                            :publish :verify-published :record :tag]
                           @calls)
                  (should-not-contain :verify-ci @calls)))

            (it "emits an audit banner naming the actor and the authorizing variable"
                (let [emitted (atom [])]
                  (with-redefs [sut/getenv              (fn [n] (if (= "GITHUB_ACTOR" n) "someone" "4.2.1"))
                                sut/assert-signing-key! (constantly nil)
                                sut/assert-clean-tree!  (constantly nil)
                                sut/assert-untagged!    (constantly nil)
                                sut/verify-published!   (constantly nil)
                                sut/record!             (constantly nil)
                                sut/head-sha            (constantly "abc123")
                                summary/emit!           (fn [text] (swap! emitted conj text))
                                sut/tag!                (fn [_ _] nil)]
                    (sut/emergency-deploy! {:version   "4.2.1"
                                            :jar!      (constantly nil)
                                            :sign!     (constantly nil)
                                            :publish!  (constantly nil)
                                            :artifacts (fn [] [])}))
                  (let [banner (first (filter #(re-find #"EMERGENCY" %) @emitted))]
                    (should-contain "someone" banner)
                    (should-contain "4.2.1" banner)
                    (should-contain "abc123" banner)
                    (should-contain "EMERGENCY_RELEASE" banner))))

            (it "names the default variable in the abort message"
                (should-contain "EMERGENCY_RELEASE=4.2.1"
                                (capturing (fn [] (with-redefs [sut/getenv (constantly nil)]
                                                    (sut/emergency-deploy! {:version   "4.2.1"
                                                                            :jar!      (constantly nil)
                                                                            :sign!     (constantly nil)
                                                                            :publish!  (constantly nil)
                                                                            :artifacts (fn [] [])}))))))

            (it "honors a custom :emergency-var in the abort message"
                (should-contain "C3KIT_EMERGENCY_RELEASE=4.2.1"
                                (capturing (fn [] (with-redefs [sut/getenv (constantly nil)]
                                                    (sut/emergency-deploy! {:version       "4.2.1"
                                                                            :emergency-var "C3KIT_EMERGENCY_RELEASE"
                                                                            :jar!          (constantly nil)
                                                                            :sign!         (constantly nil)
                                                                            :publish!      (constantly nil)
                                                                            :artifacts     (fn [] [])}))))))

            (it "falls back to the default variable when :emergency-var is blank"
                (let [looked (atom nil)
                      msg    (capturing (fn [] (with-redefs [sut/getenv (fn [n] (reset! looked n) nil)]
                                                 (sut/emergency-deploy! {:version       "4.2.1"
                                                                         :emergency-var ""
                                                                         :jar!          (constantly nil)
                                                                         :sign!         (constantly nil)
                                                                         :publish!      (constantly nil)
                                                                         :artifacts     (fn [] [])}))))]
                  (should= "EMERGENCY_RELEASE" @looked)
                  (should-contain "EMERGENCY_RELEASE=4.2.1" msg))))
```

Add this helper next to `capturing` at the top of the spec, because one new case needs
the thunk's return value rather than the abort message:

```clojure
(defn- capturing-value
  "Runs f with abort! captured, returning f's value."
  [f]
  (with-redefs [sut/abort! (fn [& msg] (throw (ex-info (cstr/join " " msg) {:aborted true})))]
    (f)))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — `No such var: sut/assert-signing-key!`

- [ ] **Step 3: Write the implementation**

In `clj/src/cleancoders/build/release.clj`, extend the `:require` with
`[cleancoders.build.publish-verify :as publish-verify]`, `[cleancoders.build.sign :as sign]`,
`[cleancoders.build.summary :as summary]`, and add:

```clojure
(defn assert-signing-key!
  "Aborts unless a signing key is configured. Runs before verify-ci! and before
   anything is built: a missing key is a configuration mistake, and it should
   cost one line of output rather than a build and a failed publish."
  []
  (when-not (sign/configured?)
    (abort! (str "signing key not configured.\n"
                 "  deploy requires GPG_PRIVATE_KEY and GPG_PASSPHRASE in the\n"
                 "  clojars environment. See README \"Signing keys\".\n"
                 "  Nothing was built; no release occurred."))))

(defn sign!
  "Runs the caller's signing thunk, turning a signing failure into a clean
   ABORT. Signing happens before publish!, so aborting here ships nothing."
  [sign-thunk]
  (try
    (sign-thunk)
    (catch clojure.lang.ExceptionInfo e
      (abort! "signing failed:" (ex-message e)))))

(defn- publish-verify-failure-message
  "Like tag-failure-message: by the time verification runs the artifact is live
   and immutable, so the message must not read as \"the release failed, retry\"."
  [{:keys [name digest url]} reason version]
  (str "published " version " but could not verify it on Clojars.\n"
       "  " reason "\n"
       "  The artifact is live and cannot be republished. Check it by hand:\n"
       "    curl -fsSL " url " | shasum -a 256\n"
       "    expected: " digest "  (" name ")\n"
       "  If it matches, finish the release with:\n"
       "    git tag -s -a " version " " (released-sha) " -m \"" version "\"\n"
       "    git push origin refs/tags/" version))

(defn verify-published!
  "Re-fetches every artifact that has a :url and compares digests. Takes the
   version because the failure message must name it -- an artifact map does not
   carry one. Aborts before any tag exists, so an unverified artifact never
   gets one."
  [version artifacts]
  (doseq [{:keys [url digest] :as artifact} (filter :url artifacts)]
    (when-let [reason (publish-verify/verify! {:url url :digest digest})]
      (abort! (publish-verify-failure-message artifact reason version)))))

(defn record!
  "Writes the release's digests where they outlive the log."
  [{:keys [version sha artifacts]}]
  (summary/emit! (summary/render {:version version :commit sha :artifacts artifacts})))
```

Then the two entry points. Note the destructuring: the `:sign!` thunk binds to
`sign-thunk`, not `sign!`, because a local named `sign!` would shadow the function of
that name and the call would recurse into the thunk instead of wrapping it.

```clojure
(defn deploy!
  "The release path. Every gate that can fail cheaply runs before anything is
   built; tagging happens last so a failed or unverified publish leaves no tag
   pointing at a version nobody confirmed."
  [{:keys [repo ci-workflow version jar! publish! artifacts] sign-thunk :sign!}]
  (assert-ci!)
  (assert-signing-key!)
  (verify-ci! {:repo repo :ci-workflow ci-workflow})
  (assert-untagged! version)
  (jar!)
  (sign! sign-thunk)
  (publish!)
  (let [shipped (artifacts)
        sha     (head-sha)]
    (verify-published! version shipped)
    (record! {:version version :sha sha :artifacts shipped})
    (tag! version (tag-message version sha shipped))))

(defn emergency-deploy!
  "Break-glass release for when the release workflow itself cannot run.

   Skips verify-ci! deliberately -- the likeliest reason to need this is that CI
   results are unavailable. It does not skip signing: an emergency is not a
   reason to ship bytes a consumer cannot verify. Authorization requires naming
   the exact version so a stale exported variable cannot authorize a later
   release, and the banner leaves a record that outlives the log."
  [{:keys [version jar! publish! artifacts emergency-var] sign-thunk :sign!}]
  ;; not-empty, not a bare or: "" is truthy in Clojure, so a blank :emergency-var
  ;; would otherwise survive as the lookup key and print "requires =4.2.1".
  (let [emergency-var (or (not-empty emergency-var) default-emergency-var)]
    (when-not (emergency-authorized? (getenv emergency-var) version)
      (abort! (str "emergency release requires " emergency-var "=" version)))
    (assert-signing-key!)
    (assert-clean-tree!)
    (assert-untagged! version)
    (let [sha (head-sha)]
      (println "!!! EMERGENCY RELEASE - CI verification skipped !!!")
      (println "    version:" version)
      (println "    commit :" sha)
      (summary/emit! (summary/emergency-banner {:version       version
                                                :commit        sha
                                                :actor         (getenv "GITHUB_ACTOR")
                                                :emergency-var emergency-var}))
      (jar!)
      (sign! sign-thunk)
      (publish!)
      (let [shipped (artifacts)]
        (verify-published! version shipped)
        (record! {:version version :sha sha :artifacts shipped})
        (tag! version (tag-message version sha shipped))))))
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS, every context including the ones Task 9 left failing

- [ ] **Step 5: Lint and commit**

```bash
clj-kondo --lint src spec --fail-level error
git add clj/src/cleancoders/build/release.clj clj/spec/cleancoders/build/release_spec.clj
git commit -m "feat: sign, verify, and record every release before tagging it"
```

---

### Task 11: Wire it up in `api` and widen validation

**Files:**
- Modify: `clj/src/cleancoders/build/api.clj`
- Test: `clj/spec/cleancoders/build/api_spec.clj`

**Interfaces:**
- Consumes: `jar/sign-all!`, `jar/artifacts`, `release/deploy!`, `release/emergency-deploy!`
- Produces: `deploy` and `emergency-publish` supply `:sign!` and `:artifacts` thunks; `validate!` accepts a vector `:ci-workflow`

- [ ] **Step 1: Write the failing test**

Add to `clj/spec/cleancoders/build/api_spec.clj`. The `:require` needs
`[cleancoders.build.jar :as jar-flow]` and `[cleancoders.build.release :as release]` —
add whichever is missing, using those exact aliases, since the test bodies below redef
`jar-flow/…` and `release/…` vars. Match the file's existing helper names; if it has no
`capturing`, copy the one from `release_spec.clj`:

```clojure
          (context "validate! and :ci-workflow"
            (it "accepts a single workflow name"
                (should-be-nil (capturing #(sut/config {:group       "com.cleancoders.c3kit"
                                                        :lib-name    "bucket"
                                                        :repo        "cleancoders/c3kit-bucket"
                                                        :ci-workflow "test.yml"
                                                        :license-url "https://example.com/LICENSE"
                                                        :version-file version-file}))))

            (it "accepts a vector of workflow names"
                (should-be-nil (capturing #(sut/config {:group       "com.cleancoders.c3kit"
                                                        :lib-name    "bucket"
                                                        :repo        "cleancoders/c3kit-bucket"
                                                        :ci-workflow ["test.yml" "security.yml"]
                                                        :license-url "https://example.com/LICENSE"
                                                        :version-file version-file}))))

            (it "rejects an empty vector, which would gate on nothing"
                (should-contain ":ci-workflow"
                                (capturing #(sut/config {:group       "com.cleancoders.c3kit"
                                                         :lib-name    "bucket"
                                                         :repo        "cleancoders/c3kit-bucket"
                                                         :ci-workflow []
                                                         :license-url "https://example.com/LICENSE"
                                                         :version-file version-file}))))

            (it "rejects a vector containing a blank name, which would build a malformed api path"
                (should-contain ":ci-workflow"
                                (capturing #(sut/config {:group       "com.cleancoders.c3kit"
                                                         :lib-name    "bucket"
                                                         :repo        "cleancoders/c3kit-bucket"
                                                         :ci-workflow ["test.yml" "  "]
                                                         :license-url "https://example.com/LICENSE"
                                                         :version-file version-file})))))

          (context "deploy wiring"
            (it "supplies jar, sign, publish, and artifact thunks to release/deploy!"
                (let [captured (atom nil)
                      calls    (atom [])]
                  (with-redefs [release/deploy!   (fn [opts] (reset! captured opts))
                                jar-flow/build!   (fn [_] (swap! calls conj :build))
                                jar-flow/sign-all! (fn [_] (swap! calls conj :sign))
                                jar-flow/publish! (fn [_] (swap! calls conj :publish))
                                jar-flow/artifacts (fn [_] (swap! calls conj :artifacts) [])]
                    (sut/deploy {:group       "com.cleancoders.c3kit"
                                 :lib-name    "bucket"
                                 :repo        "cleancoders/c3kit-bucket"
                                 :ci-workflow ["test.yml" "security.yml"]
                                 :license-url "https://example.com/LICENSE"
                                 :version-file version-file})
                    ((:jar! @captured))
                    ((:sign! @captured))
                    ((:publish! @captured))
                    ((:artifacts @captured)))
                  (should= ["test.yml" "security.yml"] (:ci-workflow @captured))
                  (should= [:build :sign :publish :artifacts] @calls))))

          (context "emergency-publish wiring"
            (it "supplies the same thunks to release/emergency-deploy!"
                (let [captured (atom nil)
                      calls    (atom [])]
                  (with-redefs [release/emergency-deploy! (fn [opts] (reset! captured opts))
                                jar-flow/build!           (fn [_] (swap! calls conj :build))
                                jar-flow/sign-all!        (fn [_] (swap! calls conj :sign))
                                jar-flow/publish!         (fn [_] (swap! calls conj :publish))
                                jar-flow/artifacts        (fn [_] (swap! calls conj :artifacts) [])]
                    (sut/emergency-publish {:group        "com.cleancoders.c3kit"
                                            :lib-name     "bucket"
                                            :repo         "cleancoders/c3kit-bucket"
                                            :ci-workflow  "test.yml"
                                            :license-url  "https://example.com/LICENSE"
                                            :version-file version-file})
                    ((:jar! @captured))
                    ((:sign! @captured))
                    ((:publish! @captured))
                    ((:artifacts @captured)))
                  (should= [:build :sign :publish :artifacts] @calls))))
```

`version-file` is a temp file containing a version — reuse whatever the existing
`api_spec.clj` already uses for that; if it has none, add:

```clojure
(def version-file
  (let [file (doto (java.io.File/createTempFile "api-spec-version" ".txt") (.deleteOnExit))]
    (spit file "2.14.0\n")
    (.getAbsolutePath file)))
```

- [ ] **Step 2: Run it and watch it fail**

Run: `clojure -M:test:spec`
Expected: FAIL — a vector `:ci-workflow` passes validation today but `deploy` supplies no `:sign!` or `:artifacts`

- [ ] **Step 3: Write the implementation**

In `clj/src/cleancoders/build/api.clj`, replace `validate!`'s missing-key check so it
understands the widened key, and wire the new thunks:

```clojure
(defn- blank-workflow?
  "True when :ci-workflow gates on nothing: absent, blank, an empty vector, or
   a vector with a blank entry. A blank entry would be formatted into the API
   path, and a 404 there must not be mistakable for a passing gate."
  [ci-workflow]
  (if (coll? ci-workflow)
    (or (empty? ci-workflow) (some #(str/blank? (str %)) ci-workflow))
    (str/blank? (str ci-workflow))))

(defn- validate!
  "Aborts naming every missing key, and separately naming every key that is
   neither required nor optional. Configuration used to be code, where a typo
   was a compile error; as :exec-args data a misspelled key would otherwise
   sail through and build target/-2.14.0.jar, or (for a misspelled optional
   key) silently fall back to that key's default."
  [args]
  (let [missing (filter #(str/blank? (str (get args %))) (remove #{:ci-workflow} required-keys))
        missing (cond-> missing (blank-workflow? (:ci-workflow args)) (conj :ci-workflow))
        unknown (remove (into (set required-keys) optional-keys) (keys args))]
    (when (seq missing)
      (release/abort! "missing or blank :build :exec-args keys:"
                      (str/join ", " missing)))
    (when (seq unknown)
      (release/abort! "unknown :build :exec-args keys:"
                      (str/join ", " unknown)))))

(defn deploy
  "The release path. Refuses to run outside CI, requires a signing key, verifies
   every named workflow is green for this commit, signs what it publishes,
   verifies the published bytes, and tags only after all of that."
  [{:keys [repo ci-workflow] :as args}]
  (let [cfg (config args)]
    (release/deploy! {:repo        repo
                      :ci-workflow ci-workflow
                      :version     (:version cfg)
                      :jar!        #(jar-flow/build! cfg)
                      :sign!       #(jar-flow/sign-all! cfg)
                      :publish!    #(jar-flow/publish! cfg)
                      :artifacts   #(jar-flow/artifacts cfg)})))

(defn emergency-publish
  "Break glass. Skips the CI check; requires the break-glass variable to name
   the exact version being released. Does not skip signing."
  [{:keys [emergency-var] :as args}]
  (let [cfg (config args)]
    (release/emergency-deploy! {:version       (:version cfg)
                                :emergency-var emergency-var
                                :jar!          #(jar-flow/build! cfg)
                                :sign!         #(jar-flow/sign-all! cfg)
                                :publish!      #(jar-flow/publish! cfg)
                                :artifacts     #(jar-flow/artifacts cfg)})))
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `clojure -M:test:spec`
Expected: PASS. Pre-existing `validate!` cases still pass: a missing `:ci-workflow` is
still reported, now through `blank-workflow?`.

- [ ] **Step 5: Lint and commit**

```bash
clj-kondo --lint src spec --fail-level error
git add clj/src/cleancoders/build/api.clj clj/spec/cleancoders/build/api_spec.clj
git commit -m "feat: wire signing, sbom, and multi-workflow gating into the build api"
```

---

### Task 12: `release.yml` template — permissions, key import, attestations

**Files:**
- Modify: `README.md` (the release workflow section, lines ~189-257)

**Interfaces:** none — documentation

- [ ] **Step 1: Replace the workflow template**

In `README.md`, replace the `release.yml` code block with:

```yaml
name: Release

# Authorization comes from the `clojars` environment, not from this file.
# workflow_dispatch cannot be restricted by permission level, so anyone with
# write access can press Run workflow; the environment's required reviewers
# decide whether it proceeds, and its master-only deployment branch policy means
# a modified copy of this file on another ref cannot reach the secrets. Do not
# add an actor allowlist here -- a gate in a versioned file can be edited by
# anyone who can merge to master, and would read as protection while providing
# none.
on: workflow_dispatch

permissions:
  contents: write      # push the release tag
  actions: read        # verify-ci! reads the CI workflows' run history
  id-token: write      # OIDC token the attestation is bound to
  attestations: write  # write the provenance and SBOM attestations

jobs:
  release:
    runs-on: ubuntu-latest
    environment: clojars
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5
        with:
          fetch-depth: 0   # assert-untagged! and tag! need tag history

      - name: Set up JDK 21
        uses: actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95 # v5
        with:
          java-version: 21
          distribution: 'temurin'

      - name: Install Clojure CLI
        uses: DeLaGuardo/setup-clojure@3fe9b3ae632c6758d0b7757b0838606ef4287b08 # 13.4
        with:
          cli: 'latest'

      - name: Build and publish
        # Use `clojure`, not `clj` -- `clj` wraps rlwrap, which GitHub runners
        # don't have installed, and fails with "Please install rlwrap for
        # command editing or use \"clojure\" instead."
        #
        # The build imports the signing key itself, so there is no separate gpg
        # step here: key handling lives in the library where it is tested, and
        # an escape-hatch consumer with its own build script gets it too.
        run: clojure -T:build deploy
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          CLOJARS_USERNAME: ${{ secrets.CLOJARS_USERNAME }}
          CLOJARS_PASSWORD: ${{ secrets.CLOJARS_PASSWORD }}
          GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}

      - name: Attest build provenance
        uses: actions/attest-build-provenance@PROVENANCE_SHA # v3
        with:
          subject-path: target/*.jar

      - name: Attest the SBOM
        uses: actions/attest-sbom@SBOM_SHA # v3
        with:
          subject-path: target/*.jar
          sbom-path: target/*-cyclonedx.json
```

`PROVENANCE_SHA` and `SBOM_SHA` are not values — resolve them first and paste the real
40-character SHAs in, keeping the trailing `# v3` comment. Every `uses:` in this repo is
SHA-pinned with a version comment; a floating `@v3` in the release workflow would be the
one unpinned action in the most security-sensitive job here.

```bash
gh api /repos/actions/attest-build-provenance/git/ref/tags/v3 --jq .object.sha
gh api /repos/actions/attest-sbom/git/ref/tags/v3 --jq .object.sha
```

If either tag resolves to a tag object rather than a commit, follow it with
`gh api /repos/<owner>/<repo>/git/tags/<sha> --jq .object.sha`.

- [ ] **Step 2: Extend the load-bearing-details list**

After the workflow block, the README lists four load-bearing details. Add two:

```markdown
- **`id-token: write` and `attestations: write`** — without both, the attestation steps
  fail after the artifact is already live on Clojars. The OIDC token is what binds the
  provenance statement to this repository, workflow, and commit; a token-less run could
  only produce an unattributable signature.
- **Attestation runs after the publish, not before.** An attestation binds bytes to a
  builder, not to a moment in time, so a statement created seconds after the upload is
  exactly as strong as one created seconds before it. Splitting `deploy` to interleave
  the steps would move the gate sequence into YAML, where it is neither tested nor
  reusable by a consumer with its own build script.
```

- [ ] **Step 3: Verify the YAML parses and zizmor is happy**

Run, from the repo root:

```bash
yq '.' <(sed -n '/^name: Release$/,/sbom-path/p' README.md) > /dev/null && echo "yaml ok"
```

Expected: `yaml ok`. If `yq` reports a parse error, the extracted block boundaries are
wrong — widen the `sed` range rather than editing the YAML to suit it.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add attestation steps and signing secrets to the release template"
```

---

### Task 13: README — signing keys, verification, dependency risk, break-glass

**Files:**
- Modify: `README.md` (the `clojars` environment section and the `clj/` consuming section)

**Interfaces:** none — documentation

- [ ] **Step 1: Add `GPG_*` to the environment table**

In the `### The `clojars` environment` table, add a row:

```markdown
| **Secrets** `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`, added to the environment | The organization release key. `deploy` aborts before building without them, so an unsigned release is impossible rather than merely discouraged. |
```

- [ ] **Step 2: Add a "Signing keys" section**

Insert after the `clojars` environment section:

````markdown
### Signing keys

Every published artifact carries a detached GPG signature, and every release tag is
signed with the same key. One organization key covers all four libraries, so a consumer
verifying any c3kit artifact imports one key rather than four.

Generate it once, on a machine that is not a CI runner:

```bash
gpg --quick-generate-key "Clean Coders Release <release@cleancoders.com>" ed25519 sign never
gpg --quick-add-key <FINGERPRINT> cv25519 encr never   # optional; not used for signing
gpg --send-keys <FINGERPRINT>                          # publish the public half
```

Export only the signing subkey for CI — note the trailing `!`, which is what limits the
export to that subkey and leaves the primary key on the offline machine:

```bash
gpg --armor --export-secret-subkeys <SUBKEY_ID>! > release-subkey.asc
```

Add the contents of `release-subkey.asc` as `GPG_PRIVATE_KEY` and the passphrase as
`GPG_PASSPHRASE`, both on the **`clojars` environment** of each repository — never at
repository level, where every workflow could read them.

Rotation: generate a new subkey, publish it, update the two secrets in each repository,
and leave the old public key on the keyservers. Artifacts already published stay
verifiable against the key that signed them; revoking it would invalidate signatures on
releases that were never compromised.

### Verifying a release

Anyone can verify a published artifact without trusting Clojars:

```bash
# Fetch the artifact and its signature
V=2.14.0
curl -fsSLO https://repo.clojars.org/com/cleancoders/c3kit/bucket/$V/bucket-$V.jar
curl -fsSLO https://repo.clojars.org/com/cleancoders/c3kit/bucket/$V/bucket-$V.jar.asc

# 1. The key holder produced these bytes
gpg --recv-keys <ORG_KEY_FINGERPRINT>
gpg --verify bucket-$V.jar.asc bucket-$V.jar

# 2. This repository, workflow, and commit produced these bytes
gh attestation verify bucket-$V.jar --repo cleancoders/c3kit-bucket

# 3. What went into it
curl -fsSL https://repo.clojars.org/com/cleancoders/c3kit/bucket/$V/bucket-$V-cyclonedx.json | jq .
```

The two checks answer different questions and neither replaces the other. A signature
proves the key holder produced the bytes; an attestation proves which repository and
commit produced them.

The jar is byte-reproducible, so a third check is available: build the tag yourself and
compare digests.

```bash
git checkout $V && clojure -T:build jar
shasum -a 256 target/bucket-$V.jar   # must equal the digest in the tag message
git cat-file -p $V                   # the signed tag, with every artifact's digest
```
````

- [ ] **Step 3: Add explicit `:mvn/repos` and the residual-risk note**

In the "Consuming it" section, replace the `deps.edn` block with one that declares its
repositories, and add the note below it:

```clojure
;; deps.edn
:mvn/repos {"central" {:url "https://repo1.maven.org/maven2/"}
            "clojars" {:url "https://repo.clojars.org/"}}

:build {:extra-deps {io.github.cleancoders/github-actions
                     {:git/sha "<full 40-char sha>" :deps/root "clj"}}
        :ns-default cleancoders.build.api
        :exec-args  {:group       "com.cleancoders.c3kit"
                     :lib-name    "bucket"
                     :repo        "cleancoders/c3kit-bucket"
                     :ci-workflow ["test.yml" "security.yml"]
                     :license-url "https://github.com/cleancoders/c3kit-bucket/blob/master/LICENSE"}}
```

```markdown
**Declare `:mvn/repos` explicitly.** Left implicit, both Central and Clojars are live
resolution sources anyway; writing them down makes the set auditable and stops a
transitive dep from quietly adding a third.

That is a mitigation, not a fix. `deps.edn` pins versions, not digests, and
`tools.deps` has no lockfile with hashes, so nothing cryptographically constrains what
those coordinates resolve to at build time. What the release does provide is
after-the-fact detection: the SBOM records the SHA-256 of every dependency jar the
release was built against, so a later substitution upstream is discoverable by
comparing two releases' SBOMs. Combined with `clj-watson` in CI, that is the floor.
The rest is documented accepted risk.
```

Also update the `:exec-args` table row for `:ci-workflow`:

```markdown
| `:ci-workflow` | yes | — | one workflow filename, or a vector of them; all must be green |
```

- [ ] **Step 4: Pin down the break-glass variable**

In the section describing `emergency-publish`, add:

````markdown
The break-glass variable **must be a variable on the `clojars` environment**, never a
repository variable. A repository variable is settable and readable outside the
environment's reviewer gate, which would let the emergency path skip CI verification
with no approval — the exact thing the gate exists to prevent.

```bash
REPO=<owner>/<repo>

# Must be present on the environment
gh api /repos/$REPO/environments/clojars/variables --jq '.variables[].name'

# Must NOT be listed at repository level
gh variable list --repo $REPO
```

Every emergency release writes a banner to the job summary naming the version, the
commit, the actor, and the fact that CI verification was skipped, and writes the same
banner to stdout when run outside Actions. Signing is not skipped: an emergency is not
a reason to ship bytes a consumer cannot verify.
````

- [ ] **Step 5: Update the gate tables for escape-hatch consumers**

In the "For escape-hatch consumers" table, replace both rows:

```markdown
| entry point | gates, in order |
|---|---|
| `(deploy! {:repo :ci-workflow :version :jar! :sign! :publish! :artifacts})` | `assert-ci!` → `assert-signing-key!` → `verify-ci!` → `assert-untagged!` → `jar!` → `sign!` → `publish!` → `verify-published!` → `record!` → `tag!` |
| `(emergency-deploy! {:version :jar! :sign! :publish! :artifacts :emergency-var})` | break glass; skips `verify-ci!` only; requires the break-glass variable to name the exact version |
```

And add, after the paragraph about `:jar!` and `:publish!` being thunks:

```markdown
`:sign!` and `:artifacts` are zero-arg thunks too. `:sign!` signs whatever this consumer
publishes; `:artifacts` is called *after* `:jar!` and returns
`[{:name :path :digest :url}]` — the digest record for the summary and the tag message,
and the `:url` entries post-publish verification re-fetches. A two-jar consumer returns
two entries with urls; `release` never learns how many artifacts exist.
```

- [ ] **Step 6: Update the "Releasing" numbered list**

Replace the closing paragraph of that section with:

```markdown
The job verifies every named CI workflow succeeded for that exact commit, refuses a
version that is already tagged, refuses to run without a signing key, builds a
reproducible jar, generates and signs the SBOM, publishes, re-fetches the artifact from
Clojars and compares digests, records every digest in the job summary, and only then
pushes a signed annotated tag carrying those digests. A failed publish leaves no tag; so
does a publish whose bytes could not be verified.
```

- [ ] **Step 7: Add the branch-protection requirement**

In the `clojars` environment section, after the table:

```markdown
**Require signed commits on your release branch.** Settings → Branches → branch
protection rule for `master` → *Require signed commits*. The release tag is signed, but
a signed tag over unsigned commits is a weaker chain than it looks: anyone able to merge
can put unattributed commits under the signature.
```

- [ ] **Step 8: Commit**

```bash
git add README.md
git commit -m "docs: document signing keys, release verification, and dependency risk"
```

---

### Task 14: Full-suite verification

**Files:** none — verification only

- [ ] **Step 1: Run the whole suite**

```bash
cd clj && clojure -M:test:spec
```

Expected: every spec passes, zero failures, zero errors. Paste the summary line into the
commit or PR description.

- [ ] **Step 2: Lint**

```bash
cd clj && clj-kondo --lint src spec --fail-level error
```

Expected: no errors.

- [ ] **Step 3: Re-check reproducibility on a clean tree**

Run the Task 6 Step 5 command again. Expected: `:reproducible true`.

- [ ] **Step 4: Confirm the CVE scan still passes with the new dependency**

```bash
cd clj && clojure -M:clj-watson scan -p deps.edn --database-strategy github-advisory --suggest-fix
```

Expected: no findings against `org.clojure/data.json`. If there are, report them rather
than pinning around them silently.

- [ ] **Step 5: Verify nothing local was left behind**

```bash
git status --porcelain
```

Expected: empty. `clj/target` and `/tmp/selftest-repo` are build scratch; delete them if
present.

- [ ] **Step 6: Push the branch and open the PR**

The PR body should state: which of the nine findings each commit closes, the reproducible
build evidence from Step 3, and the one prerequisite for consumers — `GPG_PRIVATE_KEY`
and `GPG_PASSPHRASE` on the `clojars` environment before the next release.

---

## Coverage against the spec

| Spec section | Task |
|---|---|
| §1 deploy sequence | 10 |
| §2 reproducible jar (gap 7) | 6 |
| §3 signing (gap 1) | 3, 7 |
| §4 SBOM (gaps 5, 8) | 2, 7 |
| §5 publish verification (gap 4) | 4, 10 |
| §6 CI gate (gap 3) | 8, 11 |
| §7 attestations (gap 1) | 12 |
| §8 tags (gaps 2, 6) | 9, 13 |
| §9 job summary and audit trail (gaps 6, 9) | 5, 10, 13 |
| §10 documentation | 12, 13 |
| Testing | every task; 14 verifies the whole suite |
| Failure semantics | 9, 10 |
| Rollout | 13, 14 |
