# cleancoders/github-actions

Shared reusable GitHub Actions workflows for cleancoders repos.

## `security.yml` — reusable security-scan workflow

Runs seven scanners. **Hard-fail** (block the caller): `clj-kondo`,
`shellcheck`, `gitleaks`, `actionlint`. **Advisory by default** (report, never
block): `clj-watson`, `semgrep`, `zizmor` — each can be made blocking
per-consumer via the `clj-watson-blocking` / `semgrep-blocking` /
`zizmor-blocking` inputs.

**semgrep is the only Clojure detection engine.** It carries the 16 cleancoders
`cc-*` rules in `security-rules/semgrep/` and reads `.clj`, `.cljs`, and
`.cljc`.

`clj-holmes` was removed. It read only `.clj` — silently skipping `.cljs` and
`.cljc`, and rejecting reader conditionals outright — had been unmaintained
since October 2022, and produced three failures in its first week: exiting 3 on
zero findings under `-t sarif`, writing findings to a file so a red build gave
no reason, and crashing on a progress-bar integer overflow that blocked a
production deploy. Its unique detections are now `cc-read-string`,
`cc-clojure-xml-xxe`, `cc-weak-crypto`, and `cc-insecure-tls`, which catch 8 of
8 fixture cases against its 6 — it shipped rules for Blowfish and DESede and
matched neither. Rationale: `docs/superpowers/specs/2026-07-27-cwe-owasp-coverage-design.md`
(Revision 2).

### Usage

Pin the moving `@v1` tag:

```yaml
name: Security
on:
  pull_request: {}
  workflow_call: {}
jobs:
  security:
    uses: cleancoders/github-actions/.github/workflows/security.yml@v1
    with:
      shellcheck-dir: "./bin"     # optional; default "./bin"
      # src-paths: "src"          # optional; default "src/clj src/cljs src/cljc"
    secrets: inherit
```

### Inputs

| input | default | purpose |
|-------|---------|---------|
| `src-paths` | `"src/clj src/cljs src/cljc"` | Space-separated clj-kondo lint targets. Nonexistent paths are filtered out, so the default is safe for repos missing a source root. |
| `shellcheck-dir` | `"./bin"` | shellcheck scandir. The job self-skips when the directory is absent or empty (e.g. library repos with no `bin/`). |
| `clj-watson-blocking` | `false` | When `true`, clj-watson dependency-CVE findings fail the workflow. Default `false` = advisory (reported, never blocks). |
| `semgrep-blocking` | `false` | When `true`, semgrep findings fail the workflow. Default `false` = advisory (reported, never blocks). |
| `zizmor-blocking` | `false` | When `true`, zizmor Actions-security findings fail the workflow. Advisory by default because zizmor's defaults light up existing repos. |
| `extra-rules-dir` | `".security-rules"` | Consumer-supplied semgrep rules, added as an extra `--config`. Self-skips when the directory is absent. |
| `rules-ref` | `"v1"` | Ref of this repo to source the `cc-*` rules from. **Must match the ref you consume the workflow at** — a reusable workflow cannot determine its own ref, so consuming `@v2` or a SHA without setting this gets you `v1` rules. |
| `ignored-paths` | `""` | Paths semgrep must skip, e.g. deliberately-vulnerable fixtures. |

### Secrets

Both are optional; the jobs that use them self-skip or degrade when they are unset.

| secret | purpose |
|--------|---------|
| `private-git-ssh-key` | Deploy key for cloning private git dependencies while building the classpath. Only clj-kondo and clj-watson use it, and they skip SSH setup when it is unset. |
| `gh-api-token` | API token for zizmor's online audits, which resolve every repository a workflow references with `uses:`. Defaults to `GITHUB_TOKEN`, which reaches only the repository being scanned — so if a workflow calls a **private** reusable workflow, zizmor cannot resolve it and the job degrades to offline audits with a warning. Supply a token that can read every referenced repository to keep the online audits running. |

### Coverage

Scanner rows below are generated from rule metadata by
`bin/gen-coverage-matrix.sh` and checked in CI, so the table cannot claim a rule
that no longer exists. The manual-review rows — access control, insecure design,
and everything else no scanner reaches — live in the `clojure-security` plugin's
class index, because those two halves are maintained in different repos and each
is authoritative for its own.

<!-- BEGIN COVERAGE -->

| rule | class | CWE | OWASP 2025 | blocking |
|------|-------|-----|------------|----------|
| `cc-cljs-eval` | `cljs-dom-xss` | 94 | A05 | yes |
| `cc-cljs-innerhtml` | `cljs-dom-xss` | 79 | A05 | yes |
| `cc-clojure-xml-xxe` | `xxe` | 611 | A02 | no (triage) |
| `cc-dangerously-set-html` | `cljs-dom-xss` | 79 | A05 | yes |
| `cc-explain-data-response` | `spec-malli-leak` | 209 | A10 | yes |
| `cc-generic-catch` | `fail-open` | 636, 396 | A10 | no (triage) |
| `cc-hiccup-raw` | `hiccup-injection` | 79 | A05 | yes |
| `cc-insecure-tls` | `insecure-tls-verification` | 295 | A07 | yes |
| `cc-load-string` | `dynamic-eval` | 94 | A05 | yes |
| `cc-nippy-thaw` | `java-deserialization` | 502 | A08 | yes |
| `cc-path-traversal` | `path-traversal` | 22 | A01 | no (triage) |
| `cc-read-string` | `read-string-rce` | 94 | A05 | yes |
| `cc-shell-exec` | `command-injection` | 78, 77 | A05 | yes |
| `cc-snakeyaml-unsafe` | `java-deserialization` | 502 | A08 | yes |
| `cc-sql-string-concat` | `sql-injection` | 89 | A05 | yes |
| `cc-weak-crypto` | `weak-crypto` | 327, 328 | A04 | yes |

<!-- END COVERAGE -->

#### What this coverage does not claim

A coverage table that overstates is worse than none, so:

1. **No taint analysis anywhere.** Every scanned row is pattern matching. Neither
   semgrep OSS nor clj-holmes tracks dataflow, so a sink reached by an unusual
   path is missed. The table says "we look for this shape," not "we would catch
   this bug."
2. **semgrep cannot resolve namespace aliases.** Each rule enumerates the aliases
   it expects (`hu/`, `html/`, `hiccup.util/`, …). An unusual alias is a silent
   miss. `spec-fixtures/` exercises more than one alias per sink and
   `bin/test-rules.sh` fails if any stops matching, so the enumeration is
   test-guarded rather than aspirational — but it is still enumeration.
3. **`cc-weak-crypto` and `cc-insecure-tls` match algorithm names textually**
   (`pattern-regex`), because semgrep does not bind metavariables inside Clojure
   string literals. They can therefore fire inside a comment or an unrelated
   string. Weaker than the structural rules, but the thing being checked *is* a
   literal.
4. **OWASP A06 Insecure Design is uncovered.** It is a threat-modeling category.
5. **10 of 19 applicable CWE Top 25 entries depend on a manual
   `/security-audit` run** — access control above all. CI cannot invoke it.
   Expected cadence is once per release; nothing enforces that.
6. **`cc-path-traversal`, `cc-generic-catch`, and `cc-clojure-xml-xxe` do not
   block** (`severity: WARNING`). Without dataflow they cannot be precise enough
   to gate a build — `cc-clojure-xml-xxe` in particular fires on every XML parse
   because verifying that the factory was hardened requires tracking the object.
7. **Rules track `rules-ref`, default `v1`.** Consuming another ref without
   setting it gets v1 rules.

### gitleaks

Scans full history and honors a repo-local `.gitleaksignore`. Generate a baseline
per repo to suppress the pre-existing backlog (accepted risk); newly introduced
secrets fail CI.

### Versioning

Consumers pin `@v1`, a moving tag pointing at the latest good release. Retag `v1`
to publish an update to all consumers at once. Third-party actions inside the
workflow are SHA-pinned.

## `clj/` — shared release library

Release policy for libraries published to Clojars: gates a publish on the commit's
CI result, keeps `deploy` to CI, and tags only after a successful publish. Nothing
in it is specific to any one library — a consumer supplies its own group, artifact
name, and CI workflow as data.

Onboarding a library takes three things: the `deps.edn` alias below, a
`release.yml`, and a `clojars` environment. The alias alone gets you working local
commands but no way to release — the environment is what authorizes one.

### Consuming it

A single-artifact library needs no build script — declare what it is as data:

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

That gives you `clj -T:build` `clean`, `pom`, `jar`, `install`, `deploy`, and
`emergency-publish`. `tools.build` and `pomegranate` arrive transitively.

**Pin a full `:git/sha`, never the moving `v1` tag.** `v1` moves so the reusable
workflows can be consumed that way; pointing release logic at a moving ref would let
a change here silently alter how four libraries publish.

| `:exec-args` key | Required | Default | Notes |
|---|---|---|---|
| `:group` | yes | — | |
| `:lib-name` | yes | — | |
| `:repo` | yes | — | |
| `:ci-workflow` | yes | — | one workflow filename, or a vector of them; all must be green |
| `:license-url` | yes | — | |
| `:version-file` | no | `VERSION` | |
| `:emergency-var` | no | `EMERGENCY_RELEASE` | |

Missing or blank required keys abort before anything is built. So does an
unrecognized key, so a typo in an optional one is loud rather than silently
ignored.

### The release workflow

Copy this into the consumer as `.github/workflows/release.yml`, changing only the
`:ci-workflow` filename in the `actions: read` comment and the `setup-clojure` pin
if that repo's CI already uses a different one. Keep the pins SHA-locked with a
trailing version comment.

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
        uses: actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a # v3
        with:
          subject-path: target/*.jar

      - name: Attest the SBOM
        uses: actions/attest-sbom@4651f806c01d8637787e274ac3bdf724ef169f34 # v3
        with:
          subject-path: target/*.jar
          sbom-path: target/*-cyclonedx.json
```

Six details in there are load-bearing, not incidental:

- **`fetch-depth: 0`** — the default shallow clone has no tags, so `assert-untagged!`
  would see none and `tag!` would push into a history it cannot see.
- **`clojure`, not `clj`** — the `clj` wrapper needs `rlwrap`, which GitHub runners
  lack. `clj -T:build deploy` fails there with `Please install rlwrap for command
  editing or use "clojure" instead.` and exit 1.
- **`environment: clojars` at job level** — this is what makes the approval gate
  cover every step. The Clojars secrets are scoped to that environment, so no other
  workflow in the repo can read them.
- **No actor allowlist.** `workflow_dispatch` cannot be restricted by permission
  level, so anyone with write access can press Run workflow. The environment decides
  whether it proceeds. An `if: github.actor == …` here would read as protection while
  providing none, because whoever can merge to master can edit it.
- **`id-token: write` and `attestations: write`** — without both, the attestation steps
  fail after the artifact is already live on Clojars. The OIDC token is what binds the
  provenance statement to this repository, workflow, and commit; a token-less run could
  only produce an unattributable signature.
- **Attestation runs after the publish, not before.** An attestation binds bytes to a
  builder, not to a moment in time, so a statement created seconds after the upload is
  exactly as strong as one created seconds before it. Splitting `deploy` to interleave
  the steps would move the gate sequence into YAML, where it is neither tested nor
  reusable by a consumer with its own build script.

### The `clojars` environment

The workflow is inert without this — it is where release authority actually lives.
It needs four things, which you can set up in the repo's
**Settings → Environments → New environment**, named `clojars`:

| Setting | Why |
|---|---|
| **Required reviewers** | Who may authorize a release. This is the actual access-control decision; the workflow file cannot make it. |
| **Deployment branch policy**, limited to your release branch | A modified copy of `release.yml` on another ref cannot reach the secrets. |
| **Secrets** `CLOJARS_USERNAME` and `CLOJARS_PASSWORD`, added to the environment | Scoped to this environment, so no other workflow in the repo can read them. |
| **Secrets** `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`, added to the environment | The organization release key. `deploy` aborts before building without them, so an unsigned release is impossible rather than merely discouraged. |

**Require signed commits on your release branch.** Settings → Branches → branch
protection rule for `master` → *Require signed commits*. The release tag is signed, but
a signed tag over unsigned commits is a weaker chain than it looks: anyone able to merge
can put unattributed commits under the signature.

Use a Clojars **deploy token** scoped to the artifact, generated at
<https://clojars.org/tokens> — not an account password.

Two properties are worth checking rather than assuming, because getting either
wrong silently removes the gate:

```bash
REPO=<owner>/<repo>

# Secrets must be on the environment, not the repo. Repo-level secrets are
# readable by every workflow, which defeats the whole arrangement.
gh api /repos/$REPO/environments/clojars/secrets --jq '.secrets[].name'
gh secret list --repo $REPO   # must NOT list the CLOJARS_* names

# The branch policy must be present and limited to your release branch.
gh api /repos/$REPO/environments/clojars/deployment-branch-policies --jq '.branch_policies[].name'
```

If you would rather script the setup than click through Settings, the same
configuration goes through `gh api -X PUT /repos/$REPO/environments/clojars` with a
`reviewers` array of `{"type": "User", "id": N}` entries; resolve a login to its id
with `gh api /users/<login> --jq .id`.

One choice to make deliberately: GitHub's `prevent_self_review` decides whether the
person who dispatched a release may also approve it. Leaving it off gives one-click
releases at the cost of a single account being able to complete one alone; turning it
on requires a second person for every release.

### Signing keys

Every published artifact carries a detached GPG signature, and every release tag is
signed with the same key. One key per organization is the simplest arrangement that
works: a consumer verifying any of your artifacts imports one key rather than one per
library. Per-repository keys work too — the library reads the key from the environment
and does not care how many exist.

Generate it once, on a machine that is not a CI runner:

```bash
gpg --quick-generate-key "<YOUR_ORG> Release <releases@example.com>" ed25519 sign never
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

The jar is byte-reproducible — across machines, time zones, and JDK major versions, since
the manifest's `Build-Jdk-Spec` line is stripped during normalization precisely so a
rebuild on a different JDK still matches — so a third check is available: build the tag
yourself and compare digests.

```bash
git checkout $V && clojure -T:build jar
shasum -a 256 target/bucket-$V.jar   # must equal the digest in the tag message
git cat-file -p $V                   # the signed tag, with every artifact's digest
```

### Releasing

1. Open a PR bumping the version file and `CHANGES.md`.
2. Merge to `master` and wait for CI to go green. Because the version bump is part of
   the merged commit, the commit CI validated *is* the commit that gets released.
3. Actions → **Release** → **Run workflow**.
4. Approve the `clojars` deployment when prompted.

The job verifies every named CI workflow succeeded for that exact commit, refuses a
version that is already tagged, refuses to run without a signing key, builds a
reproducible jar, generates and signs the SBOM, publishes, re-fetches the artifact from
Clojars and compares digests, records every digest in the job summary, and only then
pushes a signed annotated tag carrying those digests. A failed publish leaves no tag; so
does a publish whose bytes could not be verified. The current version in each repo is
already tagged, so the first release from a newly onboarded library must bump the
version file.

### Emergency releases

`clj -T:build emergency-publish` is the break-glass path for when the release workflow
itself cannot run. It skips CI verification only — everything else, including signing,
still runs.

The break-glass variable (`:emergency-var`, default `EMERGENCY_RELEASE`) **must be a
variable on the `clojars` environment**, never a repository variable. A repository
variable is settable and readable outside the environment's reviewer gate, which would
let the emergency path skip CI verification with no approval — the exact thing the gate
exists to prevent.

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

### When your build does not fit

Publishing more than one artifact, or needing a non-default basis, means writing
your own build script and pointing `:ns-default` at it, consuming
`cleancoders.build.jar` and `cleancoders.build.release` as ordinary libraries.
`c3kit-wire` does exactly this: it ships two jars whose source sets and bases
differ.

This is the supported alternative, not a workaround — which is why
`cleancoders.build.api` stays small. The answer to a requirement it does not
express is a local build script, not another config key.

### For escape-hatch consumers

A local build script gets the same gates `api` uses, by calling
`cleancoders.build.release` directly with its own jar and publish logic:

| entry point | gates, in order |
|---|---|
| `(deploy! {:repo :ci-workflow :version :jar! :sign! :publish! :artifacts})` | `assert-ci!` → `assert-signing-key!` → `verify-ci!` → `assert-untagged!` → `jar!` → `sign!` → `publish!` → `verify-published!` → `record!` → `tag!` |
| `(emergency-deploy! {:version :jar! :sign! :publish! :artifacts :emergency-var})` | break glass; skips `verify-ci!` only; requires the break-glass variable to name the exact version |

`:jar!` and `:publish!` are **zero-arg thunks**. That is how a consumer with two
artifacts reuses every gate: one call to `deploy!`, whose `:publish!` thunk
deploys both jars, so the gates run once for the release as a whole and `release`
never learns how a jar gets built.

`:sign!` and `:artifacts` are zero-arg thunks too. `:sign!` signs whatever this consumer
publishes; `:artifacts` is called *after* `:jar!` and returns
`[{:name :path :digest :url}]` — the digest record for the summary and the tag message,
and the `:url` entries post-publish verification re-fetches. A two-jar consumer returns
two entries with urls; `release` never learns how many artifacts exist.

`verify-ci!` asks `gh` for the newest run of the **named CI workflow** at the
current commit and requires `completed` + `success`. It is scoped to a named
workflow rather than the commit's check-runs on purpose: the release run
registers its own check-run against that same commit, so an all-check-runs-green
query would observe itself as `in_progress` and deadlock every release. It
needs `actions: read` and a `GH_TOKEN` in the environment it runs in.

`c3kit-wire` is the live example of a consumer using this escape hatch.
