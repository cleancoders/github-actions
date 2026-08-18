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

Release policy for libraries published to Clojars. It gates a publish on the commit's CI
result, keeps `deploy` to CI, verifies the published bytes, and tags only after all of that
succeeds. Nothing in it is specific to any one library — a consumer supplies its own group,
artifact name, and CI workflows as data.

Onboarding takes three things: the `deps.edn` alias below, a `release.yml`, and a `clojars`
environment. The alias alone gets you working local commands but no way to release — the
environment is what authorizes one.

**Already onboarded?** Bumping the pinned `:git/sha` is safe and changes nothing about how
you release. See [upgrading](docs/upgrading.md).

### Consuming it

A single-artifact library needs no build script — declare what it is as data:

```clojure
;; deps.edn
:mvn/repos {"central" {:url "https://repo1.maven.org/maven2/"}
            "clojars" {:url "https://repo.clojars.org/"}}

:build {:extra-deps {io.github.cleancoders/github-actions
                     {:git/sha "<full 40-char sha>" :deps/root "clj"}}
        :ns-default cleancoders.build.api
        :exec-args  {:group       "com.example"
                     :lib-name    "mylib"
                     :repo        "example/mylib"
                     :ci-workflow ["test.yml" "security.yml"]
                     :license-url "https://github.com/example/mylib/blob/master/LICENSE"}}
```

That gives you `clj -T:build` `clean`, `pom`, `jar`, `install`, `deploy`, and
`emergency-publish`. `tools.build` and `pomegranate` arrive transitively.

**Pin a full `:git/sha`, never the moving `v1` tag.** `v1` moves so the reusable workflows
can be consumed that way; pointing release logic at a moving ref would let a change here
silently alter how every consuming library publishes.

**Declare `:mvn/repos` explicitly.** Left implicit, both Central and Clojars are live
resolution sources anyway; writing them down makes the set auditable and stops a transitive
dep from quietly adding a third. That is a mitigation, not a fix — `deps.edn` pins versions,
not digests, and `tools.deps` has no lockfile with hashes, so nothing cryptographically
constrains what those coordinates resolve to at build time. What the release *can* provide
is after-the-fact detection; see [the SBOM](docs/sbom.md).

### Configuration

| `:exec-args` key | Required | Default | Notes |
|---|---|---|---|
| `:group` | yes | — | |
| `:lib-name` | yes | — | |
| `:repo` | yes | — | |
| `:ci-workflow` | yes | — | one workflow filename, or a vector of them; all must be green |
| `:license-url` | yes | — | |
| `:version-file` | no | `VERSION` | |
| `:emergency-var` | no | `EMERGENCY_RELEASE` | |
| `:sign` | no | `false` | sign the jar, pom, SBOM, and tag — [signing](docs/signing.md) |
| `:sbom` | no | `false` | generate and publish a CycloneDX SBOM — [the SBOM](docs/sbom.md) |
| `:repo-url` | no | Clojars | redirect uploads *and* verification elsewhere — [staging rehearsal](docs/staging-rehearsal.md) |

Missing or blank required keys abort before anything is built. So does an unrecognized key,
so a typo in an optional one is loud rather than silently ignored — `:sbomb true` aborts
rather than reading as "SBOM off".

### Opt-in features

`:sign` and `:sbom` are off by default, and deliberately so. Both arrived after the first
repositories onboarded, and both cost a consumer something to turn on: signing needs GPG
secrets on the release environment, and an SBOM hashes the whole resolved dependency closure
on every build. A consumer pins this library by sha, so defaulting them on would mean
bumping that sha for an unrelated fix could break a release.

What you get with no configuration at all: a reproducible jar, a CI gate on every named
workflow, post-publish digest verification against Clojars, a digest record in the job
summary and the release tag, and a refusal to release a version that is already tagged.

### Documentation

| Doc | What it covers |
|---|---|
| [Releasing](docs/releasing.md) | Cutting a release, the `release.yml` template, the `clojars` environment, emergency releases |
| [Signing](docs/signing.md) | What a signature proves, generating and exporting the key, installing the secrets, rotation |
| [The SBOM](docs/sbom.md) | What an SBOM is and why publish one, what ours contains, why it is deterministic |
| [Verifying a release](docs/verifying-a-release.md) | Consumer-side verification; and what to do when a release's own verification fails |
| [Custom builds](docs/custom-builds.md) | The escape hatch: multi-artifact repos, the thunk contract, the signature-upload trap |
| [Upgrading](docs/upgrading.md) | Bumping the pinned sha, and turning on each opt-in feature in the right order |
| [Staging rehearsal](docs/staging-rehearsal.md) | Running the whole release path against a throwaway repository, then deleting every trace |
