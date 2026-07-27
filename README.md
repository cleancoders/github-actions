# cleancoders/github-actions

Shared reusable GitHub Actions workflows for cleancoders repos.

## `security.yml` — reusable security-scan workflow

Runs six scanners. **Hard-fail** (block the caller): `clj-kondo`, `clj-holmes`,
`shellcheck`, `gitleaks`. **Advisory by default** (report, never block):
`clj-watson`, `semgrep` — each can be made blocking per-consumer via the
`clj-watson-blocking` / `semgrep-blocking` inputs.

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

### Consuming it

A single-artifact library needs no build script — declare what it is as data:

```clojure
;; deps.edn
:build {:extra-deps {io.github.cleancoders/github-actions
                     {:git/sha "<full 40-char sha>" :deps/root "clj"}}
        :ns-default cleancoders.build.api
        :exec-args  {:group       "com.cleancoders.c3kit"
                     :lib-name    "bucket"
                     :repo        "cleancoders/c3kit-bucket"
                     :ci-workflow "test.yml"
                     :license-url "https://github.com/cleancoders/c3kit-bucket/blob/master/LICENSE"}}
```

That gives you `clj -T:build` `clean`, `pom`, `jar`, `install`, `deploy`, and
`emergency-publish`. `tools.build` and `pomegranate` arrive transitively.

**Pin a full `:git/sha`, never the moving `v1` tag.** `v1` moves so the reusable
workflows can be consumed that way; pointing release logic at a moving ref would let
a change here silently alter how four libraries publish.

| `:exec-args` key | Required | Default |
|---|---|---|
| `:group` | yes | — |
| `:lib-name` | yes | — |
| `:repo` | yes | — |
| `:ci-workflow` | yes | — |
| `:license-url` | yes | — |
| `:version-file` | no | `VERSION` |
| `:emergency-var` | no | `EMERGENCY_RELEASE` |

Missing or blank required keys abort before anything is built.

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
| `(deploy! {:repo :ci-workflow :version :jar! :publish!})` | `assert-ci!` → `verify-ci!` → `assert-untagged!` → `jar!` → `publish!` → `tag!` |
| `(emergency-deploy! {:version :jar! :publish! :emergency-var})` | break glass; skips `verify-ci!`; requires the break-glass variable to name the exact version |

`:jar!` and `:publish!` are **zero-arg thunks**. That is how a consumer with two
artifacts reuses every gate: one call to `deploy!`, whose `:publish!` thunk
deploys both jars, so the gates run once for the release as a whole and `release`
never learns how a jar gets built.

`verify-ci!` asks `gh` for the newest run of the **named CI workflow** at the
current commit and requires `completed` + `success`. It is scoped to a named
workflow rather than the commit's check-runs on purpose: the release run
registers its own check-run against that same commit, so an all-check-runs-green
query would observe itself as `in_progress` and deadlock every release. It
needs `actions: read` and a `GH_TOKEN` in the environment it runs in.

`c3kit-wire` is the live example of a consumer using this escape hatch.
