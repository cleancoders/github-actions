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

Release policy for the c3kit libraries: gates a Clojars publish on the commit's
CI result, keeps `deploy` to CI, and tags only after a successful publish.

### Consuming it

```clojure
;; deps.edn
:build {:extra-deps  {io.github.cleancoders/github-actions
                      {:git/sha "<full 40-char sha>" :deps/root "clj"}}
        :ns-default  build
        :extra-paths ["dev"]}
```

`tools.build` and `pomegranate` arrive transitively — consumers do not declare them.

**Pin a full `:git/sha`, never the moving `v1` tag.** `v1` moves so the reusable
workflows can be consumed that way; pointing release logic at a moving ref would let
a change here silently alter how four libraries publish. A SHA is immutable, and
bumping it is a reviewable PR per consumer.

### `c3kit.build.release`

| fn | purpose |
|---|---|
| `(deploy! {:repo :ci-workflow :version :jar! :publish!})` | `assert-ci!` → `verify-ci!` → `assert-untagged!` → `jar!` → `publish!` → `tag!` |
| `(emergency-deploy! {:version :jar! :publish!})` | Break-glass. Skips `verify-ci!`; requires `C3KIT_EMERGENCY_RELEASE=<exact version>` |

`:jar!` and `:publish!` are zero-arg thunks, which is how wire reuses every gate
despite publishing two artifacts.

`verify-ci!` asks `gh` for the newest run of the named CI workflow at the current
commit and requires `completed` + `success`. It is scoped to a named workflow rather
than the commit's check-runs because the release run registers its own check-run
against the same commit — an all-check-runs-green query would observe itself as
`in_progress` and deadlock. It needs `actions: read` and a `GH_TOKEN`.

### `c3kit.build.jar`

The one-artifact flow: `config`, `clean!`, `pom!`, `build!`, `install!`, `publish!`.
Used by apron, bucket, and scaffold. wire supplies its own.
