# cleancoders/github-actions

Shared reusable GitHub Actions workflows for cleancoders repos.

## `security.yml` — reusable security-scan workflow

Runs six scanners. **Hard-fail** (block the caller): `clj-kondo`, `clj-holmes`,
`shellcheck`, `gitleaks`. **Advisory** (report, never block): `clj-watson`,
`semgrep`.

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

### gitleaks

Scans full history and honors a repo-local `.gitleaksignore`. Generate a baseline
per repo to suppress the pre-existing backlog (accepted risk); newly introduced
secrets fail CI.

### Versioning

Consumers pin `@v1`, a moving tag pointing at the latest good release. Retag `v1`
to publish an update to all consumers at once. Third-party actions inside the
workflow are SHA-pinned.
