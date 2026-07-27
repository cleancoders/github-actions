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

Onboarding a library takes three things: the `deps.edn` alias below, a
`release.yml`, and a `clojars` environment. The alias alone gets you working local
commands but no way to release — the environment is what authorizes one.

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
  contents: write   # push the release tag
  actions: read     # verify-ci! reads the CI workflow's run history

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
        run: clojure -T:build deploy
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          CLOJARS_USERNAME: ${{ secrets.CLOJARS_USERNAME }}
          CLOJARS_PASSWORD: ${{ secrets.CLOJARS_PASSWORD }}
```

Four details in there are load-bearing, not incidental:

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

### The `clojars` environment

The workflow is inert without this — it is where release authority actually lives.
It needs three things, which you can set up in the repo's
**Settings → Environments → New environment**, named `clojars`:

| Setting | Why |
|---|---|
| **Required reviewers** | Who may authorize a release. This is the actual access-control decision; the workflow file cannot make it. |
| **Deployment branch policy**, limited to your release branch | A modified copy of `release.yml` on another ref cannot reach the secrets. |
| **Secrets** `CLOJARS_USERNAME` and `CLOJARS_PASSWORD`, added to the environment | Scoped to this environment, so no other workflow in the repo can read them. |

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

### Releasing

1. Open a PR bumping the version file and `CHANGES.md`.
2. Merge to `master` and wait for CI to go green. Because the version bump is part of
   the merged commit, the commit CI validated *is* the commit that gets released.
3. Actions → **Release** → **Run workflow**.
4. Approve the `clojars` deployment when prompted.

The job verifies CI succeeded for that exact commit, refuses a version that is
already tagged, builds, publishes, and only then pushes the tag — so a failed publish
leaves no tag. The current version in each repo is already tagged, so the first
release from a newly onboarded library must bump the version file.

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
