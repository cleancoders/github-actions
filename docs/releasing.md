# Releasing

[← back to the README](../README.md)

## Cutting a release

1. Open a PR bumping the version file and `CHANGES.md`.
2. Merge to `master` and wait for CI to go green. Because the version bump is part of the
   merged commit, the commit CI validated *is* the commit that gets released.
3. Actions → **Release** → **Run workflow**.
4. Approve the `clojars` deployment when prompted.

The job then, in order: verifies every named CI workflow succeeded for that exact commit,
refuses a version that is already tagged, builds a reproducible jar, publishes it,
re-fetches the artifact from Clojars and compares digests, records every digest in the job
summary, and only then pushes a signed annotated tag carrying those digests. With `:sign`
on it also requires a signing key up front and signs everything it publishes; with `:sbom`
on it generates and publishes an SBOM.

A failed publish leaves no tag. So does a publish whose bytes could not be verified — see
[verifying a release](verifying-a-release.md#for-maintainers-when-the-releases-own-verification-fails)
for what to do when that happens.

The current version in a repo is already tagged, so the first release from a newly
onboarded library must bump the version file.

**Never rehearsed this before?** A Clojars deploy is permanent — there is no
self-service deletion for any version, SNAPSHOT included. See
[staging rehearsal](staging-rehearsal.md) for how to exercise the whole path against a
throwaway repository first.

## The release workflow

Copy this into the consumer as `.github/workflows/release.yml`. It needs no per-repo edits
to name that repo's CI workflows — those come from `:ci-workflow` in `deps.edn`, not from
this file. Change only the `setup-java` version if the repo builds on a different JDK, and
the third-party pins if the repo standardizes on other ones. Keep every pin SHA-locked with
a trailing version comment, and keep `cli:` pinned to an exact version rather than
`latest`.

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

jobs:
  release:
    runs-on: ubuntu-latest
    environment: clojars
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0   # assert-untagged! and tag! need tag history

      - name: Set up JDK 21
        uses: actions/setup-java@0f481fcb613427c0f801b606911222b5b6f3083a # v5
        with:
          java-version: 21
          distribution: 'temurin'

      - name: Install Clojure CLI
        uses: DeLaGuardo/setup-clojure@4c7a6f613e5089821bb3bb2a33a3ee115578580d # v13.6.1 (node24)
        with:
          # Pinned, not 'latest'. The generated pom inherits its Clojure version
          # from the installed CLI's root deps.edn, and that pom is packaged
          # inside the jar -- so the artifact's digest is a function of this
          # version. 'latest' would silently change what a release produces.
          cli: '1.12.4.1618'

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
- **`clojure`, not `clj`** — the `clj` wrapper needs `rlwrap`, which GitHub runners lack.
  `clj -T:build deploy` fails there with `Please install rlwrap for command editing or use
  "clojure" instead.` and exit 1.
- **`environment: clojars` at job level** — this is what makes the approval gate cover
  every step. The Clojars secrets are scoped to that environment, so no other workflow in
  the repo can read them.
- **No actor allowlist.** `workflow_dispatch` cannot be restricted by permission level, so
  anyone with write access can press Run workflow. The environment decides whether it
  proceeds. An `if: github.actor == …` here would read as protection while providing none,
  because whoever can merge to master can edit it.

### Adding signing

If you set `:sign true` (see [signing](signing.md)), add the two key secrets to the
publish step's `env`:

```yaml
          GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
```

There is no separate `gpg` step. The build imports the key itself, so key handling lives
in the library where it is tested — and an escape-hatch consumer with its own build script
gets it too.

### Adding attestations

Attestations are what prove *which repository and commit* built an artifact, as distinct
from who signed it. They need two more permissions and one or two more steps.

```yaml
permissions:
  contents: write
  actions: read
  id-token: write      # OIDC token the attestation is bound to
  attestations: write  # write the provenance and SBOM attestations
```

```yaml
      - name: Attest build provenance
        uses: actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a # v3
        with:
          subject-path: target/*.jar

      # Only with :sbom true -- without it there is no cyclonedx file to attest
      # and this step fails, after the artifact is already live on Clojars.
      - name: Attest the SBOM
        uses: actions/attest-sbom@4651f806c01d8637787e274ac3bdf724ef169f34 # v3
        with:
          subject-path: target/*.jar
          sbom-path: target/*-cyclonedx.json
```

Two things to get right:

- **Both `id-token: write` and `attestations: write`, or neither.** Without both, the
  attestation steps fail *after* the artifact is already live on Clojars. The OIDC token is
  what binds the provenance statement to this repository, workflow, and commit; a
  token-less run could only produce an unattributable signature.
- **Attestation runs after the publish, not before.** An attestation binds bytes to a
  builder, not to a moment in time, so a statement created seconds after the upload is
  exactly as strong as one created seconds before. Splitting `deploy` to interleave the
  steps would move the gate sequence into YAML, where it is neither tested nor reusable by
  a consumer with its own build script.

## The `clojars` environment

The workflow is inert without this — it is where release authority actually lives. Set it
up under **Settings → Environments → New environment**, named `clojars`:

| Setting | Why |
|---|---|
| **Required reviewers** | Who may authorize a release. This is the actual access-control decision; the workflow file cannot make it. |
| **Deployment branch policy**, limited to your release branch | A modified copy of `release.yml` on another ref cannot reach the secrets. |
| **Secrets** `CLOJARS_USERNAME` and `CLOJARS_PASSWORD`, on the environment | Scoped to this environment, so no other workflow in the repo can read them. |
| **Secrets** `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`, on the environment | Only with `:sign true`. `deploy` then aborts before building without them, so an unsigned release from a signing repo is impossible rather than merely discouraged. |

Use a Clojars **deploy token** scoped to the artifact, generated at
<https://clojars.org/tokens> — not an account password.

**Require signed commits on your release branch.** Settings → Branches → branch protection
rule for `master` → *Require signed commits*. The release tag is signed, but a signed tag
over unsigned commits is a weaker chain than it looks: anyone able to merge can put
unattributed commits under the signature.

Two properties are worth checking rather than assuming, because getting either wrong
silently removes the gate:

```bash
REPO=<owner>/<repo>

# Secrets must be on the environment, not the repo. Repo-level secrets are
# readable by every workflow, which defeats the whole arrangement.
gh api /repos/$REPO/environments/clojars/secrets --jq '.secrets[].name'
gh secret list --repo $REPO   # must NOT list the CLOJARS_* names

# The branch policy must be present and limited to your release branch.
gh api /repos/$REPO/environments/clojars/deployment-branch-policies --jq '.branch_policies[].name'
```

If you would rather script the setup than click through Settings, the same configuration
goes through `gh api -X PUT /repos/$REPO/environments/clojars` with a `reviewers` array of
`{"type": "User", "id": N}` entries; resolve a login to its id with
`gh api /users/<login> --jq .id`.

One choice to make deliberately: GitHub's `prevent_self_review` decides whether the person
who dispatched a release may also approve it. Leaving it off gives one-click releases at
the cost of a single account being able to complete one alone; turning it on requires a
second person for every release.

## Emergency releases

`clj -T:build emergency-publish` is the break-glass path for when the release workflow
itself cannot run. It skips CI verification — everything else still runs, and it adds one
gate the normal path does not have: **the working tree must be clean.**

That extra gate is not arbitrary. A break-glass release runs from someone's machine rather
than a CI runner, so "the commit" only means something if the bytes it builds came from
committed source. An uncommitted local change would let the release ship something no
commit, and no CI run, ever saw.

Signing is not additionally skipped. Where a repo signs at all, it signs here too: an
emergency is not a reason to ship bytes a consumer cannot verify.

The break-glass variable (`:emergency-var`, default `EMERGENCY_RELEASE`) **must be a
variable on the `clojars` environment**, never a repository variable. A repository variable
is settable and readable outside the environment's reviewer gate, which would let the
emergency path skip CI verification with no approval — the exact thing the gate exists to
prevent. It must name the exact version being released, so a stale exported variable cannot
authorize a later one.

```bash
REPO=<owner>/<repo>

# Must be present on the environment
gh api /repos/$REPO/environments/clojars/variables --jq '.variables[].name'

# Must NOT be listed at repository level
gh variable list --repo $REPO
```

Every emergency release writes a banner to the job summary naming the version, the commit,
the actor, and the fact that CI verification was skipped — and writes the same banner to
stdout when run outside Actions.
