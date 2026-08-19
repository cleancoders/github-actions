# Staging rehearsal

[← back to the README](../README.md)

A way to run the entire release path — approval gate, CI check, signing, SBOM,
attestations, digest verification, signed tag — against a throwaway repository, then
delete every trace of it.

## Why not just rehearse on Clojars

Because a Clojars deploy cannot be undone.

- There is **no self-service deletion** on Clojars for any artifact, including
  `-SNAPSHOT` versions. Deletion is a manual admin request, evaluated case by case, and
  the [policy](https://github.com/clojars/clojars-web/wiki/About) reserves it for two
  grounds: malicious code, or credentials published by accident. "We were testing" is
  not one of them.
- A maintainer explicitly rejected a timed deletion window:
  [*"I would only be comfortable with an age period if there were a staging
  repository."*](https://github.com/clojars/clojars-web/discussions/818) Raised in 2017,
  confirmed unresolved in 2022, never implemented.
- SNAPSHOTs are freely *redeployable*, which is not the same as removable. Push
  `0.0.1-SNAPSHOT` once and it is in a public index permanently.

So the rehearsal keeps everything real except the one irreversible part. `:repo-url`
redirects **both** the upload and the post-publish verification at a directory on the CI
runner, which stops existing when the job ends. Both directions matter: redirecting only
the upload would publish to the staging directory and then verify against Clojars, where
the artifact does not exist — reporting "not readable" for a rehearsal that actually
worked.

## What it does and does not exercise

| Exercised for real | Not exercised |
|---|---|
| `workflow_dispatch` + environment reviewer gate | Clojars' own auth and upload endpoint |
| `verify-ci!` against real `gh api` run history | Clojars' eventual consistency and CDN |
| `assert-untagged!` reading real remote tags (its passing path) | Its *abort* path — re-dispatching an already-tagged version. One extra dispatch proves it |
| | A genuine digest **mismatch** (spec-covered only — you cannot corrupt the staged file between publish and verify without a hook) |
| Real gpg import, agent priming, detached signing, fingerprint threading | |
| Real jar build, normalization, SBOM generation | |
| `aether/deploy` with the full `:artifact-map` | |
| Post-publish re-fetch and digest compare (`curl` handles `file://` unchanged) | |
| OIDC provenance + SBOM attestations | |
| A real signed annotated tag, pushed to a real remote | |

## Prerequisite: the pinned commit has to be reachable

The scratch repo's CI fetches this library as a git dep, so the commit under test must be
pushed and reachable. A branch push is enough — no merge, no tag, nothing on `master`,
and it is reversible with `git push origin --delete <branch>`.

The scaffolded `deps.edn` carries a `:git/sha` for exactly this reason. **Re-pin it at the
commit you actually want to test** before every rehearsal:

```bash
cd /path/to/github-actions && git rev-parse HEAD
```

A stale pin is the quiet failure here: the rehearsal runs, passes, and proves something
about older code. No error, no warning. This is worth checking rather than assuming — a
`sed` that silently matched nothing left the pin one commit behind during the first real
run of this procedure.

## 1. Create the scratch repo

Use a **copy**, not a real repo. Migrating a real one leaves migration commits to revert
and briefly points its `deps.edn` at an unmerged branch.

```bash
gh repo create OWNER/staging-rehearsal --private --clone
cd staging-rehearsal
cp -R /path/to/github-actions/scratch/. .
```

Then edit `deps.edn`:

- replace `<PUSHED_SHA>` with the sha from above
- replace both `OWNER/staging-rehearsal` occurrences with your actual owner

## 2. Generate a throwaway signing key

**Do not use the organization release key.** The point is to exercise key handling, not
to expose the real key to a repo you are about to delete.

Follow [signing → generating the key](signing.md#generating-the-key) and
[exporting the subkey](signing.md#exporting-the-subkey-for-ci), with a throwaway
identity:

```bash
export GNUPGHOME=$(mktemp -d)    # keeps this out of your real keyring
gpg --quick-generate-key "Staging Rehearsal <staging@example.invalid>" ed25519 cert never
```

The export-verification step in that doc is worth following here rather than skipping —
a silently broken export is exactly the failure this rehearsal should catch, and catching
it here is the whole point.

## 3. Create the `staging` environment

Settings → Environments → New environment, named `staging`:

- **Required reviewers** — yourself is fine; the point is to confirm the gate fires.
- **Secrets** `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`, on the environment.
- **No** `CLOJARS_USERNAME` / `CLOJARS_PASSWORD`. A `file://` target needs no
  credentials, and leaving them unset proves the rehearsal cannot reach Clojars even by
  accident.

## 4. Get a green CI run at the release commit

`verify-ci!` gates on the newest run of each named workflow **at the exact commit being
released**, so the commit has to exist and its CI has to be green before you dispatch.

```bash
git add -A && git commit -m "seed staging rehearsal" && git push
gh run watch    # wait for test.yml to go green
```

**If the release workflow is missing from the Actions tab**, push a trivial change to
`release.yml`. A `workflow_dispatch`-only workflow in a fresh repository's first push is
not always registered; `test.yml` registers immediately because it has a `push` trigger.
Remember that this moves HEAD, so wait for CI to go green again before dispatching.

## 5. Dispatch and approve

Actions → **Release (staging rehearsal)** → Run workflow. Approve the `staging`
deployment when prompted.

## 6. What to check

```bash
# Six files, with :sign and :sbom both on
#   jar, pom, cyclonedx json, and a .asc for each
#   -> read the "Show what was published" step's output

# The digest record
#   -> read the job summary: every artifact with its sha256

# The tag carries those same digests
git fetch --tags && git cat-file -p 0.1.0

# The signature verifies against the throwaway key
#   -> the "Verify every signature independently" step does this in-job

# The attestation binds the jar to this repo and commit.
# The jar only ever existed on the runner, so pull it back down first --
# that is what the "Upload what was published" step is for.
gh run download --name staged-artifacts --dir /tmp/staged
JAR=$(find /tmp/staged -name '*.jar')

# --format json, because a bare `verify` exits 0 and prints nothing on success
gh attestation verify "$JAR" --repo OWNER/staging-rehearsal --format json

# the SBOM attestation is a separate statement, skipped unless named explicitly
gh attestation verify "$JAR" --repo OWNER/staging-rehearsal \
  --predicate-type https://cyclonedx.org/bom --format json
```

Verify the signatures and digests **off** the runner too, not just in the job: pull the
artifacts down, check each `.asc` against your own keyring, and compare every digest to the
ones in the signed tag. An in-job check proves the files were right where they were made; an
off-runner check proves they survived the trip.

Worth confirming specifically, because these are the behaviors this branch changed:

- The log says nothing about skipping signing or verification — both flags are on.
- Turning `:sign` off and re-running (with a bumped `VERSION`) prints
  `NOTE: this release is not signed` and publishes four files instead of six, with no
  `.asc` anywhere.
- Removing the `GPG_*` secrets with `:sign true` aborts **before anything is built**,
  naming both variables and offering the opt-out.

## 7. Failure paths worth provoking

Each of these costs one dispatch and proves a gate that specs can only assert in
isolation:

| To test | Do this | Expect |
|---|---|---|
| CI gate | make `test.yml` fail, push, dispatch | abort naming the workflow and sha; nothing built |
| Already-tagged | dispatch the same `VERSION` twice | `is already tagged; bump the version file` |
| Missing signing key | delete the two secrets, keep `:sign true` | abort before build, naming both variables |
| Empty CI gate | set `:ci-workflow []` | `a release cannot be gated on nothing` |
| Break glass | `emergency-publish` locally with a clean tree | banner to stdout, CI check skipped, clean-tree gate enforced |

## 8. What this procedure has already caught

Run once, in full, on 2026-08-19. It passed on the second attempt, and the first attempt is
the argument for doing it at all:

- **`attest-sbom`'s `sbom-path` does not expand globs**, while `attest-build-provenance`'s
  `subject-path` does. The workflow template shipped `target/*-cyclonedx.json` and died with
  `ENOENT: no such file or directory` — *after* publishing. On Clojars that would have been
  an unrepairable release. No spec would have found it; the action's own docs do not say it.
- **A `workflow_dispatch`-only workflow in a fresh repo's first push is not registered.**
  `gh workflow run` returned `HTTP 404 ... not found on the default branch` with the file
  sitting on `master`, valid.
- **`gh attestation verify` exits 0 and prints nothing** without `--format json`, and checks
  only provenance unless a predicate type is named. The consumer recipe in
  [verifying a release](verifying-a-release.md) had both problems.
- **An evidence-upload step placed after the attestations gets skipped** when they fail,
  leaving nothing to inspect at the moment you most need it.

Everything else held: the approval gate blocked the job, `verify-ci!` gated on the exact
commit, the signing subkey signed all three artifacts (verified off-runner against a local
keyring), the post-publish digest re-fetch matched, and the signed tag carried digests
identical to the published bytes.

## 9. Cleanup

```bash
gh repo delete OWNER/staging-rehearsal --yes   # takes the tag and attestations with it
rm -rf "$GNUPGHOME"                            # the throwaway key
rm -rf /path/to/github-actions/scratch         # the local scaffold
```

And if you do not want the branch published any longer:

```bash
git push origin --delete feat/release-signing-sbom
```

The staging repository itself needs no cleanup — it only ever existed inside a CI job.
