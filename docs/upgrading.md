# Upgrading an already-onboarded repository

[← back to the README](../README.md)

## Bumping the pinned sha is safe

**If your repo already releases through this library, bumping the pinned `:git/sha` changes
nothing about how you release.** Signing, the SBOM, and post-publish verification all
arrived after the first repositories onboarded, and all of them are opt-in. A `clojars`
environment holding only `CLOJARS_USERNAME` and `CLOJARS_PASSWORD` is still sufficient.

That is a deliberate constraint on this library: a consumer pins it by sha, so a sha bump
taken for an unrelated fix must not turn into a failed release. If you want the new
features you ask for them, in `deps.edn`, one at a time.

What you get for free on a sha bump, with no configuration:

- **Post-publish verification.** After publishing, the release re-fetches the artifact from
  Clojars and compares digests before tagging. No secrets, no config.
- **A digest record.** Every artifact's SHA-256 goes into the job summary and the release
  tag's message, so "what bits did we ship" is answerable from a clone alone.
- **A reproducible jar.** Entry order and timestamps are normalized, so two builds of the
  same source produce byte-identical jars.
- **Multi-workflow CI gating**, if you want it. `:ci-workflow` still accepts a single
  string and still gates exactly as before; it *also* accepts a vector now, where all named
  workflows must be green. Adopting `["test.yml" "security.yml"]` is an optional, separate
  decision.

## Turning on signing

Signing is the one feature with a setup cost, because it needs secrets that a repo
onboarded before it existed does not have. Do these in order.

1. **Add the two `GPG_*` secrets to the `clojars` environment first** — `GPG_PRIVATE_KEY`
   and `GPG_PASSPHRASE`, on the environment and never at repository level. See
   [signing](signing.md). If you are generating the key now, follow the export verification
   there rather than trusting that the export worked; a silently broken export fails
   *inside* a release.
2. **Add the two secrets to the publish step's `env`** in `release.yml`. See
   [releasing → adding signing](releasing.md#adding-signing).
3. **Then set `:sign true` in `:exec-args`.** In that order: with the flag set and the
   secrets missing, `deploy` aborts at the signing-key gate — safely, before anything is
   built, naming both variables — but it is a failed release attempt you did not need to
   have.

If a release does abort there, the fix is either to finish adding the secrets or to drop
`:sign` again. The abort message says both.

## Turning on the SBOM

1. **Set `:sbom true` in `:exec-args`.** No secrets required.
2. Optionally add the `attest-sbom` step to `release.yml` — see
   [releasing → adding attestations](releasing.md#adding-attestations).

Order matters in the other direction here: **do not add the `attest-sbom` step before
setting `:sbom true`.** Without the flag there is no `target/*-cyclonedx.json` for it to
read, so the step fails *after* the artifact is already live on Clojars.

## Turning on attestations

Attestations are workflow-level, not library-level, so they are independent of both flags —
though `attest-sbom` specifically needs `:sbom`. Add `id-token: write` and
`attestations: write` to `permissions:` and the attestation steps after the publish step;
see [releasing → adding attestations](releasing.md#adding-attestations). Without both
permissions the steps fail after the publish has already happened.

## If you have your own build script

A repo using the [escape hatch](custom-builds.md) needs no changes either: `:sign!` and
`:artifacts` are optional thunks, and a script that passes neither keeps releasing exactly
as it did. Supplying them is how that script opts in — and if you write your own
`:publish!`, read
[the signatures warning](custom-builds.md#a-custom-publish-must-upload-the-signatures)
before turning on signing.
