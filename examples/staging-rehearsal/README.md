# staging-rehearsal

A ready-to-copy scaffold for exercising the release path in
[`cleancoders/github-actions`](../../README.md) end to end, without publishing anything
permanent.

`:repo-url` points both the upload and the post-publish verification at a directory on the
CI runner, so the "registry" ceases to exist when the job ends. Everything else is the real
path: the environment approval gate, the CI-green check, gpg import and signing, the SBOM,
the attestations, digest verification, and a real signed tag.

## Use it

```bash
gh repo create OWNER/staging-rehearsal --clone
cd staging-rehearsal
cp -R /path/to/github-actions/examples/staging-rehearsal/. .
```

Then replace `OWNER` and `<PIN_THE_COMMIT_UNDER_TEST>` in `deps.edn`, and follow
[docs/staging-rehearsal.md](../../docs/staging-rehearsal.md) for the environment setup,
the dispatch, and what to check.

The repository you create from this is meant to be deleted afterwards.

## Note on the workflows here

These live under `.github/workflows/` so `cp -R` lands them in the right place. GitHub only
registers workflows in a repository's *root* `.github/workflows/`, so they are inert in this
repository — but they are still audited by its own security scan, which is a feature: the
template gets the same checks a consumer's copy would.
