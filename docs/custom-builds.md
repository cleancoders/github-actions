# Custom builds (the escape hatch)

[← back to the README](../README.md)

## When you need one

`cleancoders.build.api` covers one artifact built from the default basis. Publishing more
than one artifact, or needing a non-default basis, means writing your own build script and
pointing `:ns-default` at it, consuming `cleancoders.build.jar` and
`cleancoders.build.release` as ordinary libraries.

This is the supported alternative, not a workaround — which is why `api` stays small. The
answer to a requirement it does not express is a local build script, not another config
key.

## The contract

A local build script gets the same gates `api` uses by calling `cleancoders.build.release`
directly with its own jar and publish logic.

| entry point | gates, in order |
|---|---|
| `(deploy! {:repo :ci-workflow :version :jar! :publish! :sign! :artifacts})` | `assert-ci!` → `assert-thunks!` → `assert-signing-key!`\* → `verify-ci!` → `assert-untagged!` → `jar!` → `sign!`\* → `publish!` → `artifacts`\* → `verify-published!`\* → `record!`\* → `tag!` |
| `(emergency-deploy! {:version :jar! :publish! :sign! :artifacts :emergency-var})` | break glass: the break-glass variable must name the exact version, then `assert-thunks!` → `assert-signing-key!`\* → **`assert-clean-tree!`** → `assert-untagged!` → the same `jar!` … `tag!` sequence. Skips `verify-ci!`, and only that — but **adds** `assert-clean-tree!`, which the normal path does not have |

\* runs only if you opted in — see below.

Every thunk is **zero-arg**. That is how a consumer with two artifacts reuses every gate:
one call to `deploy!`, whose `:publish!` thunk deploys both jars, so the gates run once for
the release as a whole and `release` never learns how a jar gets built.

## Required and optional

**`:jar!` and `:publish!` are required.** They have been part of this contract since its
first version.

**`:sign!` and `:artifacts` are optional.** They were added later, and a consumer pins this
library by `:git/sha` — so making them mandatory would mean a repo bumping that sha for an
unrelated fix could suddenly no longer release at all. Omit them and the release runs
exactly the gates it ran before they existed.

| Thunk | Omitted | Supplied |
|---|---|---|
| `:sign!` | Nothing is signed, **including the tag**; `assert-signing-key!` does not run; the log says the release is unsigned | Signs before publishing, and signs the tag; a missing signing key aborts before anything is built |
| `:artifacts` | No post-publish verification, no digest record, and the tag carries the version alone; the log says so | Verifies the published bytes, records digests in the job summary, and puts every digest in the tag message |

Both skips are announced in the log rather than silent, because a weaker release should be
visible to whoever reads it — not inferable from an absence.

Supplying one that is **not callable** is a different thing from omitting it: that is a
mistake in a build script, and it aborts early with the other pre-build gates. Unchecked, a
bad `:sign!` dies mid-release with a bare `Cannot invoke "clojure.lang.IFn.invoke()"`
*after* `jar!` has run, and a bad `:artifacts` dies the same way after the artifact is
already live.

### What `:artifacts` must return

A list of `{:name :path :digest :url}` maps — the digest record for the summary and the tag
message, and the `:url` entries that post-publish verification re-fetches. A two-jar
consumer returns two entries with urls; `release` never learns how many artifacts exist.

**If you supply it, it must return a non-empty list containing at least one entry with a
`:url`.** Post-publish verification filters on `:url`, so an empty list — or a list where
nothing carries one — would verify nothing, record an empty digest manifest, and still tag:
a release that passed every gate while proving nothing about its own bytes. Both entry
points reject that, with the same "the artifact is live, do not tag yet" message shape any
other post-publish failure gets.

Note the asymmetry with omitting it. Omitting is a consumer saying "I have not opted into
verification". Returning `[]` is a consumer *claiming* to have opted in while providing
nothing to check — so one is allowed and announced, the other aborts.

## A custom `:publish!` must upload the signatures

This is the sharpest edge in the escape hatch, because skipping it produces a *tagged,
"verified", unsigned-on-Clojars* release and every gate still passes.

`:sign!` writes detached `.asc` files next to the artifacts **locally**. Nothing about
writing them uploads them. `jar/publish!` uploads them only because it names them
explicitly:

```clojure
(aether/deploy (-> deploy
                    (dissoc :jar-file :pom-file)
                    (assoc :artifact-map (jar/artifact-map cfg))))
```

**Do not pass `:artifact-map` alongside `:jar-file`/`:pom-file`.** `aether/deploy` (from
`cemerick.pomegranate.aether`) merges `:artifact-map` with entries it builds itself from
`:jar-file` (under the bare coordinate key `[]`) and `:pom-file` (under
`[:extension "pom"]`). The pom collides with `artifact-map`'s own `[:extension "pom"]` key
and is harmlessly overwritten, but the jar's `[]` key is a *different* map key from
`artifact-map`'s `[:extension "jar"]` — even though both resolve to the same Maven artifact,
because `:extension` defaults to `"jar"`. Two distinct entries for one coordinate means the
jar gets uploaded twice in the same deploy: Clojars accepts the first PUT and 403s the
second as a non-SNAPSHOT redeploy. This is exactly what broke apron 3.2.0's release
(github.com/cleancoders/c3kit-apron/actions/runs/36616537755) before `jar/publish!` started
dissoc'ing `deploy`'s `:jar-file`/`:pom-file`. If your own `:publish!` calls `aether/deploy`
directly, dissoc them the same way, or build `:files` yourself instead of using
`:jar-file`/`:pom-file`/`:artifact-map`'s merge behavior at all.

A consumer that writes its own `:publish!` around `aether/deploy` without an
`:artifact-map` uploads the jar and the pom and nothing else. The signatures
stay on the build machine. Post-publish verification then re-fetches the jar, compares its
digest, matches — because the jar's *bytes* are fine — and the release tags. Consumers get
an artifact with no signature to verify, and the failure is invisible until someone tries.

So a custom `:publish!` **must** name the signature artifacts in its upload.
`jar/artifact-map` is the reference for the shape — a map of `[:extension …]` keys to file
paths:

```clojure
{[:extension "jar"]     jar-file
 [:extension "jar.asc"] (str jar-file ".asc")
 [:extension "pom"]     pom-file
 [:extension "pom.asc"] (str pom-file ".asc")}
```

**Never add an entry for the SBOM.** Clojars's deploy route matches uploaded filenames
against a fixed extension allowlist — `.pom`/`.jar`/`.sha1`/`.md5`/`.asc`/`.module`/`.sig`
(`clojars.routes.repo`, the `PUT` route's `:filename` regex) — with no `.json` anywhere in
it, classifier or not. Naming
`[:classifier "cyclonedx" :extension "json"] sbom-file` here, as an earlier version of this
doc suggested, is what 400'd apron 3.2.0's release. The SBOM is still built and still
attested (see [the SBOM](sbom.md)); it is simply never uploaded to Clojars, by `jar/publish!`
or by a custom one.

`jar/artifact-map` builds exactly the subset of that map which the config's flags say was
actually produced — it names no `.asc` without `:sign`. That matters because `aether/deploy`
fails on a path that does not exist, so naming a file nobody wrote turns a working publish
into a failed one. If you build the map by hand, apply the same rule.

`jar/artifact-map` is public precisely so a custom `:publish!` can call it or copy it
rather than re-derive the extension keys.

## The CI gate

`verify-ci!` asks `gh` for the newest run of **each named CI workflow** at the current
commit and requires `completed` + `success`. It needs `actions: read` and a `GH_TOKEN` in
the environment it runs in.

It is scoped to named workflows rather than the commit's check-runs on purpose: the release
run registers its own check-run against that same commit, so an all-check-runs-green query
would observe itself as `in_progress` and deadlock every release.

It also refuses to gate on **fewer** workflows than you named. An empty `:ci-workflow`, a
blank string, or a blank entry anywhere in a collection all abort before any shell call
runs. Do not "simplify" that to dropping blank entries — that turns a typo into a partial,
unannounced gate instead of a loud failure.
