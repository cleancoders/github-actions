# Verifying a release

[← back to the README](../README.md)

Two audiences here. The first half is for anyone consuming a published artifact who wants
to check it themselves. The second half is for a maintainer whose own release just failed
its verification step, which is a different and more urgent problem.

## For consumers

Anyone can verify a published artifact without trusting Clojars. There are three
independent checks, and they answer three different questions.

```bash
# Fetch the artifact and its signature
V=2.14.0
curl -fsSLO https://repo.clojars.org/com/example/mylib/$V/mylib-$V.jar
curl -fsSLO https://repo.clojars.org/com/example/mylib/$V/mylib-$V.jar.asc

# 1. The key holder produced these bytes
gpg --recv-keys <ORG_KEY_FINGERPRINT>
gpg --verify mylib-$V.jar.asc mylib-$V.jar

# 2. This repository, workflow, and commit produced these bytes
gh attestation verify mylib-$V.jar --repo example/mylib

# 3. What went into it
curl -fsSL https://repo.clojars.org/com/example/mylib/$V/mylib-$V-cyclonedx.json | jq .
```

Checks 1 and 2 are not substitutes for each other. A **signature** proves the key holder
produced the bytes — but a key can sign anything, including a jar built from uncommitted
code on someone's laptop. An **attestation** proves which repository and commit produced
them, and it cannot be forged by someone holding the signing key, because it is not made
with that key. Losing the key breaks the first check; a compromised workflow breaks the
second. You want both. See [signing](signing.md) for more on the distinction, and
[the SBOM](sbom.md) for what check 3 contains.

Checks 1 and 3 only exist if the publishing repo turned on `:sign` and `:sbom`
respectively — both are opt-in. Their absence means the repo has not enabled them, not
that something is wrong with the artifact.

### Rebuilding it yourself

The jar is byte-reproducible: entry order is fixed, every timestamp is pinned, and the
manifest's `Build-Jdk-Spec` line is stripped precisely so a rebuild on a different JDK
still matches. So there is a third-party-free check available — build the tag yourself and
compare digests:

```bash
git checkout $V && clojure -T:build jar
shasum -a 256 target/mylib-$V.jar   # must equal the digest in the tag message
git cat-file -p $V                  # the signed tag, with every artifact's digest
```

**One caveat, and it is a real one.** Reproducing the digest requires the same Clojure CLI
and `tools.build` versions the release was built with. The generated pom inherits its
Clojure version from the installed CLI's root `deps.edn`, and that pom is packaged *inside*
the jar — so the digest is partly a function of your CLI version.

**A digest mismatch under a different toolchain is expected, and is not by itself evidence
of tampering.** `tools.build` is pinned transitively by the `:git/sha` you consume this
library at, so in practice the CLI is the variable one. The workflow template pins it, but
any release cut before that pin was added used whatever `latest` resolved to that day. The
signature and the attestation are the checks that do not depend on your local toolchain.

## For maintainers: when the release's own verification fails

`deploy` runs the same digest comparison itself, right after publishing and **before** it
tags. That ordering is the entire point: a release that cannot prove what it shipped never
gets a tag vouching for it.

But the check runs after the upload, and **a published version can never be changed.**
Clojars is explicit about this: *"Once a non-SNAPSHOT version has been deployed, it is
immutable (barring a valid deletion request)."* It will not accept different bytes at the
same coordinate, and it deletes versions for only two reasons — malicious code, or
credentials published by accident.

So the question is never "how do I fix this version." It is "which of the two failures is
this."

### Clojars could not serve the artifact

The upload succeeded but the download 404s or times out. Clojars is eventually consistent,
and the CDN can lag a fresh upload by longer than the release's polling window, so most of
the time the bytes are fine and the release simply needs finishing.

The abort message hands you the `git tag` and `git push` commands for that, after you
confirm the digest by hand.

### The digest did not match

Clojars served the artifact — all of it — and it is not what was uploaded. This is the
serious case. It means either the wrong artifact got published, or something replaced it
between the upload and the check. This comparison is the only check in the release path
that would catch either.

**The abort message for this case deliberately gives you no tag command.** Every other
post-publish failure ends in a ready-to-paste `git tag`, and after a few releases you
reach for it without reading — which here would sign the release record, the thing
consumers trust to say what we shipped, over bytes that just failed the integrity check.

What to do instead:

1. **See what Clojars is actually serving**, so you are not reacting to one bad download:

   ```bash
   curl -fsSL <the url from the abort message> | shasum -a 256
   ```

2. **If it does not match: the version number is spent.** Bump the version file and
   release again — the new release *is* the remedy, and nothing recovers the old one. Then
   make a judgment call: if you conclude the bytes Clojars is serving are malicious rather
   than merely wrong, that is grounds for a
   [deletion request](https://github.com/clojars/clojars-web/wiki/About) to the Clojars
   admins, and consumers need to hear about it.

3. **If it does match: stop and treat it as unresolved.** Clojars served two different
   complete bodies for one coordinate, which should not be possible. Re-check from another
   machine and another network before deciding anything, and do not copy a tag command out
   of an earlier release's log to "finish" this one.

### The tag itself failed

A third case, and the mildest. `tag!` runs only after everything above passed, so a
failure here means the artifact is live, verified, recorded — and only the tag is missing.
The release is otherwise complete. Do not retry the release; finish the tag with the
commands the abort message gives you. It notes that the tag may already exist locally,
since `git tag` can succeed and only the push fail.

### The shape a tag has to have

If you ever finish a release by hand, the tag has to match what `deploy` would have
produced: **signed**, **annotated**, and carrying every artifact's digest in the message.

```
2.14.0

commit: <full sha>
mylib-2.14.0.jar: sha256:<digest>
mylib-2.14.0.pom: sha256:<digest>
```

The digests live in the tag so that "what bits did we ship" is answerable from a clone
alone — no API call, and no dependency on a log retention window. It is signed because the
tag is the release record, and a lightweight tag is forgeable by anyone with write access.
