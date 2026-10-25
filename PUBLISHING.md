# Publishing `in.slashmark:maven-suite` to Maven Central

Releases go out from GitHub Actions: push a `v*` tag and `.github/workflows/release.yml` runs every test, signs the
artifacts, uploads them to Maven Central through the Central Portal and creates a GitHub release with the JAR and launchers.
The one-time setup takes about 30 minutes, plus DNS propagation time.

## 1. Push the code to GitHub

Create an empty public repository `github.com/slash-mark-dev/maven-suite`, then:

```bash
cd maven-suite
git remote add origin https://github.com/slash-mark-dev/maven-suite.git
git push -u origin main
```

The CI workflow runs on every push (Java 17/21/25 on Linux, plus Windows and macOS, and the differential tests against Maven).

## 2. Create a Central Portal account and verify the namespace

1. Sign in at <https://central.sonatype.com> (GitHub login works).
2. **Namespaces → Add namespace → `in.slashmark`.** The portal shows a verification key.
3. Add a **DNS TXT record** on `slashmark.in` with that key as its value (Hostinger DNS zone → add record, type TXT, name `@`).
4. Click **Verify** once DNS has propagated (usually minutes, at most a few hours). The TXT record can be removed afterwards.

> Prefer not to touch DNS? The namespace `io.github.slash-mark-dev` is verified automatically when you sign in with
> the `slash-mark-dev` GitHub account. If you use it, change `<groupId>` in `pom.xml` and the install commands in
> `README.md` to match.

## 3. Create a publishing token

Central Portal → your account → **Generate User Token**. Keep the username and password it shows.

## 4. Create a signing key

Maven Central requires every file to be signed with PGP.

```bash
gpg --quick-gen-key "Slash Mark IT Solutions <mukesh@slashmark.in>" ed25519 sign 3y
gpg --list-keys mukesh@slashmark.in                      # copy the long key id / fingerprint
gpg --keyserver keys.openpgp.org --send-keys <FINGERPRINT>  # then confirm the e-mail keys.openpgp.org sends
gpg --armor --export-secret-keys <FINGERPRINT> > private.asc
```

## 5. Add GitHub secrets

Repository → Settings → Secrets and variables → Actions → **New repository secret**:

| Secret | Value |
|---|---|
| `CENTRAL_USERNAME` | token username from step 3 |
| `CENTRAL_TOKEN` | token password from step 3 |
| `GPG_PRIVATE_KEY` | full contents of `private.asc` (then delete the file) |
| `GPG_PASSPHRASE` | the key's passphrase |

## 6. Release

```bash
git tag v1.0.0
git push origin v1.0.0
```

The workflow checks that the tag matches the `pom.xml` version, runs the tests, then publishes. Artifacts appear on
`repo1.maven.org` within about 30 minutes and in search a little later. You can follow the release live:

```bash
java -jar build/sm-maven.jar publish-track in.slashmark:maven-suite:1.0.0 --wait
```

For the next version: bump `<version>` in `pom.xml` and `VERSION` in `build.sh`, add a `CHANGELOG.md` entry, commit, and tag.
