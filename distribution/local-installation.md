# Install enkv and select plugins

For a first installation, use the
[operator installation guide](https://github.com/enkv-sh/core/blob/main/docs/install.md),
then the [AWS or GCP first-use path](https://github.com/enkv-sh/core/blob/main/docs/README.md#start-with-one-secret).
This reference gives the detailed archive and plugin-selection rules.

Use a native archive for `darwin/arm64` or `linux/amd64`. The first beta
distributes the `full` archive, which supports both AWS and GCP domain Store/KMS.
Selected-provider archives remain development options. CLI compositions do not
define a list of plugin services or formats. Plugins are separate
executables; a CLI archive contains none. Binary use needs no Go, Git or GitHub
login. Plugin source builds use the [detached public source route](README.md#detached-public-source).
CLI source packaging is a separate contributor task.

## Install a CLI archive

Obtain the selected archive over HTTPS with certificate verification enabled.
The normal installation path trusts the download service and its release
account; it needs no external signature verifier. The release also supplies its
exact `checksums.txt` and detached signature for optional verification before
extraction or execution. Use the exact supplied native archive name in the
commands below.

### Optional signature verification

For this additional check, obtain the CLI SPKI PEM public key through an
independently trusted route and use trusted OpenSSL 3.x and `shasum`. A key or
checksum beside an untrusted download is insufficient by itself.

```sh
openssl pkeyutl -verify -rawin -pubin \
  -inkey /absolute/trusted-cli-public.pem \
  -in checksums.txt -sigfile checksums.sig || exit 1
archive=enkv-full-0.1.0-beta.1-darwin-arm64.tar.gz
expected=$(awk -v name="$archive" '$2 == name {print $1}' checksums.txt)
actual=$(shasum -a 256 "$archive") || exit 1
[ "$expected" = "${actual%% *}" ] || exit 1
```

### Extract and install

This example installs the full macOS/arm64 beta archive. Select the corresponding
Linux archive on Linux:

```sh
archive=enkv-full-0.1.0-beta.1-darwin-arm64.tar.gz
mkdir /absolute/new-enkv || exit 1
tar -xzf "$archive" -C /absolute/new-enkv || exit 1
mkdir -p "$HOME/.local/bin" || exit 1
install -m 0755 /absolute/new-enkv/enkv "$HOME/.local/bin/enkv" || exit 1
export PATH="$HOME/.local/bin:$PATH"
```

Keep the archive's license and notices. Add that PATH entry to your shell setup
if needed. Installation ends with `enkv` on PATH. It runs no installation hook,
starts no plugin and grants no provider authority. Apple Developer ID signing
and notarization are deferred for beta; manual macOS approval is accepted.
Official-plugin authentication remains automatic and mandatory, including when
the optional external CLI verification was omitted. Run preparation explicitly
for an existing valid configuration pair whose editable file is
`/absolute/application/enkv.yaml`:

```sh
cd /absolute/application
enkv prepare --json
```

This guide assumes an installed compatible CLI and a valid editable application
configuration with its generated JSON satellite and domain access. It covers
extension setup, not application creation or domain provisioning. Use your
application operator's configuration for the commands below. A source build
without assembled verification roots cannot replace a trusted packaged CLI.
The [CLI packaging recipes](https://github.com/enkv-sh/core/blob/main/distribution/cli-packaging.md) bind these roots at build time.
Project configuration and runtime environment cannot replace them.

Configuration-reading commands default to `enkv.yaml` in the captured current
directory and YAML syntax. `plan` uses this default for its trusted source.
Select another file with `--source PATH`, or `--trusted PATH` for plan.
Explicit `.yaml`, `.yml` and `.json` suffixes select syntax without regard to
case. An explicit `--source-format yaml|json` or `--trusted-format yaml|json`
overrides the suffix; an absent or unknown suffix requires that format flag.
Relative source and output paths use the same captured directory. ENKV does
not search parent directories or try another file or parser after failure.
An omitted plan candidate uses the trusted declaration; an explicit candidate
has its own `--candidate` and optional `--candidate-format` selection.

Preparation can acquire missing official plugins, capture trusted local builds
and run passive plugin validation. Plugin readiness does not prove domain
equality, provider permissions or success of a later operation. A missing
plugin selection needs a trusted compatible selection; it is different from
a selected installation that is missing or invalid.

## Trust a local author build

A new or modified plugin can remain private and unpublished. Use the
[public SDKs](../sdk/README.md) to implement one of the three supported families,
then build it with its own author descriptor. No official provider/format entry
or ENKV rebuild is required.

For example, use the local token generator
[public kit and workspace](README.md#detached-public-source). Use stock Go 1.27.3,
an existing tools directory and an existing parent for the build output:

```sh
GOWORK=/absolute/public-kit/go.work go -C /absolute/public-kit/sdk/artifact build \
  -o /absolute/tools/enkv-plugin-build ./cmd/enkv-plugin-build
/absolute/tools/enkv-plugin-build \
  -directory /absolute/public-kit/sdk/examples/local-token-generator \
  -descriptor plugin.json -command . \
  -workspace /absolute/public-kit/go.work \
  -output /absolute/builds/local-token
/absolute/tools/enkv-plugin-build -verify /absolute/builds/local-token
```

The descriptor supplies the name `private-local-token`, family, author version,
semantic declarations and credential route. The builder measures executable,
platform, compiler, module and dependency facts. It does not run the plugin or
install a hook. See the [artifact guide](../sdk/artifact/README.md) for detached
public kits and exact versioned dependencies. The
[local output](../sdk/examples/local-value-output/README.md) and
[INI manifest](../sdk/examples/ini-reference-manifest/README.md) have their own
descriptors and implementations.

Trusted settings are `os.UserConfigDir()/enkv/plugins.json`: on macOS,
`$HOME/Library/Application Support/enkv/plugins.json`; on Linux,
`$XDG_CONFIG_HOME/enkv/plugins.json`, or `$HOME/.config/enkv/plugins.json` when
`XDG_CONFIG_HOME` is unset. Persistent installation data use the sibling
`enkv/installation/` directory.

For a new settings file, create its parent directory and write the JSON below. Set `plugin_settings` to the real user-config path. Replace the two
example directories with existing absolute paths. The application directory is
the canonical directory containing the selected editable configuration; resolve
symlinks first. It is independent of the filename and domain name.

```sh
plugin_settings='/absolute/user-config/enkv/plugins.json'
cat > "$plugin_settings" <<'JSON'
{
  "schema": "enkv/plugin-settings/v1",
  "applications": [
    {
      "directory": "/absolute/application",
      "plugins": [
        {
          "name": "private-local-token",
          "directory": "/absolute/builds/local-token"
        }
      ]
    }
  ]
}
JSON
```

Preserve other applications when editing an existing file. Whitespace, a final
newline, object-field order and application/plugin list order do not change
trust. Each plugin remains assigned to its application's directory. Duplicate
keys or entries, unknown fields, invalid values, invalid Unicode and exceeded
limits refuse. Limits are 256 applications, 64 plugins per application and
1 MiB per file. Signed artifacts and internal installation records keep their
canonical encoding rules. Project files cannot replace these trusted settings
or authorize a path, URL, build hook or credential helper.

An absent optional settings file means no local overrides. An existing invalid
or unreadable file stops dependent plugin work and reports one settings failure
for `plugins.json`, with its safe path, reason, known location and correction
action. Required plugin names can remain visible as checks not attempted; this
failure makes no plugin source or integrity claim and selects no fallback.
Correct the content or file access, then run preparation on the same pair.
Completed file delivery and independent administrative readiness remain valid.

This setting explicitly trusts the local native code for that application.
The next command needing the plugin verifies and captures its immutable bytes
into installation storage. It does not execute from the mutable build folder.
No signature or release publication is required for this route. Family protocol,
actual compiled closure, descriptor and exact-byte checks still apply. A local
selection takes precedence over an official version pin for the same name.
Other applications retain their own selections.

## Select plugins in the project

An existing YAML or JSON configuration can declare an optional `plugins` map.
Each portable local ID takes `{}` or one exact semantic `version`, without a
leading `v`. For example:

```yaml
plugins:
  private-local-token: {}
  private-local-values: {}
  workshop-ini: {}
```

These are the independent examples' IDs, not a host membership list. Any name
that follows the portable basename grammar can use a supported family. A
project requirement selects trusted installed code; it cannot grant trust.
Ranges, wildcards, duplicate names and unknown record fields refuse. An exact
version controls official release selection; an explicit trusted local build
takes precedence for that application.

Generator and output declarations name the local plugin and its own public
`settings`. The following is an entry-source fragment for the token example:

```yaml
source:
  kind: generated
  plugin: private-local-token
  settings:
    endpoint: http://127.0.0.1:12345
    namespace: workshop
    subject: api
  epoch: 0
  retirement: manual
```

Use the example's [settings and service instructions](../sdk/examples/local-token-generator/README.md).
This fragment belongs to an entry in your existing application configuration;
it is not a complete configuration file. The example service is an in-process
Go test helper. The endpoint above illustrates the setting and does not start a
service. Requirements implied
by generator/output declarations use the same policy as `{}` when unpinned.
There is no implicit generic-JSON renderer requirement. Commands resolve their
actual dependencies; public comparison and minimum administration need no
unrelated effect plugin or renderer.

A manifest explicitly selects its trusted local renderer and plugin-owned JSON
settings. For the INI example:

```sh
enkv manifest --source /absolute/application/configuration.yaml --source-format yaml \
  --plugin workshop-ini --settings '{"section_prefix":"application"}' \
  --out /absolute/application/manifest.ini --json
```

`--source-format` selects the source syntax. `--plugin` selects the renderer; `--settings`
is its public input, defaulting to `{}`. `--service local-values-service/v1` can
filter the authenticated destinations by the private output example's semantic
service identity. The default entry selection is all authorized entries;
`--name` supplies exact names and `--empty-selection` requests an empty set.
The artifact contains plain values and secret references. It does not fetch
secret values or apply infrastructure.

Manifest runtime success establishes `authorized-input-and-exact-bytes`, including
common input, selected-build, framing, bounds, deadline and closure checks.
The plugin owns format validity and correspondence. Use its independent format
and consumer tests to establish those properties.

## Official selection and upgrades

Official distribution is a separate route under the CLI's embedded verification
roots. It is available for published names in the signed release index; it is
not required for private author builds.

| Request | Result |
|---|---|
| First `prepare`, unpinned, no selection | Select the latest compatible official stable release from the signed index. |
| Later `prepare`, valid selection | Verify and retain the exact build without a release-service call. |
| Ordinary command, valid official selection | Reuse exact verified bytes and proof offline. |
| Exact `version` | Preparation requires that release or refuses. |
| `prepare --upgrade` | Seek newer compatible official releases for unpinned requirements; retain exact pins. |
| Missing selected bytes | Ordinary use refuses; preparation can reacquire the same exact official artifact. |
| Damaged record or invalid signature | Refuse without selecting a replacement. |

```sh
enkv prepare --source /absolute/application/configuration.yaml --source-format yaml --upgrade --json
```

Ordinary commands do not download missing official plugins. Prereleases need an
exact pin. A failed update retains the prior valid selection and reports its
failure. Preparation reports dependency readiness and exact installation facts;
it does not certify credentials or future provider access.

Use the [manual signing instructions](release.md) and
[artifact tools](../sdk/artifact/README.md) for official records and archives.
Plugin and CLI keys differ, as do development and production keys. The manual candidate workflows need owner configuration. They stage signed draft
assets. The owner separately decides public promotion.

## Rebuilds, credentials and retained work

Rebuild a modified local plugin to the same output directory. The tool publishes
another immutable `builds/<artifact>/` directory, then atomically replaces
`build.json`. The next dependent command captures that complete build. A running
invocation keeps its captured bytes. An invalid rebuild refuses before credentials
or effects; it does not silently substitute official code. Removing a local
selection resumes the recorded official selection after verification or explicit
preparation if needed.

The selected effect plugin declares its public credential route. ENKV captures
the declared environment inputs privately; the plugin performs credential
discovery and verifies the resolved account/target. Ordinary tokens use environment
variables, such as `ENKV_EXAMPLE_TOKEN`, `CLOUDFLARE_API_TOKEN` or `GITHUB_TOKEN`.
AWS uses its standard SDK chain and GCP uses ADC. SDK routes can use trusted
configuration files/helpers. Native code is trusted and is not OS-confined.
Credentials belong in neither project settings nor artifact/install records.
Passive normalization and manifest rendering receive no provider credentials.

Equal semantic intent at the same epoch reuses a generated value after a build
change. Changed intent at that epoch refuses. Accepted generator work retains
its original exact executor and route identity; later invocations obtain current
credentials through that route. A NEW retirement Duty can use the currently
selected compatible build after passive checks of the original resource. It then
retains that selected support. Removal with no current generator declaration
requires an explicit choice, for example:

```sh
enkv apply --source /absolute/application/configuration.yaml --source-format yaml \
  --retire-generator api=private-local-token --json
```

Retained output deletion likewise requires an explicit local plugin selection:

```sh
enkv publish --source /absolute/application/configuration.yaml --source-format yaml \
  --delete-coordinate "$coordinate_id=private-local-values" --json
```

Keep original builds required by accepted work. After machine loss, restore exact
official coordinates/proof or the original local artifact bytes. Missing old
support does not authorize fallback or another service send. There is no automatic
uninstall. Output markers preserve passive history and uncertainty without
requiring an old output executable or replaying its payload.

Complete-loss configuration recovery preserves canonical public settings and
semantic identities with local selections unset. Recovered generator and output
settings appear as nested `canonical.settings` fields. The generated companion
retains their exact complete records; keep both files together. Choose trusted
compatible code before later effects; recovery does not apply newer defaults or
confer trust.
If the editable file survives and its declared companion is missing, explicit
prepare recovery can restore that companion while preserving the editable file.
A delivered pair can still need missing supplied input or plugin setup. Follow
the [operator recovery instructions](https://github.com/enkv-sh/core/blob/main/compositions/full/README.md#restore-a-missing-generated-companion),
keep recorded delivery, and complete setup on the existing pair.

Rotating a token does not change an admitted target or grant retry permission.
Lost acknowledgements remain unknown under the operation's existing rules.
