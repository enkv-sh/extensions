# Plugin artifacts

`enkv.sh/sdk/artifact` provides canonical plugin metadata, dependency records,
local build publication, archive production and verification, and detached
Ed25519 signatures.
The module and its commands use only the Go standard library. They have an
Apache-2.0 license and do not import private program code.

Use exact stock Go 1.27.3 on `darwin/arm64` or `linux/amd64`. The module's
Go 1.27.0 directive remains the source minimum. The build command fixes
`CGO_ENABLED=0`, trimpath and VCS recording. It rejects custom compiler inputs,
test tags and unsupported compiler input families. It builds one main package and does
not run that package.

Start with the [detached public source layout](../../distribution/README.md#detached-public-source).
The artifact module has no other module dependencies. From its directory, install
the tools from the source you selected:

```sh
cd /absolute/public-kit/sdk/artifact
GOWORK=off GOTOOLCHAIN=local go install ./cmd/enkv-plugin-build ./cmd/enkv-artifact-sign
```

Make the Go binary output directory available on `PATH`. The commands below use
the installed tool names. For an author build, use the kit's explicit absolute
workspace file. Run from the author module, or set `-directory`:

```sh
enkv-plugin-build -descriptor enkv-plugin.json \
  -command ./cmd/private-plugin -workspace /absolute/public-kit/go.work \
  -output /absolute/path/private-build
enkv-plugin-build -verify /absolute/path/private-build
```

Select exactly one main package; a library or package pattern refuses. The CLI
defaults to directory `.`, descriptor `plugin.json` and command `.`. The library's
`build.Config` requires those values explicitly. Both routes require an output
path and an explicit dependency mode. The public source guide supplies the
workspace `use` and exact-version `replace` rules; keep those overrides out of
maintained `go.mod` files.

[Versioned dependency builds](../../distribution/README.md#versioned-dependency-builds)
are a separate route. They need reachable exact versions and any required source
access.
Use `-versioned` instead of `-workspace` only when those prerequisites hold.

The author descriptor declares a portable local plugin name, one of the three
families (`generator`, `output`, `manifest-generator`), an exact version, its
public wire identity/version and the corresponding family declaration. Names,
module paths, services and formats need no entry in an ENKV catalog. A build
may use an unpublished author module. The host separately checks whether its
family wire protocol is supported before invocation.
The file can have any name; `-descriptor` selects it. Keep the descriptor used
by the main's SDK identity equal to this author data. The independent examples
embed `plugin.json` with `go:embed` before compilation.

Use `artifact.EncodeDescriptor` to write canonical JSON or author ordinary JSON
and read it with `artifact.DecodeDescriptor`. Input permits whitespace and field
order; duplicate and unknown fields refuse. `Descriptor.Identity` hashes the
canonical author data. The SDK implementation uses this pre-build descriptor
identity and its protocol identity; it does not embed its final executable hash.

A generator declaration contains its configuration-contract digest and encoded
credential route. An output declaration contains its configuration-contract
string and route. A manifest declaration contains configuration- and
format-contract strings. Lifecycle/resource and service/target/policy facts come
from plugin normalization, rather than static provider lists. Only the matching
declaration arm is present. Semantic strings have a 256-byte UTF-8 bound.

`credentialroute` encodes the complete public route (at most 1,581 bytes) and
private selected environment inputs (at most 65,536 bytes). It performs no
credential lookup. Routes distinguish ordinary environment and standard SDK
discovery, allow up to 32 sorted distinct environment names, and keep private
values outside artifact metadata. Names have a 128-byte ASCII bound. An absent
variable and a present empty variable have different encodings. Decoded private
values borrow the input body; retain and clear that body through its borrowers'
lifetime. Each plugin owns actual credential discovery and account/target checks.

The route's `ContractID` identifies those discovery rules, including the meaning
of declared names and public data. Keep it stable when secret values rotate.
Change it if that meaning changes incompatibly, for example when `TOKEN`
changes from a token value to a filename. Renaming a public input under the
same supported rule changes the complete route identity, but need not change
`ContractID`. Secret values enter neither identity. Neither identity grants
permission or proves that a plugin supports retained work.

For a minimal generator descriptor, use `generator.DescriptorWire()` and the
same nonzero configuration digest passed to `generator.Bind`:

```go
route, err := credentialroute.Encode(credentialroute.Route{
    Schema: credentialroute.Schema, ContractID: [32]byte{1},
    Mode: credentialroute.ModeEnvironment, Names: []string{"TOKEN"},
})
if err != nil { return err }
config := generatorprotocol.ID{3}
descriptor := artifact.Descriptor{
    Schema: artifact.DescriptorSchema, Name: "my-generator", Role: "generator",
    Version: "1.0.0", Wire: generator.DescriptorWire(),
    Generator: &artifact.GeneratorDeclaration{
        ConfigContractID: artifact.Digest(config), CredentialRoute: route,
    },
}
body, err := artifact.EncodeDescriptor(descriptor)
if err != nil { return err }
if _, err := artifact.DecodeDescriptor(body); err != nil { return err }
binding, err := generator.Bind(body, config)
if err != nil { return err }
_ = binding // Attach it to the implementation before serving.
```

Import `enkv.sh/sdk/generator`, `enkv.sh/sdk/artifact`,
`enkv.sh/sdk/artifact/credentialroute` and the generator protocol as
`generatorprotocol` from `enkv.sh/sdk/protocols/generator`.
The digest and route above are local
author choices; replace their discovery meaning with your plugin's rules.

For an output descriptor, use the same route encoding and replace the
descriptor and binding calls with:

```go
descriptor := artifact.Descriptor{
    Schema: artifact.DescriptorSchema, Name: "my-output", Role: "output",
    Version: "1.0.0", Wire: output.DescriptorWire(),
    Output: &artifact.OutputDeclaration{
        ConfigContractID: "my-output-settings/v1", CredentialRoute: route,
    },
}
body, err := artifact.EncodeDescriptor(descriptor)
if err != nil { return err }
if _, err := artifact.DecodeDescriptor(body); err != nil { return err }
binding, err := output.Bind(body, "my-output-settings/v1")
if err != nil { return err }
_ = binding
```

Here `output` is `enkv.sh/sdk/output`. A manifest generator has no credential
route. Use `native` from `enkv.sh/sdk/manifest-generator/native` and pass your
two author callbacks as `callbacks`:

```go
descriptor := artifact.Descriptor{
    Schema: artifact.DescriptorSchema, Name: "my-manifest", Role: "manifest-generator",
    Version: "1.0.0", Wire: native.DescriptorWire(),
    Manifest: &artifact.ManifestDeclaration{
        ConfigContractID: "my-manifest-settings/v1", FormatContractID: "my-format/v1",
    },
}
body, err := artifact.EncodeDescriptor(descriptor)
if err != nil { return err }
if _, err := artifact.DecodeDescriptor(body); err != nil { return err }
implementation, err := native.Bind(body, "my-manifest-settings/v1", "my-format/v1", callbacks)
if err != nil { return err }
_ = implementation
```

The family binding tests exercise these encode/decode/bind paths. Binding does
not run the callbacks, discover credentials, measure an executable or install it.

The descriptor cannot set measured command, module, platform, toolchain, source,
dependency or executable facts. The builder compares its exact file bytes before
and after compilation and records a canonical copy with the measured facts.
This authenticates the captured build; it does not prove that author-declared
semantics are true, that the executable confines native code, or that a claimed
protocol is implemented correctly.
The descriptor's semantic identities are plugin declarations, not host catalog
entries. Passive plugin callbacks validate their own canonical meaning.

For exact versioned dependencies, use `-versioned` in place of `-workspace`.
That route sets `GOWORK=off`, requires real non-main module versions and refuses
filesystem replacements. Local workspace builds retain their actual empty
resolved versions and `(devel)` compiled versions. Metadata records the resolved
graph separately from the modules that actually contributed compiled packages.

A successful build publishes an immutable `builds/<artifact>/` folder containing
`plugin`, `metadata.json`, and `dependencies.bin` for all three families.
It then replaces `build.json` atomically. The artifact is the SHA-256 of exact
canonical metadata bytes. Verification checks the executable, actual build
information, complete module closure and dependency bytes. Failed builds do not
publish an incomplete marker. Treat the output as build input to the installer;
do not execute a plugin from its mutable output folder.

Source records bind selected Go files and module/legal files. Each compiled
nonstandard owner needs `go.mod` and at least one regular `LICENSE`, `LICENSE.txt`
or `LICENSE.md` at its root. Records bind legal files in the module root and
each ancestor directory of a selected package or input, including embedded data.
The supported names are `LICENSE`, `NOTICE`, `AUTHORS`, `COPYING`, `COPYRIGHT`
and `PATENTS`, each bare or with `.txt` or `.md`, plus `THIRD_PARTY_NOTICES.md`.
The inventory stops at the module root and excludes unrelated sibling trees.
Present legal files must be regular files, not symlinks. Records bind their
exact module-relative names and bytes, plus present `go.sum`.
A local owner with no selected package needs
`go.mod`; its present legal files are bound without a license-presence claim.
Versioned
third-party dependencies can also have selected Go assembly, enumerated headers
and resolved embedded files. Local author and first-party modules retain the
Go and compiler-enumerated embedded-input family; local assembly remains unsupported. These records do not prove a source-to-binary relation or
confinement. Host compatibility, source trust and runtime admission are separate
checks.

Sign exact records with an existing PKCS8 Ed25519 private key:

```sh
enkv-artifact-sign -purpose plugin-executable -input metadata.json \
  -key plugin-signing-key.pem -output metadata.sig
enkv-artifact-sign -verify -purpose plugin-executable -input metadata.json \
  -key trusted-plugin-public.pem -signature metadata.sig
```

Other purposes are `plugin-archive`, `plugin-index` and `cli-checksums`.
Signatures are raw 64-byte pure Ed25519 signatures over the exact bounded input.
Use separate plugin and CLI keys, and separate development and production roots.
The command neither creates keys nor publishes records. Verification requires an
independently trusted SPKI public key. OpenSSL 3.x can verify the same bytes:

```sh
openssl pkeyutl -verify -rawin -pubin -inkey trusted-plugin-public.pem \
  -in metadata.json -sigfile metadata.sig
```

Create a separately installable plugin archive from a verified local build.
First sign its exact `builds/<artifact>/metadata.json` with the existing signer.
Keep that signature outside the immutable build folder:

```sh
enkv-artifact-sign -purpose plugin-executable \
  -input /absolute/path/private-build/builds/<artifact>/metadata.json \
  -key development-plugin-key.pem -output /absolute/path/metadata.sig
enkv-plugin-build -archive /absolute/path/private-build \
  -metadata-signature /absolute/path/metadata.sig \
  -directory /absolute/path/author-module \
  -command ./cmd/private-plugin -workspace /absolute/path/go.work \
  -output /absolute/path/new-private-archive
enkv-artifact-sign -purpose plugin-archive \
  -input /absolute/path/new-private-archive/archive.json \
  -key development-plugin-key.pem \
  -output /absolute/path/new-private-archive/archive.sig
```

Use the original source directory, command and workspace, or its original
`-versioned` dependency mode. Archive creation checks those current source facts
against the build metadata and checks them again before publishing output.
It requires the build's native platform and exact stock Go 1.27.3. It executes
no plugin or installation hook. The build name and version come from verified metadata;
do not pass `-descriptor` or `-verify` with `-archive`.

The output directory must not exist. Its parent must exist. Success creates
`enkv-plugin-<64 lowercase hex artifact digest>.tar.gz` and canonical
`archive.json`. The 83-byte basename uses SHA-256 of the exact canonical
metadata. Signed metadata and the archive record retain the complete plugin
name, exact version and native platform. Consumers use the signed archive
filename within its release directory.
A failure during final output writing can leave an incomplete output directory;
use a fresh output path for another attempt. The immutable local build remains
unchanged. The archive record and its later signature stay outside the archive.

Archives use a deterministic single gzip stream and POSIX ustar members. They
contain `plugin`, `metadata.json`, the required external `metadata.sig`, and
`dependencies.bin` for all three families. Legal files use the fixed
names `LICENSE`, optional `NOTICE`, and `THIRD_PARTY_NOTICES.md`. The main
owner's first supported license supplies `LICENSE`. The notices retain every
supported co-present license and notice file from actual compiler-selected
module owners and applicable input ancestors, including replacement source
owners, and the Go toolchain's `LICENSE`. They also preserve all Go source
comments, including notices after the package clause, and leading `//` and
`/* */` comment blocks from selected native source files. Original comment bytes
are retained, including carriage returns. Source symlinks must stay inside the
module; legal metadata files must not be symlinks.
Embedded data is not parsed as source. Resolved modules with no compiled package
are omitted from notices. The collector does not classify licenses or prove
legal completeness: before release, review the selected dependencies for other
legal filenames, non-leading native source notices, and file-level exceptions
whose full license text must also be supplied.
The archive command checks signature size; the installer authenticates the
metadata and archive signatures against its independently assembled trust roots.
An archive alone grants no execution trust. Trusted local overrides consume
local build folders directly.

The generic record decoder validates canonical encoding and internal relations.
The host checks supported family protocols and exact installed bytes; plugins
own their semantic interpretation. Archive extraction and local record types
grant no permission to launch a child. Local authors can instead trust a build
folder directly through the [application installation settings](../../distribution/local-installation.md#trust-a-local-author-build),
without creating an archive or signature.
