# NyaTerm fork notes

This branch carries [NyaTerm](https://github.com/nyakang/nyaterm)'s local changes
to `ironrdp-client` and `ironrdp-connector` on top of an unmodified upstream base.

- Fork: <https://github.com/nyakang/IronRDP>
- Upstream: <https://github.com/Devolutions/IronRDP>
- Base revision: `aed5ce8ba225c6d2b17ab39b0d12b3fc65e565bd` (upstream `master`, 2026-10-20)
- Branch: `nyaterm`
- Crates touched: `crates/ironrdp-client`, `crates/ironrdp-connector`,
  `crates/ironrdp-acceptor`, `crates/ironrdp-vmconnect`, `crates/ironrdp-mstsgu`,
  `crates/ironrdp`, and `ffi`.

NyaTerm consumes both through `[patch.crates-io]`. The crate versions this base
publishes are unchanged from the 0.1.0 / 0.10.0 release commit the branch used to
sit on, so those pinned slots still resolve.

## Patches

1. `feat(client): request a full desktop update on demand` — upstream now owns
   `DesktopUpdate` delivery and `RdpClient::with_desktop_updates()`. NyaTerm keeps
   only `RdpInputEvent::RequestFullFrame`, which emits a full-frame
   `DesktopUpdate` through the same ordered output channel for resynchronisation.
2. `refactor(connector): drop the picky dependency and the smart-card path` —
   removes an unused-feature dependency whose defaults pin a prerelease
   `aes-gcm`, and whose `=7.0.0-rc.25` pin also conflicts outright with the
   `=7.0.0-rc.26` that `sspi` pins. **Deliberately drops smart-card
   authentication and redirection**; username/password NLA is unaffected.
3. `feat(client): support authenticated loopback TCP routes` — direct TCP may
   connect through a validated loopback relay and send a bounded authentication
   preamble while retaining the original destination for TLS and CredSSP
   identity. UDP is disabled for relayed connections because the relay contract
   covers TCP only.
4. `build: consume SSPI 0.22` — all direct SSPI dependencies use 0.22, gateway
   picky resolves at rc.26, and fallible `TsRequest::buffer_len` calls propagate
   encoding errors in connector, acceptor, and VMConnect paths.

## Not carried here

Five patches were dropped when this series was rebased from `11a0810c`
(the 0.1.0 / 0.10.0 release commit) onto `master`, 264 commits later, because
upstream now covers what they did:

- `feat(client): report an unsupported resize instead of reconnecting` —
  upstream added `RdpOutputEvent::DisplayResizeFallback(reason)` with three
  reasons, so the reconnect is no longer silent. It still reconnects, which is
  now deliberate: `#271` (the auto-reconnect cookie) is implemented, and the
  resize path explicitly clears the cookie so the fallback establishes a fresh
  session. NyaTerm reports the same `DynamicResizeUnavailable` capability from
  that event instead.
- `feat(client): add a certificate decision hook before CredSSP` — upstream's
  `fix(tls): make certificate validation explicit (#1520)` added
  `CertificateValidation` plus `CertificateValidationCallback`, and
  `feat(mstsgu): apply certificate validation to gateways (#1775)` and
  `fix(rdpeudp)!: thread server_cert_verifier through MultitransportBootstrap`
  extended it to the gateway and multitransport paths the NyaTerm hook never
  reached. Upstream's callback fires only when the platform trust store rejects
  the chain, which for RDP is the common case, and it receives the leaf DER
  rather than a parsed certificate.
- `fix(client): rebuild the FastPath bulk decompressor after reactivation` —
  fixed upstream, and better: `#1474`, `#1255` and `#1518` moved the
  decompressor onto `ActiveStage` and preserve its *history* across
  reactivation, where this patch allocated a fresh one.
- `feat(client): add a builder toggle for audio playback` — upstream forces
  `enable_audio_playback = false` at connect time when the `sound` feature is
  off (`rdp.rs`, `#[cfg(not(feature = "sound"))]`), which is where NyaTerm needs
  it, and adds `with_sound`/`with_audio_mode` for callers that do build sound.
- `fix(connector): remove a stale single_use_lifetimes expectation` — upstream
  keeps the `#[expect]`, and it is a lint-only difference: NyaTerm consumes these
  crates as a git dependency, so cargo caps their lints, and this branch's CI
  does not use `-D warnings`.

## Removed local graphics API

The 2026-09-22 merge drops the fork-only `DesktopReset`, `ImageRegion`,
`ConfigBuilder::with_dirty_region_updates`, and its duplicate framebuffer state.
Upstream's `DesktopUpdate` carries the framebuffer extent and inclusive changed
region, and sends a full update whenever the extent changes.

## Validation

On Windows 11, with the toolchain `rust-toolchain.toml` pins (1.94.1):

```sh
cargo check -p ironrdp-client --features rustls            # clean
cargo check -p ironrdp-client --features rustls,clipboard  # clean
cargo check -p ironrdp-connector                           # clean
cargo check -p ironrdp-acceptor                            # clean
cargo check -p ironrdp-vmconnect                           # clean
cargo test -p ironrdp-connector                            # clean
cargo clippy -p ironrdp-client --features rustls           # no new warnings vs base
```

The merge conflict was limited to `crates/ironrdp-client/src/rdp.rs`. The
resolution retained upstream input batching, keepalive, UDP `ConnectOutput`, and
desktop-damage coalescing while reapplying the relay and full-frame request.

Both client feature sets are checked because `warn` is imported only under
`clipboard` while some always-compiled code uses it.

A real RDP session against a Windows host — connect, resize, clipboard, and
certificate prompt — is not covered by any of the above and remains a manual step.


## Authenticated loopback route for remote-desktop network parity

`ConfigBuilder::with_direct_tcp_proxy` redirects only the direct TCP connection,
then sends a bounded authentication preamble. The original destination continues
to drive TLS and CredSSP identity; the relay address is never substituted there.
Only loopback endpoints are accepted. Authentication bytes are omitted from Debug.
This patch is based on c44dcc77, which also merges upstream gateway authentication
8649c7c6 after NyaTerm's previously pinned 75d9a3b3.
Validation: Windows client build with rustls + clipboard; focused identity test.

## 2026-10-01 upstream merge

Merged upstream master without content conflicts. NyaTerm full-frame
resynchronisation, loopback relay routing and authentication policy remain.
Windows validation passed: `cargo check -p ironrdp-client --features rustls`,
`cargo check -p ironrdp-client --features rustls,clipboard`,
`cargo check -p ironrdp-connector -p ironrdp-acceptor -p ironrdp-vmconnect`,
and `cargo test -p ironrdp-connector`. The consumer's SSPI fork is validated
separately and selected by NyaTerm's workspace patch.

## 2026-10-13 upstream rebase

Upstream `master` is fixed at `e4143f26306a6639a889d80c1c484ca69c365a8f`.
Previous published NyaTerm head: `e6cae7c73bbaf093af96bd985e36261efc706038`.
The previous branch is retained locally as `backup/nyaterm-20261013`.

The effective old-base-to-fork tree (including merge-only resolutions) was
reconstructed byte-for-byte as separate concern commits before rebasing.
Old upstream merge history was flattened; no functional net change was discarded
except the explicitly documented upstream replacements below. The concern
commits and subsequent compatibility fixes remain separate.

| Concern | Reconstructed commit on old base |
| --- | --- |
| SSPI compatibility | `fe6c657b3047a32fe486f6fbcb7f26906fd5d382` |
| authenticated loopback routes | `2977e2bb25835691740ac1b52d231c9ee626e2a0` |
| full-frame resynchronisation | `b7e25584cbc62a90762dcf751edb37fdc5dfd0fb` |
| disabled smart-card authentication | `fd07a0978ea26af8a61c40f420472d205b96da05` |
| fork validation | `2ddbf9a8ea1cb818eb2203a03e8a2f810a35b50c` |
| fork documentation | `b33a5ae8f4714a918020a55473c490ae4872e8b1` |

Replay commits before this documentation update:

- `531bfa28b1b5ba92ecc4db7355759d572241c253` build(fork): preserve SSPI compatibility
- `29ad95f16518bea56bd67b0277e04e7437981430` feat(fork): preserve authenticated loopback routes
- `600b266276db156e335351825b74af84be50de7e` feat(fork): preserve full-frame resynchronisation
- `c7f76e8507b4c86ab00856ec7da90db916561e5e` feat(fork): preserve disabled smart-card authentication
- `6b4ad477e1ef0bc40f76eb60e4476d118d629095` ci(fork): preserve fork validation
- `1714064abb461ce6be31cd6c51ad144d76355f26` docs(fork): preserve fork documentation
- `027eecece68976d4734ce3736d68ba9c97a23e9e` build(deps): align standalone authentication with SSPI 0.23
- `bf99e9d47222bb2dd5d01ce4b8e12a05fec6916e` ci(client): run full-frame and destination identity regressions

All direct SSPI requirements now accept 0.23. The standalone workspace patches
SSPI to nyakang/sspi-rs revision d2b04e63ca9a72f2a70b456186e2472b27f0d45d,
matching NyaTerm's consumer patch and avoiding the yanked/missing GSS API baseline.
Fallible CredSSP writes, deliberate smart-card exclusion, full-frame requests,
validated authenticated loopback routing, original TLS/CredSSP target identity
and TCP-only relay policy remain in their individual patches.

Windows standalone published-SSPI checks passed: client with rustls+clipboard,
connector/acceptor/VMConnect, and 19 client library tests including full-frame
coverage and loopback proxy original-server identity. The client also checked
with rustls alone under local source overrides. Connector test target compiled
but contains no enabled tests; the client library suite provides actual regression
execution and has been added to fork CI. Client clippy passed with baseline
warnings (MSRV mismatch plus std/core import style); scoped fmt passed.


Validation is on Windows; native macOS/Linux checks are delegated to the
branch workflow. Interactive GUI/file-drop and real-server authentication
checks were not performed by this update. Their outcomes must not be inferred
from scripted peers or compile checks.

## 2026-10-20 upstream rebase

Fixed upstream master: `aed5ce8ba225c6d2b17ab39b0d12b3fc65e565bd`.
Previous published head: `56dd8686723423f2a570598ed66d2df6fd90f547`.
Original branch is retained locally as `backup/nyaterm-20261020`.

Upstream #2080 (`build(connector)!: update sspi to 0.23 and picky to rc.26`)
now supplies the old SSPI version and fallible CredSSP length compatibility.
Drop the redundant `531bfa28` patch, retaining upstream's error propagation.
Keep the NyaTerm SSPI git source override, username/password-only connector,
authenticated loopback routes, original TLS/CredSSP destination, TCP-only relay
policy and full-frame resynchronisation. The standalone lock removes the now
unused connector-to-picky edge without refreshing unrelated packages.

Windows validation passed with the pinned 1.94.1 toolchain:
- client checks with rustls and with rustls+clipboard;
- connector, acceptor and VMConnect checks;
- all 19 client library regressions, including full-frame and original target;
- client library Clippy (existing upstream warnings) and scoped formatting.
Real RDP/NLA, clipboard and relay server interoperability was not run locally.
The branch workflow verifies Linux after publication.
