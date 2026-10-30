# aether-wg-relay

Runs a standard WireGuard configuration (for example a Proton VPN Free `.conf`)
**through an unmodified [Aether](https://github.com/CluvexStudio/Aether) core**.

```
app -> local SOCKS5 (127.0.0.1:1817) -> userspace WireGuard
    -> SOCKS5 UDP ASSOCIATE -> Aether (MASQUE) -> VPN server -> internet
```

* The Aether core is not modified. The relay only uses Aether's public SOCKS5 port.
* WireGuard runs in userspace (amneziawg-go with every obfuscation option off, which is
  plain WireGuard). No kernel module and no `wireguard-tools` are needed.
* There is no direct-UDP path. If the SOCKS association is lost, WireGuard packets are
  dropped, never sent straight to the VPN endpoint.
* `PostUp`/`PostDown`/`PreUp`/`PreDown` lines in the imported config are refused.

Used by [aether-openwrt-client](../aether-openwrt-client); the client downloads the
release binary only when the user enables the feature.

## Usage

```sh
aether-wg-relay -conf /etc/aether/wg/proton.conf \
                -aether 127.0.0.1:1819 \
                -listen 127.0.0.1:1817 \
                -mtu 1380
curl -x socks5h://127.0.0.1:1817 https://ipinfo.io/json
```

| Flag | Default | Meaning |
|---|---|---|
| `-conf` | (required) | WireGuard `.conf`; read only, never modified |
| `-aether` | `127.0.0.1:18190` | Aether SOCKS5 address (MASQUE mode) |
| `-listen` | `127.0.0.1:1817` | local SOCKS5 whose exit is the inner VPN |
| `-mtu` | `1160` | inner tunnel MTU (1380 was faster than 1280 and 1160 in lab tests) |
| `-v` | off | verbose WireGuard log |
| `-version` | | print version |

Start Aether first (the relay also waits up to 3 s for the first association). If Aether stops or restarts,\nthe relay drops WireGuard packets (never sends directly), re-associates with backoff (1, 2, 4, 5 s...), and\nnudges the WireGuard peer so traffic resumes on its own.

## Releases

The workflow runs **only** when a release tag `vX.Y.Z` is pushed (not on ordinary pushes or PRs). It runs vet/tests, builds static binaries and publishes them with `SHA256SUMS`:

| Asset | Target |
|---|---|
| `aether-wg-relay-linux-x86_64` | x86_64 |
| `aether-wg-relay-linux-aarch64` | arm64 |
| `aether-wg-relay-linux-armv7` | ARMv7 (GOARM=7) |

All are `CGO_ENABLED=0`, so they run on musl (OpenWrt) without extra libraries.

```sh
git tag v0.1.0 && git push origin v0.1.0
```

## Build locally

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" -o aether-wg-relay ./cmd/aether-wg-relay
```

The Go module path is `github.com/moein8668-git/aether-wg-relay`.

`udp_assoc_test.py` checks that an Aether SOCKS port supports UDP ASSOCIATE
(`python udp_assoc_test.py 1819`), independent of WireGuard.

## Tested so far

OpenWrt 25.12.5 x86_64, Aether 2.4.0 (MASQUE over HTTP/2), Proton Free NL peer: handshake, bidirectional traffic, HTTPS exit through Proton, no direct UDP to the peer, no fallback when Aether is stopped, and automatic recovery over 3 consecutive Aether stop/start cycles (6-25 s including Aether's own start). Unit tests cover SOCKS UDP framing, reconnect after control loss, late SOCKS start, and Close/reopen. Not yet done: H3, IPv6, long soak, other architectures on real hardware.
