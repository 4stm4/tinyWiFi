# TinyWifi

Management for a Wi-Fi access point on a Raspberry Pi / embedded Linux:
a web panel and a background display daemon on top of `hostapd` and `nanodhcp`.

Hardware target: **Raspberry Pi Zero 2W** with a Waveshare 2.13″ V3 e-paper
display (SSD1675B, 122×250 px, SPI).

Core project rule: **always check that a service/file/interface is available
before reading, restarting, or rendering** — never panic on a missing config or
service; everything degrades gracefully.

## Layout

A Cargo workspace of three crates:

| Crate | Purpose |
|---|---|
| `tinywifi-core` | Shared logic: file/service/interface checks, config parsers (hostapd, nanodhcp), leases, host metrics, the status model, and safe edits with rollback. |
| `tinywifi-web` | axum HTTP panel: dashboard, Wi-Fi/DHCP/Leases/System pages, and the REST API. |
| `tinywifi-display` | Daemon that renders device status on a Waveshare 2.13″ e-paper display (SSD1675B driver via `embedded-graphics`). Falls back to console output when SPI is unavailable. |

## Build

```bash
cargo build --release
```

Binaries: `target/release/tinywifi-web`, `target/release/tinywifi-display`.

Cross-compile for Pi Zero 2W (aarch64-unknown-linux-gnu) on a faster host, then
push the binary over SSH — the Pi Zero itself is too slow for a full build.

## Configuration

`tinywifi-web` and `tinywifi-display` read a TOML application config. Path
resolution: `$TINYWIFI_CONFIG`, then `/etc/tinywifi/tinywifi.toml`, then the
in-repo `configs/tinywifi.toml`.

```toml
[web]
listen = "0.0.0.0:443"
http_redirect_listen = "0.0.0.0:80"

[display]
refresh_secs = 60

[paths]
hostapd_conf  = "/etc/hostapd/hostapd.conf"
nanodhcp_conf = "/etc/nanodhcp/nanodhcp.conf"
leases_file   = "/var/lib/nanodhcp/leases"

[services]
hostapd  = "hostapd"
nanodhcp = "nanodhcp"
web      = "tinywifi-web"
display  = "tinywifi-display"
```

`listen` is the HTTPS address; `http_redirect_listen` is a plain-HTTP
listener that 301-redirects every request to HTTPS. On first boot
`tinywifi-web` generates a self-signed certificate into `/etc/tinywifi/tls/`
(there's no domain name on a LAN device, so the browser will show a
"not trusted" warning on first visit — expected, click through once).
Configs written before this feature existed still parse: a missing
`http_redirect_listen` defaults to `0.0.0.0:80`.

Target file formats:
- `hostapd.conf` — standard `key=value`; edits are line-preserving (comments and
  unknown directives survive a round-trip).
- `nanodhcp.conf` — `key=value` (`pool_start`/`pool_end`/`router`/`lease_file`,
  etc.); unknown keys are preserved on write.

## Wi-Fi client compatibility

Modern mobile clients (iOS 17+, Android 12+) require **Protected Management
Frames** (PMF / 802.11w) to complete a WPA2 handshake. Without PMF the client
associates but immediately disassociates before the 4-way handshake — from the
outside it looks like a wrong password.

The reference config at [`configs/hostapd.conf`](configs/hostapd.conf) is set
correctly:

```
wpa_key_mgmt=WPA-PSK   # single AKM — do not add WPA-PSK-SHA256 here
rsn_pairwise=CCMP
ieee80211w=1            # PMF optional (compatible with old and new clients)
okc=0
```

**Important:** listing two key-management suites (`WPA-PSK WPA-PSK-SHA256`)
causes a PMKSA cache mismatch on reconnect — the client connects once, caches
a PMKSA under one AKM, then on the next reconnect the PMKID check fails against
the other AKM, producing an infinite associate/disassociate loop. Use exactly
one suite.

## REST API

| Method | Path | Description |
|---|---|---|
| GET | `/api/status` | Status of hostapd/nanodhcp/leases/interface |
| GET/POST | `/api/wifi` | Read/edit SSID, password, country, channel |
| POST | `/api/wifi/confirm` | Confirm a pending Wi-Fi edit |
| GET/POST | `/api/dhcp` | Read/edit the pool, gateway, DNS, lease time |
| POST | `/api/dhcp/confirm` | Confirm a pending DHCP edit |
| GET | `/api/leases` | Active DHCP clients |
| GET | `/api/services` | Service statuses |
| POST | `/api/services/:name/restart` | Restart a service |
| POST | `/api/system/reboot` | Reboot the device |

### Safe edits (commit-confirm)

`POST /api/wifi?hold=<seconds>` (and likewise `/api/dhcp`) applies the change
and arms an **auto-revert**: if no `POST /api/wifi/confirm` arrives within
`hold` seconds, the config is restored from its `.bak` and the service is
restarted on the old settings. This protects against locking yourself out when
changing the SSID/password severs the very link you administer over.

A plain `POST` (no `hold`) commits as soon as the service comes back up; on a
failed restart it rolls back immediately.

## Init systems

The service layer detects the manager once and works on top of:
- **systemd** (`systemctl`);
- **SysV-init** (`/etc/init.d/Sxx`, Buildroot/busybox) — status via a `/proc`
  scan, lifecycle via init scripts;
- otherwise status by process scan, with lifecycle unavailable.

For embedded deployment helpers (per-service init scripts, an example config),
see [`deploy/`](deploy/).

## Tests

```bash
cargo test --workspace
cargo clippy --all-targets
```
