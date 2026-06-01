# TinyWifi

Management for a Wi-Fi access point on a Raspberry Pi / embedded Linux:
a web panel and a background display daemon on top of `hostapd` and `nanodhcp`.

Core project rule: **always check that a service/file/interface is available
before reading, restarting, or rendering** — never panic on a missing config or
service; everything degrades gracefully.

## Layout

A Cargo workspace of three crates:

| Crate | Purpose |
|---|---|
| `tinywifi-core` | Shared logic: file/service/interface checks, config parsers (hostapd, nanodhcp), leases, host metrics, the status model, and safe edits with rollback. |
| `tinywifi-web` | axum HTTP panel: dashboard, Wi-Fi/DHCP/Leases/System pages, and the REST API. |
| `tinywifi-display` | Daemon that draws device status (console for now, a real screen driver later via the `Renderer` trait). |

## Build

```bash
cargo build --release
```

Binaries: `target/release/tinywifi-web`, `target/release/tinywifi-display`.

On an embedded target (Buildroot/glibc, aarch64) a binary built on a host with
an older glibc runs forward-compatibly.

## Configuration

`tinywifi-web` and `tinywifi-display` read a TOML application config. Path
resolution: `$TINYWIFI_CONFIG`, then `/etc/tinywifi/tinywifi.toml`, then the
in-repo `configs/tinywifi.toml`.

```toml
[web]
listen = "0.0.0.0:80"

[display]
refresh_secs = 5

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

Target file formats:
- `hostapd.conf` — standard `key=value`; edits are line-preserving (comments and
  unknown directives survive a round-trip).
- `nanodhcp.conf` — `key=value` (`pool_start`/`pool_end`/`router`/`lease_file`,
  etc.); unknown keys are preserved on write.

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
