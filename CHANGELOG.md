# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

### Fixed

**`remove` apagava o `.env` mesmo sem `--delete-dir` (#3)**
- Com o diretório preservado, apenas os logs do app são removidos; `.env` e demais arquivos do usuário permanecem intactos

### Added

**`set-node-version` (#3)**
- Permite trocar o runtime Node.js de um app já registrado sem recriá-lo
- A resposta traz `restart_required: true` quando o app está em execução
- Valores de metadados (`cwd`, `domain`, `subdomain`, `node_version`) passam a rejeitar quebras de linha e bytes nulos, que forjariam chaves no arquivo `.app`

---

## [1.1.0] — 2026-03-29

### Added

**Adaptive readiness detection for Unix sockets**
- Replaced fixed timeouts with progress detection via `/proc/{pid}/stat` (CPU ticks) and `/proc/{pid}/status` (VmRSS)
- Process is terminated only when it shows no CPU or RSS delta over 4 consecutive checks of 2.5s (10s of confirmed inactivity) — `socket_stuck` error
- Absolute ceiling of 120s kept as a safety fallback
- New helpers in `proc.rs`: `read_proc_cpu_ticks`, `read_proc_rss_kb`, `ProcessSnapshot`, `read_proc_snapshot`

---

## [1.0.0] — 2026-03-24

Initial production release.

### Added

**CLI and commands**
- Subcommands: `list`, `status`, `start`, `stop`, `restart`, `add`, `remove`, `logs`, `domains`
- `admin` group: `version`, `list`, `detect-nodes`, `save-node-versions`
- Global `--debug` flag — adds `_debug` to the JSON output
- `SELYNT_DEBUG=1` environment variable — enables diagnostic logs on stderr

**Process management**
- Support for multiple app types with type-specific behavior in `start` and `add`
- Processes spawned with `setsid()` via `pre_exec` — each app becomes the leader of a new session
- `stop`: SIGTERM → 200 ms poll → SIGKILL after timeout (default 10s, configurable via `--timeout`)
- `restart`: sequential stop + start
- Unix socket readiness detection: waits for creation and accepts a connection before returning success
- Per-type configurable socket timeout
- Network port blocking: any app opening TCP/UDP is terminated with `network_port_forbidden`
- Detection of installed runtimes via `admin detect-nodes` with support for fixed paths, NVM, CloudLinux (`opt/alt`) and `NVM_DIR`
- Selected runtimes persisted to `{plugin}/etc/node_versions`

**Security and privilege**
- Setuid root binary; requires `euid=0` at entry
- Privilege drop: `initgroups` + `setgid` + `setuid` + `prctl(PR_SET_NO_NEW_PRIVS)` before executing commands
- Anti PID-reuse: PID validated against `starttime` from `/proc/{pid}/stat`
- Process UID validation via `/proc/{pid}/status`
- Path traversal validation on `name`, `entry` and `host` (`..`, `/`, null bytes)
- Atomic `.app` creation via `create_new` (prevents TOCTOU)
- ACL on Unix socket and proxy marker via `setfacl`; fallback to `chmod` (711/600/604)

**State and logs**
- State dir at `/var/lib/selynt_panel/{user}/` with subdirs `.run/`, `.sockets/`, `.proxy/`
- Atomic state file writes (write `.tmp` + rename)
- Environment variables read from `.env` in the app's cwd at start time
- Automatic log rotation: files larger than 50 MB are truncated keeping the last 5,000 lines
- Log reading via reverse tail in 8 KB chunks (does not load the whole file)

**DirectAdmin integration**
- Reads `domains.list` and `{domain}.subdomains` as root before the privilege drop
- Communicates with the DA daemon over HTTP/1.0 on a Unix socket (`da.rs`)
- Supports `COOKIESTRING`, `HTTP_COOKIE` and `SESSION` for CGI authentication
- `admin list` collects data from all users in `/var/lib/selynt_panel/` as root

---

## Copyright

Copyright © 2026 [NullSablex](https://github.com/NullSablex). Licensed under [GNU AGPL-3.0-or-later](LICENSE).
