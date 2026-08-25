---
hide:
  - navigation
---

<p align="center">
  <img src="assets/logo.png" alt="Selynt Panel" width="120" />
</p>

# Core Selynt

Setuid root binary of **Selynt Panel** — process manager for web applications on DirectAdmin servers.

!!! warning
    This project is under active development. Some features may be unstable or change behavior between versions. It is not recommended for production environments without prior validation.

## Overview

`core-selynt` is invoked by the Selynt Panel plugin. Each execution:

1. Requires `euid=0` (setuid mandatory)
2. Resolves the real user via the `USERNAME` variable → `/etc/passwd`
3. Creates/validates the state directory in `/var/lib/selynt_panel/{user}/`
4. Performs **privilege drop** (`setuid`/`setgid`/`initgroups` + `PR_SET_NO_NEW_PRIVS`) before executing any logic
5. Returns JSON on stdout and exits with code `0` (success), `1` (user error) or `2` (system error)

## Quick links

- [Build & Installation](build.md)
- [Commands](usage/commands.md)
- [Environment variables](usage/environment.md)
- [State structure](architecture/state.md)
- [Socket communication](architecture/socket.md)
- [Security](security.md)

## License

Copyright © 2026 [NullSablex](https://github.com/NullSablex). Licensed under [GNU AGPL-3.0-or-later](https://github.com/NullSablex/core-selynt/blob/master/LICENSE).
