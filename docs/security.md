# Security

- **Immediate privilege drop:** `initgroups` + `setgid` + `setuid` + `prctl(PR_SET_NO_NEW_PRIVS)` before any business logic
- **`setsid` on child processes:** each app is spawned with `setsid()` via `pre_exec`, making it a session leader and preventing signals from leaking to the parent process
- **Anti PID-reuse:** the PID is validated against the `starttime` from `/proc/{pid}/stat` before sending signals
- **UID validation:** `status` only reports RUNNING if the PID belongs to the current user (`/proc/{pid}/status`)
- **Network port blocking:** TCP/UDP are checked via `/proc/net/{tcp,tcp6,udp,udp6}` after start
- **Socket ACL:** `setfacl` with fallback to `chmod` for the web user
- **Path traversal validation:** app names and `entry`/`host` are validated against `..`, `/` and null bytes
- **Atomic creation:** `.app` files use `create_new` to avoid TOCTOU race conditions
- **Log rotation:** files larger than 50 MB are truncated keeping the last 5,000 lines
