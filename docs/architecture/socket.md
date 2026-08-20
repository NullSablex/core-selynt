# Socket communication

Apps **must** listen on a Unix socket. The socket path is provided via `SELYNT_HOST` and `SELYNT_SOCKET`.

Applications that open TCP or UDP ports are **terminated immediately** (`SIGTERM` + `SIGKILL`) and the `network_port_forbidden` error is returned.
