# State structure

```
/var/lib/selynt_panel/{user}/
├── .run/
│   ├── {name}.app     # Metadata (type, cwd, entry, host, ...)
│   ├── {name}.pid     # Current PID
│   └── {name}.meta    # uid + starttime + started_at (anti PID-reuse)
├── .sockets/
│   └── {host}         # App's Unix socket
└── .proxy/
    └── {host}         # Readiness marker for the reverse proxy

{cwd}/
├── .env               # App environment variables
└── logs/
    ├── {name}.out.log
    └── {name}.err.log
```
