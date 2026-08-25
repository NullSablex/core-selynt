# Commands

## Invocation

```
core-selynt [--debug] <COMMAND>
```

The `--debug` flag includes a `_debug` field in the JSON output with `user`, `home` and `state_dir`.

For debug logging on stderr during development, set `SELYNT_DEBUG=1`.

## App management

```
list                              List the user's registered apps
status <name>                     Status (RUNNING/STOPPED) and PID
start  <name>                     Start the app
stop   <name> [--timeout N]       Stop the app (default: 10s)
restart <name>                    Stop and restart
add    <name> ...                 Register a new app
remove <name> [--delete-dir]      Remove the app (and optionally the cwd)
logs   <name> [--lines N]         Last N lines of stdout log (default: 100)
       [--stderr]                 Read stderr instead of stdout
domains [--domain D]              List the user's domains/subdomains
```

## `add` options

```
--type <type>             App type (required; see supported types)
--entry <file>            Entry file name (no path, relative to cwd)
--host  <value>           Host identifier (used as the Unix socket name)
--cwd   <directory>       App root directory (default: apps/nodejs/{host})
--domain <domain>         Associated domain (optional)
--subdomain <subdomain>   Associated subdomain (optional)
--node-version <path>     Path to the runtime binary (optional; uses PATH if omitted)
--env KEY=VAL             Environment variable (repeatable)
```

## Admin commands (requires `diradmin`)

```
admin version                        Binary version
admin list                           Apps from all users
admin detect-nodes                   Detect runtimes installed on the system
admin save-node-versions <idx...>    Save selected versions by index
```

## Behavior by app type

!!! note
    Each app type has specific handling in `start` and `add`. Support for new types may be added in future versions. Environment variables are always read from the `.env` file in the app's cwd at the moment of `start`, regardless of type.
