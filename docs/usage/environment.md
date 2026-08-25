# Environment variables

| Variable | Required | Description |
|---|---|---|
| `USERNAME` | Yes | The real user the command is executed for |
| `SELYNT_STATE_DIR` | No | Overrides the state dir (must begin with `/var/lib/selynt_panel/`) |
| `SELYNT_WEB_USER` | No | Web user for ACL (alternative to the `etc/ols_web_user` file) |
| `SELYNT_DEBUG` | No | `1` to enable debug logs on stderr |
| `NVM_DIR` | No | Used by `admin detect-nodes` to find NVM versions |
