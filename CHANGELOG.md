# Changelog

Todas as mudanças notáveis neste projeto são documentadas aqui.
Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) · Versionamento: [SemVer](https://semver.org/lang/pt-BR/).

---

## [1.1.0] — 2026-03-29

### Adicionado

**Detecção adaptativa de readiness do socket Unix**
- Substituídos timeouts fixos por detecção de progresso via `/proc/{pid}/stat` (CPU ticks) e `/proc/{pid}/status` (VmRSS)
- Processo encerrado apenas quando não apresenta delta de CPU nem de RSS por 4 checks consecutivos de 2.5s (10s de inatividade confirmada) — erro `socket_stuck`
- Teto absoluto de 120s mantido como fallback de segurança
- Novos helpers em `proc.rs`: `read_proc_cpu_ticks`, `read_proc_rss_kb`, `ProcessSnapshot`, `read_proc_snapshot`

---

## [1.0.0] — 2026-03-24

Versão inicial de produção.

### Adicionado

**CLI e comandos**
- Subcomandos: `list`, `status`, `start`, `stop`, `restart`, `add`, `remove`, `logs`, `domains`
- Grupo `admin`: `version`, `list`, `detect-nodes`, `save-node-versions`
- Flag global `--debug` — adiciona `_debug` ao JSON de saída
- Variável `SELYNT_DEBUG=1` — ativa logs de diagnóstico em stderr

**Gerenciamento de processos**
- Suporte a múltiplos tipos de app com comportamento específico por tipo no `start` e no `add`
- Processos spawnados com `setsid()` via `pre_exec` — cada app é líder de nova sessão
- `stop`: SIGTERM → poll de 200 ms → SIGKILL após timeout (padrão 10 s, configurável via `--timeout`)
- `restart`: stop + start sequencial
- Detecção de readiness por socket Unix: aguarda criação e aceita conexão antes de retornar sucesso
- Timeout de socket configurável por tipo de app
- Bloqueio de portas de rede: app que abrir TCP/UDP é encerrado com `network_port_forbidden`
- Detecção de runtimes instalados via `admin detect-nodes` com suporte a paths fixos, NVM, CloudLinux (`opt/alt`) e `NVM_DIR`
- Persistência de runtimes selecionados em `{plugin}/etc/node_versions`

**Segurança e privilégio**
- Binário setuid root; exige `euid=0` na entrada
- Drop de privilégio: `initgroups` + `setgid` + `setuid` + `prctl(PR_SET_NO_NEW_PRIVS)` antes de executar comandos
- Anti PID-reuse: PID validado contra `starttime` de `/proc/{pid}/stat`
- Validação de UID do processo via `/proc/{pid}/status`
- Validação de path traversal em `name`, `entry` e `host` (`..`, `/`, bytes nulos)
- Criação atômica de `.app` via `create_new` (previne TOCTOU)
- ACL no socket Unix e no marker de proxy via `setfacl`; fallback para `chmod` (711/600/604)

**Estado e logs**
- State dir em `/var/lib/selynt_panel/{user}/` com subdirs `.run/`, `.sockets/`, `.proxy/`
- Escrita atômica de arquivos de estado (write `.tmp` + rename)
- Variáveis de ambiente lidas do `.env` no cwd do app no momento do start
- Log rotation automática: arquivos > 50 MB são truncados mantendo 5.000 linhas
- Leitura de log por tail reverso em chunks de 8 KB (sem carregar o arquivo inteiro)

**Integração DirectAdmin**
- Leitura de `domains.list` e `{domain}.subdomains` como root antes do drop de privilégio
- Comunicação com o daemon DA via HTTP/1.0 sobre Unix socket (`da.rs`)
- Suporte a `COOKIESTRING`, `HTTP_COOKIE` e `SESSION` para autenticação CGI
- `admin list` coleta dados de todos os usuários em `/var/lib/selynt_panel/` como root

---

## Copyright

Copyright © 2026 [NullSablex](https://github.com/NullSablex). Licenciado sob a [GNU AGPL-3.0-or-later](LICENSE).
