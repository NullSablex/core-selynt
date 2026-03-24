<p align="center">
  <img src="img/logo.png" alt="Selynt Panel" width="120" />
</p>

<h1 align="center">Core Selynt</h1>

<p align="center">
  Binário setuid root do <strong>Selynt Panel</strong> — gerenciador de processos para aplicações web em servidores DirectAdmin.
</p>

<p align="center">
  <a href="https://github.com/NullSablex/core-selynt/releases"><img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0--or--later-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square&logo=linux" alt="Linux">
  <img src="https://img.shields.io/badge/DirectAdmin-plugin-blueviolet?style=flat-square" alt="DirectAdmin">
  <a href="https://github.com/NullSablex/core-selynt/actions/workflows/ci.yml"><img src="https://github.com/NullSablex/core-selynt/actions/workflows/ci.yml/badge.svg?branch=master" alt="CI"></a>
</p>

> [!WARNING]
> Este projeto está em desenvolvimento ativo. Algumas funcionalidades podem apresentar instabilidades ou mudanças de comportamento entre versões. Não é recomendado para ambientes de produção sem validação prévia.

---

## Visão geral

`core-selynt` é invocado pelo plugin do Selynt Panel. Cada execução:

1. Exige `euid=0` (setuid obrigatório)
2. Resolve o usuário real via variável `USERNAME` → `/etc/passwd`
3. Cria/valida o diretório de estado em `/var/lib/selynt_panel/{user}/`
4. Faz **drop de privilégio** (`setuid`/`setgid`/`initgroups` + `PR_SET_NO_NEW_PRIVS`) antes de executar qualquer lógica
5. Retorna JSON em stdout e sai com código `0` (sucesso), `1` (erro de usuário) ou `2` (erro de sistema)

---

## Build

> [!IMPORTANT]
> O binário **deve** ser compilado com o target `x86_64-unknown-linux-musl` para gerar um executável estático, sem dependência de glibc do host. Compilar sem esse target produz um binário incompatível com servidores DirectAdmin que utilizem versões diferentes de glibc.

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

O binário gerado estará em `target/x86_64-unknown-linux-musl/release/core-selynt`.

O perfil `release` já está configurado no `Cargo.toml` com `strip`, `lto`, `opt-level = "z"`, `codegen-units = 1` e `panic = "abort"`.

---

## Instalação

O binário deve ser instalado no diretório do plugin com o bit setuid:

```bash
install -o root -g root -m 4755 target/x86_64-unknown-linux-musl/release/core-selynt \
    /usr/local/directadmin/plugins/selynt_panel/bin/core-selynt
```

Verificar:
```
-rwsr-xr-x 1 root root ... core-selynt
```

---

## Uso

```
core-selynt [--debug] <COMANDO>
```

A flag `--debug` inclui um campo `_debug` no JSON de saída com `user`, `home` e `state_dir`.

Para debug em stderr durante desenvolvimento, definir `SELYNT_DEBUG=1`.

---

## Comandos

### Gerenciamento de apps

```
list                              Lista apps registrados do usuário
status <name>                     Status (RUNNING/STOPPED) e PID
start  <name>                     Inicia o app
stop   <name> [--timeout N]       Para o app (padrão: 10s)
restart <name>                    Para e reinicia
add    <name> ...                 Registra novo app
remove <name> [--delete-dir]      Remove o app (e opcionalmente o cwd)
logs   <name> [--lines N]         Últimas N linhas de log stdout (padrão: 100)
       [--stderr]                 Ler stderr em vez de stdout
domains [--domain D]              Lista domínios/subdomínios do usuário
```

### Opções de `add`

```
--type <tipo>            Tipo do app (obrigatório; ver tipos suportados)
--entry <arquivo>        Nome do arquivo de entrada (sem path, relativo ao cwd)
--host  <valor>          Identificador de host (usado como nome do socket Unix)
--cwd   <diretório>      Diretório raiz do app (padrão: apps/nodejs/{host})
--domain <domínio>       Domínio associado (opcional)
--subdomain <subdomínio> Subdomínio associado (opcional)
--node-version <path>    Caminho para o binário runtime (opcional; usa o do PATH se omitido)
--env KEY=VAL            Variável de ambiente (repetível)
```

### Comandos admin (requer `diradmin`)

```
admin version                        Versão do binário
admin list                           Apps de todos os usuários
admin detect-nodes                   Detecta runtimes instalados no sistema
admin save-node-versions <idx...>    Salva versões selecionadas por índice
```

---

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|---|---|---|
| `USERNAME` | Sim | Usuário real para o qual o comando é executado |
| `SELYNT_STATE_DIR` | Não | Sobrescreve o state dir (deve começar com `/var/lib/selynt_panel/`) |
| `SELYNT_WEB_USER` | Não | Usuário web para ACL (alternativa ao arquivo `etc/ols_web_user`) |
| `SELYNT_DEBUG` | Não | `1` para logs de debug em stderr |
| `NVM_DIR` | Não | Usado por `admin detect-nodes` para encontrar versões NVM |

---

## Comportamento por tipo de app

> [!NOTE]
> Cada tipo de app possui tratamento específico no `start` e no `add`. O suporte a novos tipos pode ser adicionado em versões futuras. Variáveis de ambiente são sempre lidas do arquivo `.env` no cwd do app no momento do `start`, independente do tipo.

---

## Comunicação via socket

Apps **devem** escutar em Unix socket. O caminho do socket é passado via `SELYNT_HOST` e `SELYNT_SOCKET`.

Aplicações que abrirem portas TCP ou UDP são **encerradas imediatamente** (`SIGTERM` + `SIGKILL`) e o erro `network_port_forbidden` é retornado.

---

## Estrutura de estado

```
/var/lib/selynt_panel/{user}/
├── .run/
│   ├── {name}.app     # Metadados (type, cwd, entry, host, ...)
│   ├── {name}.pid     # PID atual
│   └── {name}.meta    # uid + starttime + started_at (anti PID-reuse)
├── .sockets/
│   └── {host}         # Unix socket do app
└── .proxy/
    └── {host}         # Marker de readiness para o proxy reverso

{cwd}/
├── .env               # Variáveis de ambiente do app
└── logs/
    ├── {name}.out.log
    └── {name}.err.log
```

---

## Segurança

- **Drop de privilégio imediato:** `initgroups` + `setgid` + `setuid` + `prctl(PR_SET_NO_NEW_PRIVS)` antes de qualquer lógica de negócio
- **Setsid em processos filhos:** cada app é spawnado com `setsid()` via `pre_exec`, tornando-o líder de sessão e evitando que sinais vazem para o processo pai
- **Anti PID-reuse:** o PID é validado contra o `starttime` de `/proc/{pid}/stat` antes de enviar sinais
- **Validação de UID:** `status` só reporta RUNNING se o PID pertencer ao usuário atual (`/proc/{pid}/status`)
- **Bloqueio de portas de rede:** TCP/UDP são verificados via `/proc/net/{tcp,tcp6,udp,udp6}` após o start
- **ACL no socket:** `setfacl` com fallback para `chmod` para o usuário web
- **Validação de path traversal:** nomes de apps e `entry`/`host` são validados contra `..`, `/` e bytes nulos
- **Criação atômica:** arquivos `.app` usam `create_new` para evitar race condition TOCTOU
- **Log rotation:** arquivos maiores que 50 MB são truncados mantendo as últimas 5.000 linhas

---

## Licença

Copyright © 2026 [NullSablex](https://github.com/NullSablex). Licenciado sob a [GNU AGPL-3.0-or-later](LICENSE).
