# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

### Security

As falhas abaixo têm a mesma causa: o binário é setuid root e executável por
qualquer um, mas confiava em valores fornecidos pelo próprio chamador —
variáveis de ambiente e caminhos. Qualquer conta local em servidor compartilhado
conseguia explorá-las; todas foram confirmadas em uma instalação real antes da
correção.

**Escalação de privilégio via `USERNAME`**
- `resolve_target_user` lia `USERNAME` do ambiente sem verificar se o chamador
  tinha direito àquele nome, então `USERNAME=vitima core-selynt …` permitia a
  qualquer usuário local operar sobre os apps e o estado de outra pessoa — como
  root, já que o drop de privilégio mira o usuário *resolvido*
- A autoridade passa a vir do uid real (preservado pelo setuid): root e o web
  user do painel podem nomear qualquer conta; os demais agem apenas como si
  mesmos
- Nova `state::caller_is_privileged()` centraliza essa decisão de confiança

**Comandos `admin` sem autenticação**
- Os subcomandos `Admin` estavam documentados como "requires `diradmin`", mas
  não verificavam nada: qualquer usuário local rodava `admin list` e lia o
  inventário de apps de todos os clientes (caminhos de home, domínios, tipos)
- `Admin` agora exige root ou o web user do painel, rejeitando os demais com
  `admin_required`

**Execução de código arbitrário como root via `NVM_DIR`**
- `detect_node_versions` *executa* cada candidato para ler `--version`, e
  aceitava `NVM_DIR` sob `/home/` — o home de todo cliente em servidor
  compartilhado. Alcançado por `save-node-versions`, que roda no prelude como
  root, um `~/versions/node/*/bin/node` plantado seria executado com privilégio
- `NVM_DIR` passa a aceitar apenas `/opt/` e `/usr/local/`; a guarda de `..`
  nunca foi suficiente, pois o próprio caminho do home já satisfazia o filtro

**Controle cruzado de apps via `SELYNT_STATE_DIR`**
- O override validava só o prefixo `/var/lib/selynt_panel/`, então
  `/var/lib/selynt_panel/<outro-usuário>` passava — expondo os apps de outro
  usuário a `list`, e igualmente a `start`, `stop` e `remove`
- O override agora só é aceito de chamador privilegiado; os demais ficam presos
  ao próprio state dir

**`SELYNT_WEB_USER` não é mais definível por chamador sem privilégio**
- Esse valor decide a quem as ACLs são concedidas; passa a ser lido do
  `etc/ols_web_user` (propriedade de root), exceto quando o chamador é root

**Destruição de dados via symlink no `cwd`**
- O `cwd` não era confinado ao home: aceitava `/tmp` e `/var/tmp` (graváveis por
  todos, onde outra conta poderia trocar o arquivo de entrada executado pelo
  app), e seguia symlinks para fora
- Com o `cwd` apontando para um link, `remove --delete-dir` chamava
  `remove_dir_all` sobre o **alvo**, apagando o conteúdo de um diretório que o
  app nunca possuiu — reproduzido com perda de arquivo real antes da correção
- `add` passa a resolver o caminho (com symlinks de todos os ancestrais) e a
  exigir que fique dentro do home; `remove --delete-dir` recusa apagar através
  de link (`cwd_is_symlink`) e revalida o confinamento, cobrindo também apps
  registrados antes desta versão

**`HOME` era definido pelo chamador**
- A validação de confinamento lia `HOME` do ambiente, que vem de quem invoca —
  apontá-lo para outro lugar anularia a proteção
- `HOME` passa a ser fixado logo após a resolução do usuário, com o valor obtido
  de `getpwnam` (não do ambiente)

### Fixed

**Apps morriam junto com o processo que os iniciou**
- Um app herdava o cgroup de quem o executou — o processo CGI do painel, ou a
  unidade `oneshot` de recuperação no boot. Quando esse cgroup era encerrado, o
  systemd levava o app junto: no boot ele subia e morria no mesmo instante, e um
  app iniciado por sessão de login ficava à mercê de `KillUserProcesses`
- `start` passa a registrar cada app em um escopo systemd próprio
  (`selynt-<user>-<app>.scope`), tornando-o independente do processo pai
- O escopo é criado no prelude, como root: registrar unidade transiente exige o
  barramento do sistema, e um chamador sem privilégio recebe "Interactive
  authentication required". O rebaixamento passa a ser feito pelo systemd via
  `--uid`/`--gid`, com o mesmo uid/gid que `drop_privileges` aplicaria
- `--collect` remove a unidade ao término, para que um app que caia não deixe
  unidade em estado de falha bloqueando o próximo start com o mesmo nome
- Onde não há systemd, o comportamento anterior é mantido

**Sequências ANSI tornavam os logs ilegíveis no painel**
- Bibliotecas de log costumam colorir incondicionalmente (o
  `tracing-subscriber` do Rust habilita `ansi` por padrão e *não* testa se há
  terminal), então os escapes são gravados no arquivo e aparecem como `[2m`,
  `[0m` no visualizador HTML do painel
- `cmd_logs` passa a remover ANSI (formas CSI, OSC e de dois bytes) de cada
  linha; o arquivo de log em si permanece intacto

**`remove` apagava o `.env` mesmo sem `--delete-dir` (#3)**
- Com o diretório preservado, apenas os logs do app são removidos; `.env` e demais arquivos do usuário permanecem intactos

### Added

**Limites de memória sob demanda**
- Cada conta ganha uma slice systemd (`selynt-<user>.slice`) com o `MemoryMax`
  do DirectAdmin: é o teto que o kernel impõe sobre todos os apps juntos, e
  nenhum app consegue furá-lo
- Dentro dela, cada app recebe `MemoryMin` (garantia contra reclaim, nunca
  abaixo de 48 MB — o que um Node precisa para iniciar), `MemoryHigh` (throttle)
  e `MemoryMax` (parada dura). Os máximos individuais somam mais que a slice de
  propósito: é esse overcommit que torna o consumo elástico
- Um app sozinho alcança 80% do pool; quando outro sobe e há disputa real, o
  kernel pressiona quem passou da cota e a memória volta a circular. O modelo
  anterior dividia o teto em partes iguais e fixas, reservando memória que
  ninguém usava — com 1 GB e dois apps, cada um ficava preso a 307 MB
- `set-memory-max` passa a apenas *reduzir*: o valor escolhido vira teto rígido
  daquele app e é aplicado a quente, sem reiniciar
- Parar, remover ou iniciar um app redistribui as garantias dos demais na hora
- Sem `MemoryMax` na conta, nenhuma propriedade é aplicada — comportamento
  anterior preservado

**`stats <app>` — uso de CPU e memória por aplicação**
- Lê o cgroup do escopo systemd criado pelo `start`, então os números são do app
  inteiro (processos filhos incluídos), não estimativa por PID
- A memória reportada é `anon` (páginas do próprio app), não `memory.current`:
  este último inclui o page cache, que o kernel descarta sob pressão e que
  oscila a cada leitura de disco
- Os limites vêm do `user.conf` do DirectAdmin (`MemoryMax`, `CPUQuota`), que é
  onde o DA já os configura; sem limite definido, a memória total da máquina
  serve de referência para a porcentagem
- A leitura dos limites acontece no prelude root: `data/users/` é `diradmin` e
  `0700`, e depois do drop de privilégio retornaria vazio silenciosamente
- CPU é contador acumulado — o valor bruto é devolvido e quem chama amostra duas
  vezes, evitando que o CGI bloqueie a cada requisição
- `admin list` passa a trazer `memory` e `cpu_usec` de cada app na mesma
  varredura, para a visão geral do admin não precisar de uma chamada por app

**Suíte de testes (`cargo test`)**
- Primeira cobertura automatizada do projeto: 12 testes sobre a validação de
  caminhos, incluindo cada vetor confirmado como explorável
- Cobre cwd dentro/fora do home, `..` escapando e `..` que permanece dentro,
  symlink apontando para fora (como folha e como ancestral no meio do caminho),
  symlink que fica dentro, cwd relativo, e `/home/user2` não passando por
  compartilhar prefixo textual com `/home/user`
- `validate_cwd_within_home` foi dividida em `check_cwd_within_home` (decisão
  pura, testável) e o invólucro que encerra o processo

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
