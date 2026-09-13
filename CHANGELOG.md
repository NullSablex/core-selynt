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

**Portas expostas por apps já em execução**
- A proibição de abrir porta de rede só era verificada durante o start, e apenas
  no processo do app. O bloqueio de `listen()` vive no `node-loader`, que cobre
  só o processo principal: um filho iniciado sem ele — ou um app que não seja
  Node — abria qualquer porta, a qualquer momento depois, contornando o proxy
- Novo comando `netguard`: varre os PIDs do **cgroup** do app, onde todo filho
  está, e para quem estiver com bind alcançável de fora. Reação medida em ~1s
  com o timer que o acompanha
- Loopback continua permitido: um app falando consigo mesmo (cache local, IPC
  entre workers) não expõe nada. A distinção lê o endereço de `/proc/net/*` e
  cobre IPv4, IPv6 e v4-mapped (`::ffff:7f00:0001`)

**Runtimes Node.js executados como root sem verificação de posse**
- A detecção roda cada candidato para ler `--version` e é alcançável pelo
  prelúdio root, mas confiava apenas na localização do arquivo. Não bastava: as
  árvores de runtime costumam ficar com o dono de quem as descompactou (o nvm
  preserva o dono do `$NVM_DIR`; um tarball mantém o uid do arquivo), e o
  `npm install -g` escreve nelas com essa conta — um pacote comprometido
  substituía o `node` e ganhava execução como root
- Confirmado em servidor real: os binários estavam `admin:admin` e
  `almalinux:almalinux`, nenhum deles root
- `is_safe_to_execute` passa a exigir que o caminho **resolvido** esteja sob uma
  raiz confiável **e** que o arquivo e cada diretório acima dele sejam do root e
  não graváveis por outros — um pai gravável permite trocar o binário
- Também fecha o caso do symlink: `canonicalize` já era chamado, mas só para
  deduplicar; o alvo resolvido era descartado e o caminho original executado

### Added

**Execução de comandos npm pelo painel**
- `run-job` executa `install`, `update`, `ci` e os scripts declarados no
  `package.json`; `job-status` devolve estado e log; `stop-job` interrompe.
  Quem não tem SSH — a regra em hospedagem compartilhada — não conseguia nem
  instalar as dependências da própria aplicação
- Sempre dentro do bubblewrap, vendo apenas o diretório da aplicação: um
  `postinstall` comprometido não alcança o `.env` do app vizinho porque o
  vizinho não existe no namespace. Verificado no servidor com um script hostil,
  que recebeu `No such file or directory` ao tentar ler
- Desprendido da requisição: um `install` grande passa do timeout do CGI, e
  prender a resposta a ele faria a página perder a execução no meio. O comando
  segue em sessão própria e o estado fica em `.run/`, que é do root com sticky
  bit — a conta lê o próprio job, não o reescreve
- `--ignore-scripts` em `install`/`update`/`ci`, não em `npm run`: o hook de uma
  dependência transitiva é código que o cliente nunca leu; o script dele é o que
  ele está pedindo para executar
- `install`/`update`/`ci` exigem a aplicação parada — reescrever `node_modules`
  sob um processo que lê dela a quebra sem erro claro. Um job por aplicação, e
  timeout de 15 minutos para o comando travado não ficar para sempre
- `stop-job` manda `SIGINT` ao grupo de processos, o mesmo do Ctrl+C: o npm
  encerra sem deixar `node_modules` pela metade, e o `SIGKILL` só vem depois de
  cinco segundos

**Estado das dependências, sem executar npm**
- `dependency_state` decide entre cinco situações — nada declarado, não
  instaladas, instalação incompleta, `package.json` mudou, tudo certo —
  comparando `package.json`, `package-lock.json` e o disco
- Não usa `npm ls` de propósito: ele exige o npm no `PATH`, que sob o CGI do
  painel não traz `/usr/local/bin`, e custa meio segundo contra os 35ms da
  leitura de arquivo. Também não resolve semver — se `^2.1.3` está satisfeito é
  o npm quem decide, e adivinhar aqui daria respostas confiantes e erradas

**`scripts`, para o painel saber o que a aplicação declara**
- Só os nomes, nunca o corpo: corpo de script é shell escrito pelo cliente, e o
  painel não tem por que renderizar isso
- Os nomes passam por filtro porque é aqui que um nome deixa de ser dado e vira
  parte de uma linha de comando: nada que comece com `-`, sem espaço, aspas ou
  separador

**`set-entry`, para trocar o arquivo de entrada**
- O `entry` era decidido na criação e ficava assim para sempre. Quem migrou de
  `index.js` para `app.mjs`, ou de JavaScript para TypeScript, só resolvia
  apagando a aplicação e criando outra
- A recusa acontece **antes** da gravação: o prelúdio escreve o `.app` como
  root, e validar só depois deixaria a aplicação apontando para um arquivo
  inexistente

**`package.json` criado junto com a aplicação Node**
- Roda o `npm init` de verdade, e o resultado dele é o que fica — o painel não
  escolhe entre CommonJS e ESM, nem entre JavaScript e TypeScript
- Dois ajustes, com o próprio npm: sai o `scripts.test`, que só existe para
  falhar, e `main` aponta para a entrada real, que o `npm init` não tem como
  saber

**O bubblewrap passa a ser distribuído pelo release**
- Compilado estático a partir do commit `1b80120e` (v0.11.2), fixado por **SHA**
  e não por tag, que pode ser reapontada. O workflow confere o SHA após o
  checkout, a versão no `meson.build`, e recusa binário que não seja estático
- A distribuição entrega versões antigas — o AlmaLinux 9 traz 0.6.3 — e o
  comportamento do sandbox precisa ser o mesmo em todo servidor

**O diagnóstico reporta o isolamento**
- Binário ausente e namespaces desligados no kernel são causas diferentes, que o
  admin resolve de formas diferentes. Reporta também a versão instalada

**Documentos de contribuição**
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `AI-POLICY.md`, templates de issue e
  de pull request. O guia descreve o modelo de privilégio do `plan.rs`, que toda
  mudança precisa respeitar, e o template de PR pergunta explicitamente se a
  mudança amplia o que roda como root
- O uso de IA é permitido e não sofre preconceito; quem contribui responde pelo
  que envia, e não se atribui co-autoria a um assistente

**Isolamento entre aplicações da mesma conta**
- Novo `set-isolated --isolated true|false` (conta) e
  `admin save-default-isolated` (padrão do servidor). Ligado, cada app roda em
  namespaces de mount e PID próprios: os vizinhos não existem para ele — nem os
  arquivos, nem os processos, nem os sockets
- Vale para a **conta inteira**, não app a app. Um namespace confina o que o
  processo de dentro enxerga, mas não muda seu uid: um app não isolado, com a
  visão normal do host, ainda leria os arquivos de um isolado e mataria seus
  processos. Isolar um só protegeria os outros dele, não ele dos outros
- Sem criar usuário de sistema por app: o app segue rodando como a conta, e o
  proxy o alcança pela mesma ACL POSIX de sempre
- Requer `bubblewrap` e namespaces de usuário habilitados; onde não houver, o
  app roda compartilhado em vez de falhar ao iniciar

**Detecção de runtimes em `/usr/local/lib/nodejs`**
- Onde o tarball oficial é convencionalmente descompactado. Antes só era
  alcançado pelo symlink `/usr/local/bin/node`, então uma segunda versão
  instalada ali ao lado da primeira ficava invisível

**Comando `status-isolated`** — reporta o modo da conta e quais apps ainda rodam
com o modo anterior, para a interface poder avisar quais precisam reiniciar.

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

### Fixed

**Glob de runtimes nunca casava com `/opt/alt/alt-nodejs*`**
- `glob_paths` aceitava `*` apenas ocupando um componente inteiro do caminho,
  então o padrão do CloudLinux — onde o `*` fica no meio do nome — não casava
  com nada. O suporte estava quebrado em silêncio
- O `*` passa a casar dentro de um componente, com literais dos dois lados

**Logs de aplicação ficavam do root**
- `init_app_logs_dir` fazia `chown` apenas do diretório; os arquivos, criados no
  prelúdio root, ficavam `root:apache` e o app não conseguia reabri-los —
  `restart` falhava com `log_open_failed`
- Agora faz `chown` dos arquivos, e roda também no `Restart` (antes só no
  `Start`, que era o único a chegar nesse caminho)

**Apps sandboxed deixavam processo órfão ao parar**
- O `bwrap` não repassa sinais ao filho, e o pid que o painel rastreia é o dele:
  o `SIGTERM` parava o wrapper e deixava o processo real vivo, segurando o
  socket
- `stop_internal` passa a sinalizar toda a árvore de descendentes

**Socket perdido ao alternar o modo de isolamento**
- O caminho do socket muda entre os modos, mas um app em execução mantém o que
  recebeu ao iniciar; parar o app procurava no lugar errado e deixava o arquivo
  para trás
- O `.meta` passa a registrar o socket real, e é ele que orienta a limpeza

**`--isolated` não podia ser desligado**
- A flag era booleana pura, então `--isolated false` era recusado pelo parser e
  não havia como voltar ao modo compartilhado pela linha de comando

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

**Aplicação sem versão fixada não iniciava pelo painel**
- O comando era `node`, resolvido pelo `PATH` de quem invocou. Da linha de
  comando funcionava; do CGI do DirectAdmin não, porque ali o `PATH` não traz
  `/usr/local/bin`
- O sintoma aparecia longe da causa: ao trocar o isolamento, a aplicação era
  parada e não voltava, e o painel dizia apenas `failed` — o erro real
  (`bwrap: execvp node: No such file or directory`) ficava no log da aplicação
- `default_node_path` resolve entre os caminhos que a detecção já conhece, e a
  falha do religamento passa a registrar a mensagem do filho

**Mudar a cota de memória fazia a aplicação sumir do painel**
- `apply_memory_max` tinha a própria escrita do `.app`: gravava 0600 e passava
  o arquivo para a conta. Mas `load_app_meta` recusa `.app` que não seja do
  root — é o que impede uma aplicação de forjar o arquivo que diz o que
  executar
- A aplicação desaparecia da listagem enquanto o processo seguia rodando, sem
  nada ligando uma coisa à outra
- Passa a usar `appfile::write_as_root`, como as demais escritas; um teste
  recusa qualquer volta atrás

**Handlers existiam em disco e o servidor web nunca os lia**
- Sem `include selynt_extprocessors.conf` no `httpd_config.conf`, toda
  aplicação responde 503 parecendo saudável: processo no ar, socket aceitando,
  marcador no lugar. O desinstalador removia a linha e nada a escrevia de volta
- O `setup` repõe a linha *depois* do `rewrite_confs`, porque o DirectAdmin
  regenera o `httpd_config.conf` e leva a linha junto
- O diagnóstico não olhava para isso e relatava 12 de 12 com o painel fora do
  ar; agora falha explicando o que fazer

**Páginas do painel ficavam sem permissão de execução**
- A regra de permissão olhava a extensão `.html`, e as páginas deixaram de ter
  extensão; ficavam 644, e o DirectAdmin não serve o que não pode executar
- O modo passa a ser decidido pelo diretório: tudo em `user/`, `admin/` e
  `reseller/` é script que o DA executa, e vai a 755

### Changed

**Isolamento ligado por padrão**
- Estava desligado por uma razão que deixou de existir: o bubblewrap vinha da
  distribuição e podia não estar lá, então ligar por padrão teria recusado
  iniciar aplicações em servidores sem o pacote
- Desligado significava que ninguém pagava nada pelo isolamento e ninguém tinha
  nenhum: uma aplicação ler o `.env` da vizinha era a norma. A escolha do admin
  continua valendo, e servidores que já gravaram a preferência não mudam

**O sandbox usa o bubblewrap do painel, sem cair para o do sistema**
- Cair para a versão da distribuição trocaria o comportamento do sandbox sem
  ninguém perceber, incluindo versões anteriores a correções que a nossa já tem
- E recusa executar quando o binário falta, em vez de rodar sem confinamento: um
  pacote de terceiros fora do sandbox por causa de arquivo ausente é exatamente
  o que ele existe para evitar

**Runtimes reunidos em `Runtime`**
- O comportamento que varia por ambiente era decidido por comparações
  `app_type == "node"` espalhadas por `manage`, `start` e `main`. Um runtime
  novo exigia encontrar cada uma delas, e a esquecida falhava em execução
- Agora tudo o que difere (`is_interpreted`, `scaffolds_entry`,
  `requires_executable_entry`, `command_display`) pende do enum, e uma variante
  nova faz o compilador apontar cada decisão pendente

**Actions do GitHub fixadas por SHA**
- Uma tag é móvel: quem controla o repositório da action pode reapontar `@v7`
  para outro commit, e o workflow roda o que vier — com o token do repositório
  em mãos. O `rust.yml` já fazia assim; os demais não
- O token deixa de nascer com poder de escrita: `release.yml` declarava
  `contents: write` no topo, valendo para todos os jobs, e a permissão desce
  para o job que publica
- O `checks: write` do job de auditoria fica: a `rustsec/audit-check` documenta
  essa permissão como necessária, e o Scorecard não distingue esse caso

**Labels do repositório sincronizados por workflow**
- O `labels.yml` existia e nada o aplicava. O labeler também aplicava `docs`,
  que não estava definido ali, então o GitHub criava o label sozinho, sem cor
  nem descrição

**Tipo de aplicação `rust` renomeado para `binary`**
- O painel oferecia "Binário Rust" e gravava `rust`, mas o core nunca olhou a
  linguagem: ele executa o arquivo de entrada, e qualquer coisa que produza um
  executável serve. O nome prometia uma restrição que não existe
- Passa a ser `binary` no metadado e "Binário executável" na interface. O
  identificador antigo não é aceito, para não deixar o painel gravando um nome
  e lendo outro; nenhuma aplicação em produção usava `rust`

**Versões do Node listadas da mais nova para a mais antiga**
- A ordem era a da varredura — caminhos fixos primeiro, depois cada glob na
  ordem que o diretório devolvesse. No servidor saía v25, v20, v22, v24, sem
  lógica visível para quem precisa escolher

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
