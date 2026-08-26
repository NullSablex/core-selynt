# Contribuindo com o core-selynt

Obrigado pelo interesse em contribuir! Leia este guia antes de abrir uma issue ou
pull request.

O `core-selynt` é o binário que executa as operações privilegiadas do
[Selynt Panel](https://github.com/NullSablex/selynt-panel). Ele é **setuid root**
e pode ser executado por qualquer conta local do servidor — o que muda o que
conta como uma mudança segura. Leia a seção de regras antes de mexer no código.

## Antes de começar

- Verifique se já existe uma
  [issue](https://github.com/NullSablex/core-selynt/issues) aberta para o
  problema ou funcionalidade.
- Para mudanças significativas, abra uma issue primeiro para discutir a
  abordagem antes de implementar.
- **Falha de segurança não vai em issue pública.** Use o
  [relato privado](https://github.com/NullSablex/core-selynt/security/advisories/new);
  ver [SECURITY.md](SECURITY.md).
- Ao contribuir, você concorda que seu código será licenciado sob os mesmos
  termos da [licença do projeto](LICENSE) (AGPL-3.0-or-later).

## Configurando o ambiente

**Pré-requisitos:**

- Rust estável (edição 2024)
- O alvo `x86_64-unknown-linux-musl` e o `musl-tools`, que é como o CI compila

```bash
git clone https://github.com/NullSablex/core-selynt
cd core-selynt
rustup target add x86_64-unknown-linux-musl
cargo build
```

**Testar:**

```bash
cargo test
```

**O que o CI exige** (rode antes de abrir a PR):

```bash
cargo fmt --all -- --check
cargo clippy --target x86_64-unknown-linux-musl --all-targets --all-features \
  -- -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery \
  -D clippy::cargo
cargo test --target x86_64-unknown-linux-musl
```

O clippy roda em modo estrito: `pedantic`, `nursery` e `cargo` são negados, não
avisados. Qualquer achado quebra o build.

**Verificar o binário instalado:**

`cargo test` não alcança o que só aparece com o binário setuid rodando num
servidor de verdade — posse de arquivo, queda de privilégio, scope do systemd.
Para isso existe a sonda:

```sh
scp tools/sonda.sh servidor:/tmp/
ssh servidor 'sh /tmp/sonda.sh [conta] [app]'
```

Só leitura por padrão; `SONDA_ESCRITA=1` inclui `sync-proxy` e `netguard`.
Detalhes em [tools/README.md](tools/README.md).

## Estrutura do projeto

```
src/main.rs      ← entrada e definição dos comandos
src/plan.rs      ← despacho: o que roda como root e o que roda como a conta
src/app/         ← ciclo de vida das aplicações (start, logs, metadados, boot)
src/limits/      ← cota, uso, isolamento e a guarda de portas
src/webserver/   ← integração com o servidor web (handlers, proxy, ACL)
src/install/     ← instalação, remoção, unidades do systemd e diagnóstico
src/runtime/     ← detecção de runtimes e versões do Node
src/admin/       ← comandos administrativos
src/sys/         ← autenticação, sistema de arquivos, estado, processos, saída
tools/           ← sonda de deploy (não faz parte do binário)
```

`plan.rs` é o coração do modelo de privilégio: cada comando é um braço do match,
o corpo roda como root e a closure devolvida roda como a conta, com a queda de
privilégio entre os dois. O match é exaustivo de propósito — um comando novo não
compila sem que os dois lados sejam decididos.

## Regras de código

- **Nada de privilégio implícito.** Se uma operação precisa de root, ela vai no
  lado root do `plan.rs`, e o resto roda como a conta. Não adie a queda de
  privilégio "porque é mais simples".
- **Entrada do chamador é hostil.** Variável de ambiente, caminho, nome de conta
  e metadado de aplicação vêm de quem chamou o binário, e quem chama pode ser
  qualquer conta local. Valide antes de usar; não confie em prefixo de caminho
  como se fosse autorização.
- **Quem pode agir sobre quem** é decidido pelo uid real, não por valor
  informado. Ver `sys::auth::caller_is_privileged`.
- **`.app` é do root.** É o arquivo que diz o que executar; se a conta puder
  escrevê-lo, ela escolhe o que o binário roda como root. Escritas passam por
  `appfile::write_as_root`, e há teste que recusa qualquer volta atrás.
- **`unsafe` só com motivo escrito.** O projeto usa `libc` e `nix`; onde houver
  `unsafe`, o comentário acima precisa dizer por que é correto ali.
- **Erro é valor, não pânico.** O binário responde JSON ao painel; um `panic!`
  vira falha opaca. Use os tipos de erro do projeto e devolva o código certo.
- **Sem comentário óbvio** — comentário explica *por quê*, não *o quê*.

## Uso de IA

O uso de ferramentas de IA (assistentes de código, LLMs, tradutores) neste
projeto é **permitido e bem-vindo**. Em resumo:

- **Você é o responsável.** Quem abre o PR assume autoria e responsabilidade
  integral pelo que enviou — revise e entenda o código, tenha usado IA ou não.
- **Sem co-autoria de IA.** A autoria é humana; não atribua co-autoria a um
  assistente em commits ou PRs (`Co-Authored-By:` de IA, "gerado por", etc.).
- **Sem preconceito.** Nenhuma contribuição é rejeitada *só por* ter sido feita
  com auxílio de IA — o que vale é o mérito dela.

Num binário setuid, o item "você é o responsável" pesa mais: código plausível
que assume um processo comum introduz escalação de privilégio sem parecer
errado. Detalhes em [AI-POLICY.md](AI-POLICY.md).

## Abrindo uma Pull Request

1. Crie um branch a partir de `master`: `git checkout -b fix/minha-correcao`
2. Faça as alterações seguindo as regras acima.
3. Rode `cargo fmt`, o clippy estrito e `cargo test`.
4. Se a mudança afeta o comportamento instalado, rode a sonda num servidor.
5. Atualize o `CHANGELOG.md`.
6. Abra a PR com uma descrição clara do que mudou e por quê.

## Reportando bugs

Inclua na issue:

- Versão do binário (`core-selynt --version`)
- Versão do DirectAdmin e qual servidor web
- O comando executado e a saída JSON completa
- Passos para reproduzir
- Comportamento esperado e o que aconteceu

## Sugestões de melhoria

Abra uma issue descrevendo:

- O problema que a mudança resolveria
- Como você imagina que funcionaria
- Alternativas que você considerou
