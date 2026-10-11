# xtask

Tarefas de desenvolvimento do core-selynt. Não fazem parte do binário.

## `cargo xtask sonda`

Confere se o binário **instalado** faz o que promete. Complementa `cargo test`,
que não alcança o que só aparece com o binário setuid rodando no servidor.

```sh
cargo xtask sonda <host-ssh> [--conta C] [--app A] [--escrita]
```

`<host-ssh>` é um alias do `~/.ssh/config`. A sonda se compila como binário
musl estático, copia a si mesma para o servidor, roda lá como root e apaga a
cópia. O servidor não precisa de nada além dela.

Só leitura por padrão. `--escrita` inclui `sync-proxy` e `netguard`.

Checa as duas metades do contrato:

- **o que a saída promete** — JSON válido, campos presentes, o código de erro
  certo em cada recusa;
- **o que se espera do sistema** — a aplicação marcada RUNNING está no próprio
  scope do systemd, o socket existe, as contas de serviço são barradas onde
  devem e passam onde o painel precisa, e nem a conta comum nem o revendedor
  gravam o preset npm do servidor.

A segunda metade é a que importa: um comando pode responder `ok:true` com todos
os campos e ainda ter deixado o sistema errado.

### Por que existe

Duas regressões passaram por build, clippy e a suíte inteira, e só a sonda
pegou:

- uma aplicação reiniciada ficava fora do systemd — sem cgroup próprio, fora da
  cota da conta e invisível para o netguard, que encontra processos varrendo
  cgroups;
- uma constante reescrita à mão perdeu o prefixo `etc/`, e `apache`/`nobody`
  deixaram de contar como contas de serviço: o painel recusava todo cliente.

Nos dois casos o JSON continuou correto. Rodar depois de cada instalação.
