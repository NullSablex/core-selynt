# Verificação de deploy

## `sonda.sh`

Confere se o binário **instalado** faz o que promete. Complementa `cargo test`,
que não alcança o que só aparece com o binário setuid rodando no servidor.

```sh
scp tools/sonda.sh servidor:/tmp/
ssh servidor 'sh /tmp/sonda.sh [conta] [app]'
```

Só leitura por padrão. `SONDA_ESCRITA=1` inclui `sync-proxy` e `netguard`.

Checa as duas metades do contrato:

- **o que a saída promete** — JSON válido, campos presentes, o código de erro
  certo em cada recusa;
- **o que se espera do sistema** — a aplicação marcada RUNNING está no próprio
  scope do systemd, o socket existe, e as contas de serviço são barradas onde
  devem e passam onde o painel precisa.

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
