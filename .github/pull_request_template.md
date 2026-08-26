<!--
Obrigado por contribuir! Preencha os campos abaixo.
O uso de IA é permitido — você é responsável pelo que envia. Ver AI-POLICY.md.
-->

## O que este PR faz

<!-- Descreva a mudança e o motivo. -->

## Tipo de mudança

<!-- Marque o que se aplica. -->

- [ ] Correção de bug
- [ ] Nova funcionalidade
- [ ] Segurança
- [ ] Documentação
- [ ] Refatoração sem mudança de comportamento
- [ ] Manutenção ou infraestrutura (CI, dependências)

## Issue relacionada

<!-- Ex.: Fecha #123. Remova se não houver. -->

## Checklist

- [ ] `cargo fmt --all -- --check` passa
- [ ] Clippy estrito passa (`-D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo`)
- [ ] `cargo test` passa
- [ ] Atualizei o `CHANGELOG.md`
- [ ] Rodei a sonda num servidor, se a mudança afeta o binário instalado

## Privilégio

<!-- Este binário é setuid root. Responda se a mudança tocar em execução,
     posse de arquivo, caminho ou identidade do chamador. -->

- [ ] A mudança não amplia o que roda como root
- [ ] Toda entrada vinda do chamador continua sendo validada antes do uso
- [ ] Nenhum `unsafe` novo (ou, se houver, o motivo está comentado no código)
