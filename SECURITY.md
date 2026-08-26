# Política de segurança

## Como relatar

**Não abra issue pública para falha de segurança.**

Use o [relato privado de vulnerabilidade][priv] deste repositório
(aba *Security* → *Report a vulnerability*). O canal é privado entre quem
relata e quem mantém, e permite publicar o aviso junto com a correção.

[priv]: https://github.com/NullSablex/core-selynt/security/advisories/new

Ao relatar, ajuda incluir: a versão do binário (`core-selynt --version`), o
sistema e o painel em uso, o que era esperado e o que aconteceu, e o passo a
passo para reproduzir.

O projeto é mantido por uma pessoa, sem plantão: não há prazo de resposta
garantido. Relatos de segurança têm prioridade sobre o resto da fila, e o
retorno vem assim que possível.

## Escopo

O `core-selynt` é **setuid root** e executável por qualquer conta local do
servidor. Por isso interessa em especial qualquer caminho que permita:

- agir sobre aplicações, arquivos ou estado de outra conta;
- executar código como root a partir de valor controlado pelo chamador
  (variável de ambiente, caminho, metadado de aplicação);
- contornar a autenticação dos comandos `admin`;
- fazer uma aplicação escapar do isolamento ou expor porta externa.

Falha que exija acesso root prévio está fora de escopo: quem já é root não
precisa do binário.

## Divulgação

A correção sai antes do detalhe técnico. Publicado o release corrigido, o
aviso é divulgado com crédito a quem relatou, salvo pedido em contrário.
