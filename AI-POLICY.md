# Política de uso de IA

Esta política define como ferramentas de Inteligência Artificial (assistentes de
código, LLMs, geradores e afins) podem ser usadas ao contribuir com o core-selynt. Ela vale para código, documentação, traduções, issues e pull requests.

## Princípios

1. **O uso de IA é permitido e bem-vindo.** Assistentes de IA são ferramentas
   legítimas de desenvolvimento, como um linter, um depurador ou a documentação
   de uma API. Usá-las para escrever, revisar, traduzir ou refatorar é aceitável.

2. **A pessoa que contribui é a única responsável.** Quem abre a issue ou o pull
   request assume responsabilidade integral pelo conteúdo enviado — correção,
   qualidade, licença e adequação às regras do projeto —, tenha usado IA ou não.
   A ferramenta não responde por nada; quem a operou responde por tudo. Isso
   significa: **revise e entenda o que enviar.** Enviar código que você não
   compreende, gerado por IA ou não, não é aceitável.

3. **Sem co-autoria de IA.** A autoria é humana. Não atribua co-autoria a uma IA
   em commits, PRs, documentação ou qualquer artefato — nada de
   `Co-Authored-By:` apontando para um assistente, nem assinaturas do tipo
   "gerado por". O motivo é direto: é a pessoa que está usando a ferramenta e
   submetendo o resultado, não uma IA agindo e enviando por conta própria. O
   crédito e a responsabilidade são de quem contribui.

4. **Sem preconceito quanto ao uso de IA.** Uma contribuição não deve ser
   rejeitada, depreciada ou tratada com suspeita *só por ter sido feita com
   auxílio de IA*. A revisão avalia a contribuição pelo seu mérito — corretude,
   clareza, aderência às regras do projeto —, nunca pela ferramenta usada para
   produzi-la. Declarar que usou IA é **opcional**: ninguém é obrigado a
   informar, e quem quiser mencionar (ex.: "revisado por mim, gerado com auxílio
   de X") é bem-vindo a fazê-lo — nem proibido, nem exigido.

5. **A revisão também pode usar IA.** Mantenedores e revisores podem se apoiar em
   IA para revisar contribuições, sob a mesma regra do item 2: a ferramenta
   auxilia, mas a decisão e a responsabilidade pela revisão são humanas. Uma IA
   não aprova nem rejeita um PR sozinha.

## Atenção ao revisar conteúdo de IA

O item 2 (você é responsável) tem implicações concretas quando se usa IA, porque
assistentes erram de formas específicas. Antes de enviar, verifique em especial:

- **APIs e símbolos inventados** — LLMs às vezes chamam funções, crates ou
  campos que não existem. Confirme contra o código real e a documentação da
  crate, não contra o que parece plausível.
- **Suposições sobre privilégio** — este binário é *setuid root* e executável
  por qualquer conta local do servidor. Código sugerido por IA costuma assumir
  um processo comum: que o ambiente é confiável, que o caminho recebido é
  legítimo, que basta abrir o arquivo. Aqui cada uma dessas suposições é uma
  falha em potencial. Toda entrada vinda do chamador — variável de ambiente,
  caminho, nome de conta, metadado de aplicação — é hostil até prova em
  contrário, e a queda de privilégio tem hora certa para acontecer.
- **`unsafe` e chamadas de sistema** — não aceite um bloco `unsafe` porque
  "compilou". Se a sugestão envolve libc, fork, exec ou manipulação de uid,
  entenda a semântica antes; erro aí não aparece em teste, aparece em produção
  como escalação de privilégio.
- **Dependências inexistentes ou maliciosas** — não adicione um pacote só porque
  a IA o sugeriu; nomes plausíveis podem não existir ou ser typosquatting. Cheque
  a fonte oficial antes.
- **Licença de código sugerido** — trechos gerados podem reproduzir código de
  terceiros sob licença incompatível, sem aviso. Só entra com licença compatível
  com a AGPL-3.0 e com a devida atribuição.
- **Segredos e dados** — não cole chaves, tokens, senhas de contas ou dados de
  clientes em prompts, e não aceite exemplos que os embutam no código.

## O que continua valendo

A política de IA não afrouxa nenhuma regra do projeto. Todo o conteúdo enviado,
com ou sem IA, precisa:

- Seguir as [regras de código](CONTRIBUTING.md#regras-de-código) e a arquitetura
  do projeto.
- Passar em `cargo test`, `cargo fmt --all -- --check` e no clippy estrito que o
  CI aplica.
- Respeitar licenças de terceiros — código de terceiros (gerado por IA ou não)
  só entra com licença compatível e a devida atribuição.
- Não introduzir segredos, dados pessoais ou conteúdo que você não tem o direito
  de contribuir.
