Bubblewrap (https://github.com/containers/bubblewrap)
Copyright (C) 2016 Alexander Larsson e colaboradores

--------------------------------------------------------------------------------

# O que é distribuído

O release deste repositório publica o executável `bwrap` junto do
`core-selynt`. Ele é compilado sem modificações a partir do código-fonte
oficial do Bubblewrap, versão **0.11.2**, commit
`1b80120ef26a28e065e67f89bfef873f13bdd317`.

O `core-selynt` o invoca para confinar a execução de comandos das aplicações —
instalação de dependências e scripts do `package.json` —, de modo que cada
execução veja apenas o diretório da própria aplicação.

O binário é fixado por **SHA de commit**, não por tag: uma tag pode ser
reapontada, um commit não. O workflow confere o SHA e a versão declarada no
`meson.build` antes de compilar.

# Licença: GNU Lesser General Public License, versão 2.0 ou posterior

`SPDX-License-Identifier: LGPL-2.0-or-later`

O texto integral está em `LICENSES/bubblewrap-COPYING.txt`, nesta mesma pasta,
e é o arquivo `COPYING` distribuído com o código-fonte original.

# Código-fonte correspondente

A LGPL exige que o código-fonte correspondente ao binário distribuído esteja
disponível. Como o binário sai da fonte oficial sem nenhuma modificação, o
fonte correspondente é o próprio commit:

    https://github.com/containers/bubblewrap/tree/1b80120ef26a28e065e67f89bfef873f13bdd317

O comando de compilação está em `.github/workflows/release.yml`, na etapa
"Build bubblewrap (static)".

--------------------------------------------------------------------------------

# Relação com a licença do core-selynt

O `core-selynt` é licenciado sob a AGPL-3.0-or-later. O Bubblewrap é
distribuído como um **executável separado**, invocado como processo externo —
não é vinculado ao código do core. Essa forma de uso é compatível com a LGPL e
não altera o licenciamento deste projeto.
