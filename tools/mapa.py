#!/usr/bin/env python3
"""Mapa estrutural do core-selynt, extraído do código — nunca de memória.

Uso:
    tools/mapa.py                 # visão geral por arquivo
    tools/mapa.py --fns           # todas as funções, com tamanho
    tools/mapa.py --grandes [N]   # funções acima de N linhas (padrão 60)
    tools/mapa.py --mortas        # itens sem nenhuma referência
    tools/mapa.py --pub           # `pub` que só tem uso local
    tools/mapa.py --colisoes      # mesmo nome definido em vários arquivos
    tools/mapa.py --cmds          # comandos da CLI x prelúdio x dispatch
    tools/mapa.py --snapshot      # linha-base p/ comparar antes/depois
    tools/mapa.py --diff ARQUIVO  # compara com um snapshot salvo

O ponto: responder por extração, não por lembrança. Cada saída é derivada
do fonte no momento da execução.
"""
import json
import os
import re
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")

FN = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))? )?(?:const |unsafe |async )*fn ([a-z_][a-z_0-9]*)", re.M
)
TYPE = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))? )?(struct|enum|trait) ([A-Za-z_][A-Za-z_0-9]*)", re.M
)


def files():
    out = []
    for root, _, fs in os.walk(SRC):
        for f in fs:
            if f.endswith(".rs"):
                out.append(os.path.relpath(os.path.join(root, f), SRC))
    return sorted(out)


def read(rel):
    """Devolve (fonte completo, só produção). Testes ficam de fora das análises."""
    src = open(os.path.join(SRC, rel), encoding="utf-8").read()
    i = src.find("#[cfg(test)]")
    return src, (src[:i] if i >= 0 else src)


def fns_of(prod):
    """[(nome, linha, tamanho)] — tamanho vai até a próxima definição."""
    ms = list(FN.finditer(prod))
    out = []
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(prod)
        out.append(
            (m.group(1), prod[: m.start()].count("\n") + 1, prod[m.start():end].count("\n"))
        )
    return out


def collect():
    data = {}
    for rel in files():
        src, prod = read(rel)
        data[rel] = {
            "linhas": src.count("\n") + 1,
            "prod": prod.count("\n") + 1,
            "fns": fns_of(prod),
            "tipos": [t[1] for t in TYPE.findall(prod)],
            "src": src,
            "prodsrc": prod,
        }
    return data


def visao_geral(d):
    print(f"{'arquivo':30}{'linhas':>8}{'prod':>7}{'teste':>7}{'fns':>6}  maior função")
    tl = tf = 0
    for rel, i in d.items():
        big = max(i["fns"], key=lambda x: x[2]) if i["fns"] else ("-", 0, 0)
        tl += i["linhas"]
        tf += len(i["fns"])
        print(
            f"{rel:30}{i['linhas']:8}{i['prod']:7}{i['linhas']-i['prod']:7}"
            f"{len(i['fns']):6}  {big[2]:3}l {big[0]}"
        )
    print(f"{'TOTAL':30}{tl:8}{'':7}{'':7}{tf:6}")


def grandes(d, lim):
    print(f"=== funções com mais de {lim} linhas ===")
    rows = [
        (sz, rel, ln, nm) for rel, i in d.items() for nm, ln, sz in i["fns"] if sz > lim
    ]
    for sz, rel, ln, nm in sorted(rows, reverse=True):
        print(f"  {sz:4}l  {rel}:{ln}\t{nm}")
    if not rows:
        print("  (nenhuma)")


def mortas(d):
    """Sem referência fora da própria definição — candidato a código morto."""
    todo = "\n".join(i["prodsrc"] for i in d.values())
    print("=== sem referência alguma (candidatas a remoção) ===")
    achou = False
    for rel, i in d.items():
        for nm, ln, _ in i["fns"]:
            defs = len(re.findall(r"\bfn\s+" + re.escape(nm) + r"\b", todo))
            occ = len(re.findall(r"\b" + re.escape(nm) + r"\b", todo))
            if occ <= defs:
                print(f"  {rel}:{ln}\t{nm}")
                achou = True
    if not achou:
        print("  (nenhuma)")


def pubs_compilador():
    """Pergunta ao COMPILADOR quais `pub` são largos demais.

    Restringe cada um a `pub(crate)`, compila, e desfaz. O que continuar
    compilando não precisava ser `pub`. É mais lento que casar texto, e é o
    único jeito honesto: contar ocorrências com regex já me fez afirmar que
    `AppMeta.domain` estava em uso quando o campo nunca era lido — a busca
    casava `args.domain`, de outra struct.
    """
    import subprocess

    raiz = os.path.dirname(SRC)
    alvos = []
    for rel in files():
        _, prod = read(rel)
        for m in re.finditer(r"^pub fn ([a-z_][a-z_0-9]*)", prod, re.M):
            alvos.append((rel, m.group(1)))

    if not alvos:
        print("  (nenhum `pub fn`)")
        return

    print(f"=== testando {len(alvos)} `pub fn` contra o compilador ===")
    largos = []
    for rel, fn in alvos:
        caminho = os.path.join(SRC, rel)
        orig = open(caminho, encoding="utf-8").read()
        novo = re.sub(r"^pub fn " + fn + r"\b", "pub(crate) fn " + fn, orig, count=1, flags=re.M)
        if novo == orig:
            continue
        open(caminho, "w", encoding="utf-8").write(novo)
        r = subprocess.run(
            ["cargo", "build", "--message-format=short"],
            capture_output=True, text=True, cwd=raiz,
        )
        open(caminho, "w", encoding="utf-8").write(orig)
        if r.returncode == 0:
            largos.append(f"{rel}::{fn}")

    for x in largos:
        print(f"  pub(crate) basta: {x}")
    print(f"\n  {len(largos)} de {len(alvos)} são largos demais")


def pubs_texto(d):
    """Aproximação por texto. Rápida, mas sujeita a falso positivo/negativo."""
    print("=== `pub` com uso apenas local ===")
    achou = False
    for rel, i in d.items():
        for nm, ln, _ in i["fns"]:
            if not re.search(
                r"^[ \t]*pub(?:\((?!super|crate)[^)]*\))? fn " + re.escape(nm) + r"\b",
                i["prodsrc"],
                re.M,
            ):
                continue
            fora = sum(
                len(re.findall(r"\b" + re.escape(nm) + r"\b", o["prodsrc"]))
                for r, o in d.items()
                if r != rel
            )
            if fora == 0:
                print(f"  {rel}:{ln}\t{nm}")
                achou = True
    if not achou:
        print("  (nenhuma)")


def colisoes(d):
    """Mesmo nome em arquivos diferentes: convite a importar o errado."""
    nomes = {}
    for rel, i in d.items():
        for nm, ln, _ in i["fns"]:
            nomes.setdefault(nm, []).append(f"{rel}:{ln}")
    print("=== nomes definidos em mais de um arquivo ===")
    achou = False
    for nm, locs in sorted(nomes.items()):
        if len(locs) > 1:
            print(f"  {nm}: {', '.join(locs)}")
            achou = True
    if not achou:
        print("  (nenhuma)")


def cmds(d):
    """Cada comando da CLI deve ser despachado. Um órfão nunca roda."""
    main = d.get("main.rs")
    if not main:
        print("main.rs não encontrado")
        return
    s = main["src"]
    try:
        enum = re.search(r"enum Commands \{(.*?)\n\}", s, re.S).group(1)
    except AttributeError:
        print("enum Commands não encontrado")
        return
    lista = re.findall(r"^\s{4}([A-Z][A-Za-z]*)", enum, re.M)
    pre = s[s.index("fn run_root_prelude"):s.index("fn dispatch")]
    dis = s[s.index("fn dispatch"):]
    print(f"{'comando':22}{'prelúdio':>10}{'dispatch':>10}")
    for c in lista:
        p = "sim" if re.search(r"Commands::" + c + r"\b", pre) else "-"
        v = "sim" if re.search(r"Commands::" + c + r"\b", dis) else "-"
        alerta = "" if v == "sim" else "   <-- ÓRFÃO: nunca executa"
        print(f"{c:22}{p:>10}{v:>10}{alerta}")


def snapshot(d):
    """Linha-base para provar que uma refatoração preservou o conteúdo."""
    out = {
        rel: {
            "prod": i["prod"],
            "fns": sorted(n for n, _, _ in i["fns"]),
            "tipos": sorted(i["tipos"]),
        }
        for rel, i in d.items()
    }
    print(json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False))


def diff(d, caminho):
    """Compara com um snapshot: o que sumiu, surgiu ou mudou de arquivo."""
    velho = json.load(open(caminho, encoding="utf-8"))
    novo = {
        rel: {"fns": sorted(n for n, _, _ in i["fns"]), "tipos": sorted(i["tipos"])}
        for rel, i in d.items()
    }

    def flat(m, k):
        return {f"{n}": rel for rel, i in m.items() for n in i[k]}

    problema = False
    for k, rotulo in (("fns", "função"), ("tipos", "tipo")):
        a, b = flat(velho, k), flat(novo, k)
        for n in sorted(set(a) - set(b)):
            print(f"  SUMIU    {rotulo} {n}  (estava em {a[n]})")
            problema = True
        for n in sorted(set(b) - set(a)):
            print(f"  NOVO     {rotulo} {n}  (em {b[n]})")
        for n in sorted(set(a) & set(b)):
            if a[n] != b[n]:
                print(f"  MOVEU    {rotulo} {n}: {a[n]} -> {b[n]}")
    if not problema:
        print("  nada foi perdido")


def main():
    d = collect()
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--fns":
        for rel, i in d.items():
            print(f"### {rel}")
            for nm, ln, sz in i["fns"]:
                print(f"  {ln:5} ({sz:3}l)  {nm}")
    elif arg == "--grandes":
        grandes(d, int(sys.argv[2]) if len(sys.argv) > 2 else 60)
    elif arg == "--mortas":
        mortas(d)
    elif arg == "--pub":
        pubs_compilador()
    elif arg == "--pub-rapido":
        pubs_texto(d)
    elif arg == "--colisoes":
        colisoes(d)
    elif arg == "--cmds":
        cmds(d)
    elif arg == "--snapshot":
        snapshot(d)
    elif arg == "--diff":
        diff(d, sys.argv[2])
    else:
        visao_geral(d)


if __name__ == "__main__":
    main()
