#!/bin/sh
# Sonda dinâmica do core-selynt: roda os comandos no servidor e confere se a
# saída é a que o contrato promete.
#
# Complementa tools/mapa.py, que é estático. Este aqui pega o que só aparece
# rodando: JSON inválido, campo faltando, comando que diz ok:true sem ter feito
# nada, autorização que passa quando deveria barrar.
#
# Uso (no servidor):   sh sonda.sh [conta] [app]
#
# Só LEITURA por padrão. Comandos que escrevem estão marcados ESCRITA e
# desativados a menos que SONDA_ESCRITA=1.

B=/usr/local/directadmin/plugins/selynt_panel/bin/core-selynt
CONTA="${1:-user}"
APP="${2:-}"
PASS=0; FALHA=0

# ---------------------------------------------------------------- utilidades

# Valida JSON e a presença de campos. Uso: checa "rótulo" "<json>" campo...
checa() {
  rotulo="$1"; saida="$2"; shift 2
  erro=$(printf '%s' "$saida" | python3 -c '
import json,sys
raw=sys.stdin.read()
try: d=json.loads(raw)
except Exception as e:
    print(f"JSON invalido: {e} | bruto: {raw[:120]!r}"); raise SystemExit
if not isinstance(d,dict): print(f"esperava objeto, veio {type(d).__name__}"); raise SystemExit
for c in sys.argv[1:]:
    neg = c.startswith("!")
    k = c[1:] if neg else c
    if neg and k in d: print(f"campo proibido presente: {k}")
    elif not neg and k not in d: print(f"campo ausente: {k}")
' "$@" 2>&1)

  if [ -z "$erro" ]; then
    PASS=$((PASS+1)); printf '  ok    %s\n' "$rotulo"
  else
    FALHA=$((FALHA+1)); printf '  FALHA %s\n        %s\n' "$rotulo" "$erro"
  fi
}

# Espera que o comando seja recusado com um erro específico.
recusa() {
  rotulo="$1"; saida="$2"; cod="$3"
  if printf '%s' "$saida" | grep -q "\"error\":\"$cod\""; then
    PASS=$((PASS+1)); printf '  ok    %s (recusado: %s)\n' "$rotulo" "$cod"
  else
    FALHA=$((FALHA+1)); printf '  FALHA %s\n        esperava erro %s, veio: %s\n' \
      "$rotulo" "$cod" "$(printf '%s' "$saida" | head -c 140)"
  fi
}

echo "== sonda do core-selynt =="
echo "binario: $(sha256sum $B | cut -c1-16)  conta: $CONTA"
echo

# ------------------------------------------------------- leitura por conta
echo "-- comandos de leitura (conta $CONTA) --"
checa "list"             "$(USERNAME=$CONTA $B list 2>&1)" ok apps
checa "domains"          "$(USERNAME=$CONTA $B domains 2>&1)" ok
checa "status-isolated"  "$(USERNAME=$CONTA $B status-isolated 2>&1)" ok isolated supported running

# Descobre um app se nenhum foi dado.
if [ -z "$APP" ]; then
  APP=$(USERNAME=$CONTA $B list 2>/dev/null | python3 -c '
import json,sys
try: a=json.load(sys.stdin).get("apps",[])
except Exception: a=[]
print(a[0]["name"] if a else "")' 2>/dev/null)
fi

if [ -n "$APP" ]; then
  echo
  echo "-- app: $APP --"
  checa "status"  "$(USERNAME=$CONTA $B status "$APP" 2>&1)" ok status
  checa "stats"   "$(USERNAME=$CONTA $B stats "$APP" 2>&1)" ok running memory
  checa "logs"    "$(USERNAME=$CONTA $B logs "$APP" 2>&1)" ok

  # O que o painel mostra tem de bater com a realidade do cgroup: um app
  # RUNNING fora do seu scope escapa da cota e some do netguard (foi o bug 8).
  st=$(USERNAME=$CONTA $B status "$APP" 2>/dev/null)
  if printf '%s' "$st" | grep -q '"status":"RUNNING"'; then
    pid=$(printf '%s' "$st" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("pid",""))' 2>/dev/null)
    cg=$(cat /proc/$pid/cgroup 2>/dev/null | head -1)
    esperado="selynt-$CONTA-$APP.scope"
    if printf '%s' "$cg" | grep -q "$esperado"; then
      PASS=$((PASS+1)); printf '  ok    RUNNING esta no proprio scope\n'
    else
      FALHA=$((FALHA+1))
      printf '  FALHA RUNNING fora do scope (escapa da cota e do netguard)\n'
      printf '        esperado: %s\n        real:     %s\n' "$esperado" "$cg"
    fi

    # O painel diz que serve; o socket tem de aceitar conexao.
    sock=$(grep -h '^socket=' /var/lib/selynt_panel/$CONTA/.run/$APP.meta 2>/dev/null | cut -d= -f2)
    if [ -n "$sock" ] && [ -S "$sock" ]; then
      PASS=$((PASS+1)); printf '  ok    socket existe (%s)\n' "$sock"
    else
      FALHA=$((FALHA+1)); printf '  FALHA RUNNING mas sem socket: %s\n' "$sock"
    fi
  fi
fi

# ----------------------------------------------------------------- admin
echo
echo "-- admin --"
checa "admin version"      "$(USERNAME=admin $B admin version 2>&1)" ok version
checa "admin list"         "$(USERNAME=admin $B admin list 2>&1)" ok
checa "admin detect-nodes" "$(USERNAME=admin $B admin detect-nodes 2>&1)" ok
checa "admin diagnose"     "$(USERNAME=admin $B admin diagnose 2>&1)" ok

USERNAME=admin $B admin diagnose 2>/dev/null | python3 -c '
import json,sys
from collections import Counter
try: d=json.load(sys.stdin)
except Exception as e: print(f"  FALHA diagnostico ilegivel: {e}"); raise SystemExit
i=d.get("items",d.get("checks",[]))
c=Counter(x.get("level") for x in i)
print(f"  info  diagnostico: {dict(c)}")
for x in i:
    lvl = x.get("level")
    if lvl != "pass":
        print("        %s: %s" % (lvl, x.get("key", x)))
'

# ---------------------------------------------------------- autorizacao
# Nivel 3: so root real instala ou remove. Contas de servico tem de ser barradas
# aqui — e nao nos comandos de leitura, que elas precisam para o painel andar.
echo
echo "-- autorizacao (o que TEM de ser recusado) --"
recusa "nobody nao instala" "$(su -s /bin/sh -c "USERNAME=admin $B setup" nobody 2>&1)" root_required
recusa "apache nao remove"  "$(su -s /bin/sh -c "USERNAME=admin $B teardown" apache 2>&1)" root_required
recusa "root sem USERNAME"  "$(env -u USERNAME $B admin version 2>&1)" user_resolve_failed
recusa "app inexistente"    "$(USERNAME=$CONTA $B status __nao_existe__ 2>&1)" app_not_found

# Contas de servico PRECISAM passar nos comandos de leitura (o CGI roda como
# elas); se isso quebrar, o painel para de funcionar.
checa "apache le como conta" "$(su -s /bin/sh -c "USERNAME=$CONTA $B list" apache 2>&1)" ok apps

# -------------------------------------------------------------- escrita
if [ "$SONDA_ESCRITA" = "1" ]; then
  echo
  echo "-- ESCRITA (SONDA_ESCRITA=1) --"
  checa "sync-proxy" "$(USERNAME=admin $B sync-proxy 2>&1)" ok apps
  checa "netguard"   "$(USERNAME=$CONTA $B netguard 2>&1)" ok stopped
else
  echo
  echo "  (escrita desativada; SONDA_ESCRITA=1 para incluir sync-proxy/netguard)"
fi

echo
echo "== $PASS ok, $FALHA falha(s) =="
[ "$FALHA" -eq 0 ]
