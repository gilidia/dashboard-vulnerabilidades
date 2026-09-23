"""Dashboard de Análise de Vulnerabilidades.

Lê um CSV com o resultado de uma varredura de vulnerabilidades, valida os dados
(IPs, portas e pontuações CVSS) e gera um painel HTML com o resumo do risco.

Uso:
    python main.py
    python main.py --entrada data/vulnerabilidades.csv --saida dashboard.html
"""
import argparse
import csv
import html
import ipaddress
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from string import Template

BASE = Path(__file__).parent
SEVERIDADES = ("Crítica", "Alta", "Média", "Baixa")
STATUS_VALIDOS = ("Aberta", "Em correção", "Corrigida")
CLASSE = {"Crítica": "critica", "Alta": "alta", "Média": "media", "Baixa": "baixa"}


def classificar(cvss):
    """Faixas de severidade do CVSS v3.x."""
    if cvss >= 9.0:
        return "Crítica"
    if cvss >= 7.0:
        return "Alta"
    if cvss >= 4.0:
        return "Média"
    return "Baixa"


def validar(linha):
    ip = ipaddress.ip_address(linha["ip"].strip())  # levanta ValueError se o IP for inválido
    porta = int(linha["porta"])
    if not 1 <= porta <= 65535:
        raise ValueError(f"porta fora do intervalo 1-65535 ({porta})")
    cvss = float(linha["cvss"].replace(",", "."))
    if not 0.1 <= cvss <= 10.0:
        raise ValueError(f"CVSS fora do intervalo 0,1-10,0 ({cvss})")
    status = linha["status"].strip()
    if status not in STATUS_VALIDOS:
        raise ValueError(f"status desconhecido ({status!r})")
    return {
        "id": linha["id"].strip(), "host": linha["host"].strip(), "ip": str(ip), "porta": porta,
        "servico": linha["servico"].strip(), "vulnerabilidade": linha["vulnerabilidade"].strip(),
        "cvss": cvss, "status": status, "severidade": classificar(cvss),
        "rede": str(ipaddress.ip_network(f"{ip}/24", strict=False)),
    }


def carregar(caminho):
    vulns, erros = [], []
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        for numero, linha in enumerate(csv.DictReader(arquivo), start=2):
            try:
                vulns.append(validar(linha))
            except KeyError as coluna:
                erros.append(f"linha {numero}: coluna ausente {coluna}")
            except ValueError as erro:
                erros.append(f"linha {numero}: {erro}")
    return vulns, erros


def resumir(vulns):
    """Só o que não foi corrigido conta como risco atual."""
    abertas = [v for v in vulns if v["status"] != "Corrigida"]
    risco_por_host = defaultdict(lambda: [0, 0.0])  # host -> [quantidade, soma do CVSS]
    for v in abertas:
        risco_por_host[v["host"]][0] += 1
        risco_por_host[v["host"]][1] += v["cvss"]
    return {
        "total": len(vulns),
        "abertas": abertas,
        "corrigidas": len(vulns) - len(abertas),
        "por_severidade": Counter(v["severidade"] for v in abertas),
        "por_status": Counter(v["status"] for v in vulns),
        "por_servico": Counter(f"{v['servico']} ({v['porta']})" for v in abertas).most_common(5),
        "por_rede": Counter(v["rede"] for v in abertas).most_common(),
        "hosts": sorted(risco_por_host.items(), key=lambda h: h[1][1], reverse=True),
    }


# ---------- geração do HTML ----------
def barras(itens, classe_fn=lambda rotulo: ""):
    maximo = max((n for _, n in itens), default=0) or 1
    return "".join(
        f'<div class="linha"><span>{html.escape(str(r))}</span>'
        f'<div class="trilho"><div class="barra {classe_fn(r)}" style="width:{n / maximo * 100:.0f}%"></div></div>'
        f"<b>{n}</b></div>"
        for r, n in itens
    ) or "<p>Sem dados.</p>"


def gerar_html(resumo):
    abertas = sorted(resumo["abertas"], key=lambda v: v["cvss"], reverse=True)
    criticas = resumo["por_severidade"]["Crítica"]
    taxa = resumo["corrigidas"] / resumo["total"] * 100 if resumo["total"] else 0

    linhas_vulns = "".join(
        f"<tr><td>{html.escape(v['id'])}</td><td>{html.escape(v['host'])}</td>"
        f"<td>{v['ip']}:{v['porta']}</td><td>{html.escape(v['servico'])}</td>"
        f"<td>{html.escape(v['vulnerabilidade'])}</td><td>{v['cvss']:.1f}</td>"
        f"<td><span class='tag {CLASSE[v['severidade']]}'>{v['severidade']}</span></td>"
        f"<td>{html.escape(v['status'])}</td></tr>"
        for v in abertas
    )
    linhas_hosts = "".join(
        f"<tr><td>{html.escape(h)}</td><td>{qtd}</td><td>{soma:.1f}</td></tr>"
        for h, (qtd, soma) in resumo["hosts"]
    )
    return Template(PAGINA).substitute(
        data=date.today().strftime("%d/%m/%Y"),
        total=resumo["total"], abertas=len(abertas), criticas=criticas, taxa=f"{taxa:.0f}",
        graf_sev=barras([(s, resumo["por_severidade"][s]) for s in SEVERIDADES], lambda s: CLASSE[s]),
        graf_status=barras([(s, resumo["por_status"][s]) for s in STATUS_VALIDOS]),
        graf_servico=barras(resumo["por_servico"]),
        graf_rede=barras(resumo["por_rede"]),
        linhas_vulns=linhas_vulns, linhas_hosts=linhas_hosts,
    )


PAGINA = """<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard de Vulnerabilidades</title>
<style>
:root{--paper:#E8E6E3;--ink:#2A2725;--muted:#5E5853;--line:#CFCAC4;--brown:#7A4E32}
*{box-sizing:border-box;margin:0}
body{font-family:system-ui,sans-serif;background:var(--paper);color:var(--ink);line-height:1.5;padding:1.5rem}
main{max-width:1100px;margin:0 auto}
h1{font-size:1.8rem}h2{font-size:1.05rem;margin-bottom:.8rem}
.sub{color:var(--muted);margin-bottom:1.5rem}
.kpis,.paineis{display:grid;gap:1rem;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin-bottom:1rem}
.card{background:#fff;border:1px solid var(--line);border-radius:8px;padding:1.1rem;overflow-x:auto}
.kpi b{display:block;font-size:2.2rem;line-height:1.1;color:var(--brown)}
.linha{display:grid;grid-template-columns:130px 1fr 28px;gap:.6rem;align-items:center;font-size:.9rem;margin-bottom:.45rem}
.trilho{background:var(--paper);border-radius:4px;height:14px}
.barra{background:var(--brown);height:100%;border-radius:4px}
.barra.critica,.tag.critica{background:#3B2417}.barra.alta,.tag.alta{background:#7A4E32}
.barra.media,.tag.media{background:#B08968}.barra.baixa,.tag.baixa{background:#CDBBA7;color:var(--ink)}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--line);white-space:nowrap}
td:nth-child(5){white-space:normal;min-width:230px}
th{background:var(--paper)}
.tag{color:#fff;padding:.1rem .55rem;border-radius:4px;font-size:.8rem}
p.nota{color:var(--muted);font-size:.85rem;margin-top:1rem}
</style></head><body><main>
<h1>Dashboard de Análise de Vulnerabilidades</h1>
<p class="sub">Gerado em $data. Dados de exemplo (fictícios) para fins de estudo.</p>
<div class="kpis">
<div class="card kpi"><b>$total</b>vulnerabilidades registradas</div>
<div class="card kpi"><b>$abertas</b>ainda sem correção</div>
<div class="card kpi"><b>$criticas</b>críticas sem correção</div>
<div class="card kpi"><b>$taxa%</b>já corrigidas</div>
</div>
<div class="paineis">
<div class="card"><h2>Pendentes por severidade</h2>$graf_sev</div>
<div class="card"><h2>Situação geral</h2>$graf_status</div>
<div class="card"><h2>Serviços mais afetados</h2>$graf_servico</div>
<div class="card"><h2>Pendentes por sub-rede (/24)</h2>$graf_rede</div>
</div>
<div class="card" style="margin-bottom:1rem"><h2>Vulnerabilidades pendentes, da mais grave para a menos grave</h2>
<table><thead><tr><th>ID</th><th>Host</th><th>IP:porta</th><th>Serviço</th><th>Vulnerabilidade</th><th>CVSS</th><th>Severidade</th><th>Status</th></tr></thead>
<tbody>$linhas_vulns</tbody></table></div>
<div class="card"><h2>Risco por host (soma do CVSS das pendências)</h2>
<table><thead><tr><th>Host</th><th>Pendências</th><th>Risco acumulado</th></tr></thead><tbody>$linhas_hosts</tbody></table></div>
<p class="nota">Severidade pelas faixas do CVSS v3.x: Baixa 0,1-3,9 | Média 4,0-6,9 | Alta 7,0-8,9 | Crítica 9,0-10,0.</p>
</main></body></html>
"""


def main():
    parser = argparse.ArgumentParser(description="Gera um dashboard HTML a partir de um CSV de vulnerabilidades")
    parser.add_argument("--entrada", default=BASE / "data" / "vulnerabilidades.csv", type=Path)
    parser.add_argument("--saida", default=BASE / "dashboard.html", type=Path)
    args = parser.parse_args()

    vulns, erros = carregar(args.entrada)
    for erro in erros:
        print(f"Aviso, {erro} (ignorada)")
    if not vulns:
        raise SystemExit("Nenhum registro válido encontrado.")

    resumo = resumir(vulns)
    args.saida.write_text(gerar_html(resumo), encoding="utf-8")
    print(f"{resumo['total']} registros lidos | {len(resumo['abertas'])} pendentes | "
          f"{resumo['por_severidade']['Crítica']} críticas")
    print(f"Dashboard gerado em: {args.saida}")


if __name__ == "__main__":
    main()
