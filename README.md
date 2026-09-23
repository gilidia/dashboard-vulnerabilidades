# Dashboard de Análise de Vulnerabilidades

Programa em Python que lê o resultado de uma varredura de vulnerabilidades (CSV), valida os dados e gera um **painel HTML** com o resumo do risco de uma rede.

Construído com base nos conceitos do curso **Introdução à Cibersegurança (Cisco Networking Academy)**.

> Os dados em `data/vulnerabilidades.csv` são **fictícios**, criados para estudo. As pontuações CVSS são ilustrativas.

## O que o painel mostra

- Total de vulnerabilidades, pendentes, críticas pendentes e percentual já corrigido
- Pendências por severidade, situação geral, serviços mais afetados e sub-rede
- Tabela de pendências ordenada da mais grave para a menos grave
- Risco acumulado por host (soma do CVSS das pendências)

## Tecnologias

Python 3.9+ (apenas biblioteca padrão), conceitos de redes de computadores e lógica de programação.

## Como executar localmente

1. Clone este repositório: `git clone [link]`
2. Instale as dependências: `pip install -r requirements.txt`
3. Execute a aplicação: `python main.py`

O arquivo `dashboard.html` será criado na pasta do projeto. Abra-o no navegador.

Para usar outro arquivo: `python main.py --entrada meus_dados.csv --saida painel.html`

## Formato do CSV

```
id,host,ip,porta,servico,vulnerabilidade,cvss,status
V-001,srv-web-01,192.168.10.10,8080,HTTP,Painel com credenciais padrão,9.8,Aberta
```

`status` aceita: `Aberta`, `Em correção` ou `Corrigida`.

## Conceitos de redes e segurança aplicados

- **Validação de endereços IP** com o módulo `ipaddress` (linhas com IP inválido são ignoradas e avisadas)
- **Portas (1 a 65535) e serviços:** cada achado está ligado a uma porta e a um serviço (SSH, SMB, RDP, Telnet...)
- **Agrupamento por sub-rede /24**, para ver onde as falhas se concentram
- **Classificação por severidade** segundo as faixas do CVSS v3.x: Baixa (0,1-3,9), Média (4,0-6,9), Alta (7,0-8,9), Crítica (9,0-10,0)
- **Saída segura:** todo texto vindo do CSV passa por `html.escape` antes de entrar na página

## Próximos passos

- Importar relatórios reais de ferramentas de varredura
- Filtros interativos e exportação em PDF
- Comparar duas varreduras para medir a evolução
