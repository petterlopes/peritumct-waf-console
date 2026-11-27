# Filtros

O cabeçalho tem três controles independentes. Cada um reduz um conjunto conhecido de linhas. Quando um controle não enxerga um campo, a tela diz isso, em vez de manter o total anterior.

Console **2.0.10**. As mesmas regras estão em `rust/src/dashboard.rs` e `legacy/python/dashboard.py`.

## Domínio

A lista de domínios é o catálogo em escopo. A comparação usa o host normalizado:

- minúsculas
- sem esquema, sem uma única `:porta` e sem `www.` inicial

`www.example.com` e `example.com` são o mesmo host. `app.example.com` é outro host. Escolher o ápice não inclui o subdomínio, e escolher o subdomínio não inclui o ápice.

Os totais do painel, a saúde da origem e a lista de hosts da borda seguem esse host. Um nome fora do catálogo é ignorado.

## País do mapa

Clicar num país ou num ponto fixa um código ISO para o console inteiro. Isso reduz:

- alertas, decisões e achados OWASP e ATT&CK
- ofensores repetidos, quando o IP está na amostra atual do mapa
- a tabela de pontos do mapa
- as linhas de eventos e logs do painel

Os cartões de total do painel continuam a janela do domínio. Uma nota sob o painel avisa quando as linhas estão mais estreitas do que esses totais.

## Busca

A busca compara IP, cenário ou país nas mesmas listas do país do mapa. Ela não substitui os chips do painel (IP, caminho, país, ação, método). Esses chips vão para a API e já valem antes de a página filtrar a amostra carregada.

## Linhas sem host

Algumas amostras da LAPI não têm FQDN.

| Lista | Com domínio selecionado |
|-------|-------------------------|
| Achados OWASP / ATT&CK | Ocultos, com nota para escolher Todos os domínios |
| Alertas sem FQDN | Ocultos, com a mesma nota |
| Ofensores repetidos | Continuam listados. O cartão diz que o ranking é a amostra da LAPI e que o domínio não o reduz. País e busca continuam valendo |
| Decisões locais | Continuam listadas. Banimentos não estão ligados a um domínio. País e busca continuam valendo |

## Hub e formulários

A busca do Hub filtra só a categoria aberta. Os formulários de alertas e decisões (IP, cenário, país, origem, a expirar) aplicam-se por cima da busca do cabeçalho.
