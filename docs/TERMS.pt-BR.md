# Termos de uso

Vigente em 17 de setembro de 2026.

Ao abrir este console você confirma que é um **operador autorizado** do engine
CrowdSec ao qual ele se conecta. O acesso não autorizado é proibido.

## Licença de software

O código do console é MIT (Copyright (c) 2026 PeritumCT). O CrowdSec permanece
MIT no projeto upstream. Estes termos regem a **operação de uma instância
implantada**; não substituem a licença MIT do código. Ver `LICENSE` e `NOTICE`.

## Uso aceitável

Use o console só para monitorar e operar políticas AppSec, decisões locais e
allowlists dos hosts in-scope.

Não:

- exponha LAPI ou AppSec fora do loopback
- coloque `/waf` atrás do bouncer CrowdSec
- use a UI para ativar CRS in-band, `INCLUDE_LARGE_UPLOADS`,
  `DisableBodyInspection`, fail-open ou bot challenge CrowdSec 1.8

Esses controles permanecem desligados por política.

## Não é um serviço público

A UI liga-se a `127.0.0.1` e, em produção, a um overlay de administração. Não é
oferecida aos usuários finais dos origins. Os sites públicos mantêm os
seus próprios termos.

## Sem garantia

O SOFTWARE É FORNECIDO COMO ESTÁ, SEM GARANTIA DE QUALQUER TIPO, conforme a
licença MIT. AppSec fail-closed pode bloquear tráfego quando o engine está
inacessível. Os operadores aceitam esse risco.

## Lei aplicável

Estes termos operacionais são interpretados de acordo com as leis do Brasil, sem
prejuízo da licença MIT.

Contato: https://periciacomputacional.com/sobre/

UI: aba Termos · `#terms`
English: [TERMS.md](TERMS.md)
