# Terms of use

Effective 22 September 2026.

By opening this console you confirm you are an **authorized operator** of the
CrowdSec engine it talks to. Unauthorized access is forbidden.

## Software license

The console source is **GNU GPL-3.0-or-later** (Copyright (c) 2026 PeritumCT) —
Linux-like copyleft, not MIT. CrowdSec remains MIT from its upstream project.
These terms govern **operation of a deployed instance**; they do not replace
the GPL for the code. See `LICENSE` and `NOTICE`.

## Acceptable use

Use the console only to monitor and operate AppSec policies, local decisions and
allowlists for in-scope hosts.

Do not:

- expose LAPI or AppSec beyond loopback
- put `/waf` behind the CrowdSec bouncer
- use the UI to enable CRS in-band, `INCLUDE_LARGE_UPLOADS`,
  `DisableBodyInspection`, fail-open, or CrowdSec 1.8 bot challenge

Those controls stay off by policy.

## Not a public service

The UI binds to `127.0.0.1` and, in production, an admin overlay. It is not
offered to end users of origin sites. Public sites keep their own terms.

## No warranty

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, as stated in the
GPL-3.0. Fail-closed AppSec may block traffic when the engine is unreachable.
Operators accept that risk.

## Governing law

These operational terms are interpreted under the laws of Brazil, without
prejudice to the GPL-3.0-or-later license.

Contact: https://periciacomputacional.com/sobre/

UI: Terms tab · `#terms`
Portuguese: [TERMS.pt-BR.md](TERMS.pt-BR.md)
