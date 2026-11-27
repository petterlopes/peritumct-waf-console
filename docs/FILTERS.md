# Filters

The header has three independent controls. Each one narrows a known set of rows. A control that cannot see a field says so, instead of leaving the old total in place.

Console **2.0.10**. The same rules are implemented in `rust/src/dashboard.rs` and `legacy/python/dashboard.py`.

## Domain

The domain list is the in-scope catalog. The match is the host after normalization:

- lower case
- drop a scheme, a single `:port`, and a leading `www.`

`www.example.com` and `example.com` are the same host. `app.example.com` is a different host. Selecting the apex does not include the subdomain, and selecting the subdomain does not include the apex.

Dashboard totals, origin health, and the edge-host list follow that host. A name that is not in the catalog is ignored.

## Map country

Clicking a country or a point sets an ISO code for the whole console. It narrows:

- alerts, decisions, OWASP and ATT&CK findings
- repeated offenders, when the IP is on the current map sample
- the map point table
- dashboard event and log rows

Dashboard KPI tiles stay the domain window. A note under the dashboard says when the rows are narrower than those tiles.

## Search

The search box matches IP, scenario, or country text on the same lists as the map country. It does not replace the dashboard chips (IP, path, country, action, method). Those chips are sent to the API and already applied before the page filters the loaded sample.

## Rows without a host

Some LAPI samples have no FQDN.

| List | Domain selected |
|------|-----------------|
| OWASP / ATT&CK findings | Hidden, with a note to choose All domains |
| Alerts with no FQDN | Hidden, with the same note |
| Repeated offenders | Still listed. The card says the ranking is the LAPI sample and the domain does not narrow it. Country and search still apply |
| Local decisions | Still listed. Bans are not tied to a domain. Country and search still apply |

## Hub and policy forms

Hub inventory search filters the open category only. Alert and decision forms (IP, scenario, country, origin, expiring) apply on top of the header search.
