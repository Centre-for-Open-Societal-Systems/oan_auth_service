# APISIX gateway config (ADC)

`adc.yaml` is generated from `openapi/openapi_v1.public.yaml`. Do not edit it.
It is applied to an APISIX running in **etcd mode** with
[ADC](https://github.com/api7/adc) (APISIX Declarative CLI).

```bash
python3 apisix/generate_apisix_config_from_spec.py   # spec + tiers -> apisix/adc.yaml
adc lint     -f apisix/adc.yaml                      # local schema check, no gateway needed
adc validate -f apisix/adc.yaml                      # checked by the gateway, nothing saved
adc diff     -f apisix/adc.yaml --label-selector app=oan-auth
adc sync     -f apisix/adc.yaml --label-selector app=oan-auth
```

`oan-auth` is `oan-auth`. Every service, route and consumer carries the label
`app: oan-auth`, so a sync with that selector creates, updates and **deletes only this
app's resources**. Apps sharing one APISIX can sync independently and never remove each
other's routes. Always pass `--label-selector`.

Routes are grouped by throttling tier (`TIERS`, `TIER_OVERRIDES` in the generator), not by
URL. To expose a new endpoint: add it to the spec, give it a tier in `TIER_OVERRIDES`,
regenerate. The generator refuses to run while the spec and `TIER_OVERRIDES` disagree.
Shared logic lives in `oan_auth_service/gateway_apisix.py`.

Routes match the public spec's `/v1/...` paths. A service-level `proxy-rewrite` sends them
to Frappe as `/api/v1/...`. `/api/v1/...` is not served through the gateway.
See `oan_auth_service/docs/API_CONVENTIONS.md`.

## Gateway requirements

```yaml
# APISIX config.yaml
deployment:
  role: traditional
  role_traditional:
    config_provider: etcd
apisix:
  router:
    http: radixtree_uri_with_parameter # routes use :param segments
```

ADC connects with `ADC_BACKEND=apisix`, `ADC_SERVER=<admin URL>` and `ADC_TOKEN=<admin key>`.

## Environment values

Hosts are written into `adc.yaml` as `${VAR}` placeholders. ADC fills them in from its
own environment at `adc lint|diff|sync`, so export them before running ADC; an unset one
fails the run. Ports, origins and the Redis address are read from the environment **when
the file is generated**, so regenerate with their real values.

Read at sync time (`${VAR}`): `OAN_AUTH_UPSTREAM_HOST`, `FRAPPE_SITE_NAME`.

| Variable                                 | Default                        | Meaning                      |
| ---------------------------------------- | ------------------------------ | ---------------------------- |
| `OAN_AUTH_UPSTREAM_PORT`                 | `8000`                         | Frappe port                  |
| `CORS_ORIGINS_REGEX`                     | `https?://localhost(:[0-9]+)?` | Allowed browser origin regex |
| `APISIX_REDIS_HOST`, `APISIX_REDIS_PORT` | `redis`, `6379`                | Rate-limit counter store     |

## Kubernetes (APISIX Ingress Controller)

`k8s/` is the `oan-auth-gateway` Helm chart. The same generator writes its `templates/`
(`ApisixRoute`, `ApisixUpstream`) from the ADC document, through
`gateway_apisix.write_helm_templates`. Only `Chart.yaml` is hand-edited. The chart has no
default values: hosts, the Frappe Service name and port, the site name, the Redis host and
the CORS origins come from the per-environment values in
[oan-helm](https://github.com/Centre-for-Open-Societal-Systems/oan-helm), and a missing
required value fails the render.

```bash
helm upgrade --install oan-auth-gateway apisix/k8s -n <namespace> \
  -f <oan-helm>/environments/dev/values/oan-auth-gateway.yaml
```

This app runs inside the same Frappe bench as the app it serves, so its routes point at
that app's Frappe Service and site. Manage a gateway with either the Ingress Controller or
`adc sync`, never both. Each one overwrites the other's routes.

## Token checking

`GATEWAY_JWT = False` in the generator (default): the gateway does not verify tokens.
Frappe's `auth_hooks` middleware does, for both `oan_auth_service` tokens and OpenG2P IAM
tokens. The gateway only rate-limits (by client address), caps body size and handles CORS.
Set `GATEWAY_JWT = True` in both repos only for a deployment that issues
`oan_auth_service` tokens exclusively: it adds `jwt-auth` on bearer routes, keys limits by
token, and emits the `oan-auth-jwt-issuer` consumer (needs `OAN_AUTH_JWT_PUBLIC_KEY`, the
PEM, and `OAN_JWT_ISSUER`), which refuses IAM tokens.

## Known limits

- Rate limits are per client address. Users behind one NAT or proxy share a bucket, and
  limits keyed per user are not possible without a verified token. Forward the real client
  address (`real-ip` plugin or trusted proxy config) when a load balancer sits in front.
- Requests with a missing or invalid token reach Frappe, which rejects them (401, or 503 if
  IAM is down). The gateway cannot return that 401 itself.
- `adc diff` prints only a summary; the detail is written to `diff.yaml` in the working directory.
