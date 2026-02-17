# WebServer Discovery

`@opsimathically/webdiscovery` probes TCP ports using HTTP methods and URL paths to identify which services are web servers, how they respond, and which technologies they likely run. This code is intended for my use only, although you may find it useful.

## Install

```bash
npm install @opsimathically/webdiscovery
```

## Build From Source

```bash
npm install
npm run build
```

## Example Usage

```typescript
import { WebServerDiscovery } from './classes/webserverdiscovery/WebServerDiscovery.class';

const webserverdiscovery = new WebServerDiscovery();
const discovery_result = await webserverdiscovery.discover({
  host: '192.168.11.1',
  tcp_ports: [80, 443],
  methods: ['GET', 'POST', 'OPTIONS'],
  paths: ['/', '/admin', '/info'],
  timeout_miliseconds: 2000,
  rejectUnauthorized: false,
  concurrency: 10,
  rate_limit_per_second: 25
});
```

## API

`WebServerDiscovery.discover(params)` accepts:

- `host: string`
- `tcp_ports: number[]`
- `methods: string[]`
- `paths: string[]`
- `timeout_miliseconds?: number` default `2000`
- `rejectUnauthorized?: boolean` default `true`
- `concurrency?: number` default `5`
- `rate_limit_per_second?: number | null` default `null` (disabled)
- `max_body_preview_bytes?: number` default `2048`
- `retry_policy?: retry_policy_t`

`retry_policy_t` fields:

- `max_retries_per_scheme?: number` default `0`
- `initial_backoff_miliseconds?: number` default `100`
- `max_backoff_miliseconds?: number` default `1000`
- `backoff_multiplier?: number` default `2`
- `retryable_error_types?: ('timeout' | 'tls' | 'connection' | 'unknown')[]` default `['timeout', 'connection', 'tls']`

Returns:

- `request_results`: per-request result objects with scheme attempts, status, headers, timing, body preview, and errors.
- `port_results`: per-port summary including responsiveness, detected schemes, and per-port inferred technologies.
- `identified_technologies`: deduplicated technology findings with confidence and evidence.
- `summary`: request/port counts and total scan duration.

## Discovery Behavior

- Every `tcp_port x method x path` combination is tested.
- Scheme strategy is per-port:
- Known TLS ports (`443`, `8443`, `9443`) try `https` first, then fallback to `http`.
- Other ports try `http` first, then fallback to `https`.
- Request errors are classified (timeout, tls, connection, unknown).
- Responses collect status, headers, body preview, and timing metadata.
- Optional retries run per scheme before fallback, using exponential backoff.

## Rate Limiting And Concurrency

- `concurrency` controls max in-flight probe tasks.
- `rate_limit_per_second` controls max global request start rate.
- Both are applied together:
- Workers run concurrently up to `concurrency`.
- A shared rate-limit gate spaces request starts to respect `rate_limit_per_second`.
- This prevents request bursts while preserving throughput.
- Retries also respect this flow, so backoff and rate-limit behavior remain coherent.

## Technology Fingerprinting

Fingerprinting analyzes response headers and body preview for signals such as:

- Web servers: `nginx`, `apache`, `iis`, `openresty`, `litespeed`, `caddy`, `envoy`, `gunicorn`, `uvicorn`, `waitress`, `passenger`, `tomcat`, `jetty`, `kestrel`, `tengine`, `h2o`
- Frameworks/runtimes: `asp_net`, `rails`, `django`, `laravel`, `symfony`, `spring`, `express`, `fastify`, `koa`, `nestjs`, `hapi`, `sails`, `adonisjs`, `nextjs`, `nuxtjs`, `gatsby`, `remix`, `angular`, `react`, `vue`, `sveltekit`, `flask`, `phoenix`, `meteor`, `php`, `nodejs`
- CMS/services: `wordpress`, `drupal`, `joomla`, `magento`, `shopify`, `ghost`, `mediawiki`, `prestashop`, `typo3`, `opencart`, `moodle`, `strapi`
- CDN/edge/service signals: `cloudflare`, `cloudfront`, `fastly`, `akamai`, `imperva`, `sucuri`, `vercel`, `netlify`, `heroku`, `render`, `azure_front_door`, `varnish`, `mod_pagespeed`

Each finding includes:

- `technology_id`
- `display_name`
- `category`
- `confidence` (0 to 1)
- `evidences` (source, signal, matched value, note)

Confidence increases when multiple independent signals are found for the same technology.

## Testing

```bash
npm test
```

Test coverage includes:

- HTTP and HTTPS local service detection
- HTTP/HTTPS fallback behavior
- TLS validation behavior (`rejectUnauthorized`)
- Timeout handling
- Input validation
- Concurrency and rate-limit coherence

## Limitations And Safety Notes

- Fingerprinting is heuristic and probabilistic, not definitive attribution.
- Some server headers may be intentionally obfuscated or removed.
- Body analysis is preview-based (bounded bytes), not full content parsing.
- Configure conservative `rate_limit_per_second` and `concurrency` values when scanning remote infrastructure.
