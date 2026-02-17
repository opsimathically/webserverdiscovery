import http from 'node:http';
import https from 'node:https';
import { performance } from 'node:perf_hooks';

export type scheme_t = 'http' | 'https';

export type technology_category_t =
  | 'web_server'
  | 'application_framework'
  | 'cms'
  | 'language_runtime'
  | 'service';

export type technology_evidence_t = {
  source: 'header' | 'body' | 'cookie';
  signal: string;
  matched_value: string;
  confidence: number;
  note: string;
};

export type technology_finding_t = {
  technology_id: string;
  display_name: string;
  category: technology_category_t;
  confidence: number;
  evidences: technology_evidence_t[];
};

export type request_attempt_t = {
  scheme: scheme_t;
  attempt_number: number;
  successful_response: boolean;
  error_type: string | null;
  error_message: string | null;
};

export type retry_error_type_t = 'timeout' | 'tls' | 'connection' | 'unknown';

export type retry_policy_t = {
  max_retries_per_scheme?: number;
  initial_backoff_miliseconds?: number;
  max_backoff_miliseconds?: number;
  backoff_multiplier?: number;
  retryable_error_types?: retry_error_type_t[];
};

export type request_discovery_result_t = {
  host: string;
  tcp_port: number;
  method: string;
  path: string;
  final_scheme: scheme_t | null;
  attempted_schemes: scheme_t[];
  attempts: request_attempt_t[];
  is_http_responsive: boolean;
  status_code: number | null;
  status_message: string | null;
  response_headers: Record<string, string>;
  response_time_miliseconds: number | null;
  body_preview: string;
  body_bytes_received: number;
  content_type: string | null;
  content_length: number | null;
  technologies: technology_finding_t[];
  error_type: string | null;
  error_message: string | null;
};

export type port_discovery_result_t = {
  tcp_port: number;
  successful_requests: number;
  failed_requests: number;
  http_responsive: boolean;
  detected_schemes: scheme_t[];
  inferred_technologies: technology_finding_t[];
};

export type web_server_discovery_summary_t = {
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  responsive_ports: number;
  unresponsive_ports: number;
  duration_miliseconds: number;
};

export type web_server_discovery_params_t = {
  host: string;
  tcp_ports: number[];
  methods: string[];
  paths: string[];
  timeout_miliseconds?: number;
  rejectUnauthorized?: boolean;
  concurrency?: number;
  rate_limit_per_second?: number | null;
  max_body_preview_bytes?: number;
  retry_policy?: retry_policy_t;
};

export type web_server_discovery_result_t = {
  host: string;
  request_count: number;
  request_results: request_discovery_result_t[];
  port_results: port_discovery_result_t[];
  identified_technologies: technology_finding_t[];
  summary: web_server_discovery_summary_t;
};

type normalized_web_server_discovery_params_t = {
  host: string;
  tcp_ports: number[];
  methods: string[];
  paths: string[];
  timeout_miliseconds: number;
  rejectUnauthorized: boolean;
  concurrency: number;
  rate_limit_per_second: number | null;
  max_body_preview_bytes: number;
  retry_policy: required_retry_policy_t;
};

type required_retry_policy_t = {
  max_retries_per_scheme: number;
  initial_backoff_miliseconds: number;
  max_backoff_miliseconds: number;
  backoff_multiplier: number;
  retryable_error_types: retry_error_type_t[];
};

type request_task_t = {
  host: string;
  tcp_port: number;
  method: string;
  path: string;
  preferred_scheme: scheme_t;
  fallback_scheme: scheme_t;
};

type low_level_request_result_t = {
  successful_response: boolean;
  status_code: number | null;
  status_message: string | null;
  response_headers: Record<string, string>;
  response_time_miliseconds: number | null;
  body_preview: string;
  body_bytes_received: number;
  error_type: string | null;
  error_message: string | null;
  should_try_fallback: boolean;
};

type raw_technology_finding_t = {
  technology_id: string;
  display_name: string;
  category: technology_category_t;
  confidence: number;
  evidence: technology_evidence_t;
};

type fingerprint_source_t = 'header' | 'body' | 'cookie';

type fingerprint_match_type_t = 'contains' | 'exists' | 'regex';

type fingerprint_signature_t = {
  technology_id: string;
  display_name: string;
  category: technology_category_t;
  confidence: number;
  source: fingerprint_source_t;
  signal: string;
  match_type: fingerprint_match_type_t;
  match_value?: string;
  match_regex?: RegExp;
  note: string;
};

const KNOWN_TLS_PORTS = new Set<number>([443, 8443, 9443]);

const DEFAULT_TIMEOUT_MILISECONDS = 2000;
const DEFAULT_CONCURRENCY = 5;
const DEFAULT_MAX_BODY_PREVIEW_BYTES = 2048;
const DEFAULT_MAX_RETRIES_PER_SCHEME = 0;
const DEFAULT_INITIAL_BACKOFF_MILISECONDS = 100;
const DEFAULT_MAX_BACKOFF_MILISECONDS = 1000;
const DEFAULT_BACKOFF_MULTIPLIER = 2;
const DEFAULT_RETRYABLE_ERROR_TYPES: retry_error_type_t[] = [
  'timeout',
  'connection',
  'tls'
];

const KNOWN_RETRY_ERROR_TYPES = new Set<retry_error_type_t>([
  'timeout',
  'tls',
  'connection',
  'unknown'
]);

const FINGERPRINT_SIGNATURES: fingerprint_signature_t[] = [
  {
    technology_id: 'nginx',
    display_name: 'Nginx',
    category: 'web_server',
    confidence: 0.95,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'nginx',
    note: 'server header includes nginx'
  },
  {
    technology_id: 'apache',
    display_name: 'Apache HTTP Server',
    category: 'web_server',
    confidence: 0.95,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'apache',
    note: 'server header includes apache'
  },
  {
    technology_id: 'iis',
    display_name: 'Microsoft IIS',
    category: 'web_server',
    confidence: 0.95,
    source: 'header',
    signal: 'server',
    match_type: 'regex',
    match_regex: /(microsoft-)?iis/i,
    note: 'server header indicates iis'
  },
  {
    technology_id: 'openresty',
    display_name: 'OpenResty',
    category: 'web_server',
    confidence: 0.95,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'openresty',
    note: 'server header includes openresty'
  },
  {
    technology_id: 'litespeed',
    display_name: 'LiteSpeed',
    category: 'web_server',
    confidence: 0.95,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'litespeed',
    note: 'server header includes litespeed'
  },
  {
    technology_id: 'caddy',
    display_name: 'Caddy',
    category: 'web_server',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'caddy',
    note: 'server header includes caddy'
  },
  {
    technology_id: 'envoy',
    display_name: 'Envoy',
    category: 'web_server',
    confidence: 0.9,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'envoy',
    note: 'server header includes envoy'
  },
  {
    technology_id: 'gunicorn',
    display_name: 'Gunicorn',
    category: 'web_server',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'gunicorn',
    note: 'server header includes gunicorn'
  },
  {
    technology_id: 'uvicorn',
    display_name: 'Uvicorn',
    category: 'web_server',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'uvicorn',
    note: 'server header includes uvicorn'
  },
  {
    technology_id: 'waitress',
    display_name: 'Waitress',
    category: 'web_server',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'waitress',
    note: 'server header includes waitress'
  },
  {
    technology_id: 'werkzeug',
    display_name: 'Werkzeug',
    category: 'application_framework',
    confidence: 0.88,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'werkzeug',
    note: 'server header includes werkzeug'
  },
  {
    technology_id: 'passenger',
    display_name: 'Phusion Passenger',
    category: 'web_server',
    confidence: 0.9,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'passenger',
    note: 'server header includes passenger'
  },
  {
    technology_id: 'tomcat',
    display_name: 'Apache Tomcat',
    category: 'web_server',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'tomcat',
    note: 'server header includes tomcat'
  },
  {
    technology_id: 'jetty',
    display_name: 'Jetty',
    category: 'web_server',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'jetty',
    note: 'server header includes jetty'
  },
  {
    technology_id: 'kestrel',
    display_name: 'Kestrel',
    category: 'web_server',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'kestrel',
    note: 'server header includes kestrel'
  },
  {
    technology_id: 'tengine',
    display_name: 'Tengine',
    category: 'web_server',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'tengine',
    note: 'server header includes tengine'
  },
  {
    technology_id: 'h2o',
    display_name: 'H2O',
    category: 'web_server',
    confidence: 0.9,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'h2o',
    note: 'server header includes h2o'
  },
  {
    technology_id: 'php',
    display_name: 'PHP',
    category: 'language_runtime',
    confidence: 0.85,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'php',
    note: 'x-powered-by includes php'
  },
  {
    technology_id: 'nodejs',
    display_name: 'Node.js',
    category: 'language_runtime',
    confidence: 0.75,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'node',
    note: 'x-powered-by includes node'
  },
  {
    technology_id: 'express',
    display_name: 'Express',
    category: 'application_framework',
    confidence: 0.88,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'express',
    note: 'x-powered-by includes express'
  },
  {
    technology_id: 'fastify',
    display_name: 'Fastify',
    category: 'application_framework',
    confidence: 0.85,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'fastify',
    note: 'x-powered-by includes fastify'
  },
  {
    technology_id: 'koa',
    display_name: 'Koa',
    category: 'application_framework',
    confidence: 0.84,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'koa',
    note: 'x-powered-by includes koa'
  },
  {
    technology_id: 'nestjs',
    display_name: 'NestJS',
    category: 'application_framework',
    confidence: 0.86,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'nestjs',
    note: 'x-powered-by includes nestjs'
  },
  {
    technology_id: 'hapi',
    display_name: 'hapi',
    category: 'application_framework',
    confidence: 0.84,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'hapi',
    note: 'x-powered-by includes hapi'
  },
  {
    technology_id: 'sails',
    display_name: 'Sails.js',
    category: 'application_framework',
    confidence: 0.84,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'sails',
    note: 'x-powered-by includes sails'
  },
  {
    technology_id: 'adonisjs',
    display_name: 'AdonisJS',
    category: 'application_framework',
    confidence: 0.84,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'adonis',
    note: 'x-powered-by includes adonis'
  },
  {
    technology_id: 'nextjs',
    display_name: 'Next.js',
    category: 'application_framework',
    confidence: 0.84,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'next.js',
    note: 'x-powered-by includes next.js'
  },
  {
    technology_id: 'nuxtjs',
    display_name: 'Nuxt',
    category: 'application_framework',
    confidence: 0.84,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'nuxt',
    note: 'x-powered-by includes nuxt'
  },
  {
    technology_id: 'asp_net',
    display_name: 'ASP.NET',
    category: 'application_framework',
    confidence: 0.9,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'asp.net',
    note: 'x-powered-by includes asp.net'
  },
  {
    technology_id: 'asp_net',
    display_name: 'ASP.NET',
    category: 'application_framework',
    confidence: 0.9,
    source: 'header',
    signal: 'x-aspnet-version',
    match_type: 'exists',
    note: 'x-aspnet-version header exists'
  },
  {
    technology_id: 'rails',
    display_name: 'Ruby on Rails',
    category: 'application_framework',
    confidence: 0.84,
    source: 'header',
    signal: 'x-runtime',
    match_type: 'exists',
    note: 'x-runtime header exists'
  },
  {
    technology_id: 'rails',
    display_name: 'Ruby on Rails',
    category: 'application_framework',
    confidence: 0.88,
    source: 'header',
    signal: 'x-rails-version',
    match_type: 'exists',
    note: 'x-rails-version header exists'
  },
  {
    technology_id: 'django',
    display_name: 'Django',
    category: 'application_framework',
    confidence: 0.88,
    source: 'header',
    signal: 'x-django-version',
    match_type: 'exists',
    note: 'x-django-version header exists'
  },
  {
    technology_id: 'django',
    display_name: 'Django',
    category: 'application_framework',
    confidence: 0.82,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'csrftoken=',
    note: 'cookie contains csrftoken'
  },
  {
    technology_id: 'django',
    display_name: 'Django',
    category: 'application_framework',
    confidence: 0.8,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'sessionid=',
    note: 'cookie contains django sessionid'
  },
  {
    technology_id: 'laravel',
    display_name: 'Laravel',
    category: 'application_framework',
    confidence: 0.9,
    source: 'header',
    signal: 'x-laravel-version',
    match_type: 'exists',
    note: 'x-laravel-version header exists'
  },
  {
    technology_id: 'laravel',
    display_name: 'Laravel',
    category: 'application_framework',
    confidence: 0.84,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'laravel_session=',
    note: 'cookie contains laravel_session'
  },
  {
    technology_id: 'laravel',
    display_name: 'Laravel',
    category: 'application_framework',
    confidence: 0.78,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'xsrf-token=',
    note: 'cookie contains xsrf-token'
  },
  {
    technology_id: 'symfony',
    display_name: 'Symfony',
    category: 'application_framework',
    confidence: 0.85,
    source: 'header',
    signal: 'x-symfony-cache',
    match_type: 'exists',
    note: 'x-symfony-cache header exists'
  },
  {
    technology_id: 'spring',
    display_name: 'Spring',
    category: 'application_framework',
    confidence: 0.86,
    source: 'header',
    signal: 'x-application-context',
    match_type: 'exists',
    note: 'x-application-context header exists'
  },
  {
    technology_id: 'spring',
    display_name: 'Spring',
    category: 'application_framework',
    confidence: 0.82,
    source: 'header',
    signal: 'x-spring-version',
    match_type: 'exists',
    note: 'x-spring-version header exists'
  },
  {
    technology_id: 'java_servlet',
    display_name: 'Java Servlet',
    category: 'application_framework',
    confidence: 0.75,
    source: 'header',
    signal: 'x-powered-by',
    match_type: 'contains',
    match_value: 'servlet',
    note: 'x-powered-by includes servlet'
  },
  {
    technology_id: 'wordpress',
    display_name: 'WordPress',
    category: 'cms',
    confidence: 0.9,
    source: 'header',
    signal: 'x-generator',
    match_type: 'contains',
    match_value: 'wordpress',
    note: 'x-generator includes wordpress'
  },
  {
    technology_id: 'wordpress',
    display_name: 'WordPress',
    category: 'cms',
    confidence: 0.88,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'wordpress_',
    note: 'cookie contains wordpress marker'
  },
  {
    technology_id: 'wordpress',
    display_name: 'WordPress',
    category: 'cms',
    confidence: 0.84,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'wp-settings',
    note: 'cookie contains wp-settings marker'
  },
  {
    technology_id: 'drupal',
    display_name: 'Drupal',
    category: 'cms',
    confidence: 0.88,
    source: 'header',
    signal: 'x-generator',
    match_type: 'contains',
    match_value: 'drupal',
    note: 'x-generator includes drupal'
  },
  {
    technology_id: 'drupal',
    display_name: 'Drupal',
    category: 'cms',
    confidence: 0.86,
    source: 'header',
    signal: 'x-drupal-cache',
    match_type: 'exists',
    note: 'x-drupal-cache header exists'
  },
  {
    technology_id: 'joomla',
    display_name: 'Joomla',
    category: 'cms',
    confidence: 0.9,
    source: 'header',
    signal: 'x-generator',
    match_type: 'contains',
    match_value: 'joomla',
    note: 'x-generator includes joomla'
  },
  {
    technology_id: 'ghost',
    display_name: 'Ghost',
    category: 'cms',
    confidence: 0.88,
    source: 'header',
    signal: 'x-generator',
    match_type: 'contains',
    match_value: 'ghost',
    note: 'x-generator includes ghost'
  },
  {
    technology_id: 'mediawiki',
    display_name: 'MediaWiki',
    category: 'cms',
    confidence: 0.88,
    source: 'header',
    signal: 'x-generator',
    match_type: 'contains',
    match_value: 'mediawiki',
    note: 'x-generator includes mediawiki'
  },
  {
    technology_id: 'shopify',
    display_name: 'Shopify',
    category: 'service',
    confidence: 0.86,
    source: 'header',
    signal: 'x-shopify-stage',
    match_type: 'exists',
    note: 'x-shopify-stage header exists'
  },
  {
    technology_id: 'shopify',
    display_name: 'Shopify',
    category: 'service',
    confidence: 0.82,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: '_shopify_y=',
    note: 'cookie contains _shopify_y'
  },
  {
    technology_id: 'shopify',
    display_name: 'Shopify',
    category: 'service',
    confidence: 0.82,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'shop_session_token=',
    note: 'cookie contains shop_session_token'
  },
  {
    technology_id: 'cloudflare',
    display_name: 'Cloudflare',
    category: 'service',
    confidence: 0.92,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'cloudflare',
    note: 'server header indicates cloudflare'
  },
  {
    technology_id: 'cloudflare',
    display_name: 'Cloudflare',
    category: 'service',
    confidence: 0.94,
    source: 'header',
    signal: 'cf-ray',
    match_type: 'exists',
    note: 'cf-ray header exists'
  },
  {
    technology_id: 'cloudflare',
    display_name: 'Cloudflare',
    category: 'service',
    confidence: 0.86,
    source: 'header',
    signal: 'cf-cache-status',
    match_type: 'exists',
    note: 'cf-cache-status header exists'
  },
  {
    technology_id: 'cloudfront',
    display_name: 'Amazon CloudFront',
    category: 'service',
    confidence: 0.92,
    source: 'header',
    signal: 'x-amz-cf-id',
    match_type: 'exists',
    note: 'x-amz-cf-id header exists'
  },
  {
    technology_id: 'fastly',
    display_name: 'Fastly',
    category: 'service',
    confidence: 0.88,
    source: 'header',
    signal: 'x-served-by',
    match_type: 'contains',
    match_value: 'cache-',
    note: 'x-served-by includes fastly cache marker'
  },
  {
    technology_id: 'akamai',
    display_name: 'Akamai',
    category: 'service',
    confidence: 0.84,
    source: 'header',
    signal: 'server',
    match_type: 'contains',
    match_value: 'akamai',
    note: 'server header includes akamai'
  },
  {
    technology_id: 'imperva',
    display_name: 'Imperva',
    category: 'service',
    confidence: 0.88,
    source: 'header',
    signal: 'x-iinfo',
    match_type: 'exists',
    note: 'x-iinfo header exists'
  },
  {
    technology_id: 'sucuri',
    display_name: 'Sucuri',
    category: 'service',
    confidence: 0.88,
    source: 'header',
    signal: 'x-sucuri-id',
    match_type: 'exists',
    note: 'x-sucuri-id header exists'
  },
  {
    technology_id: 'vercel',
    display_name: 'Vercel',
    category: 'service',
    confidence: 0.9,
    source: 'header',
    signal: 'x-vercel-id',
    match_type: 'exists',
    note: 'x-vercel-id header exists'
  },
  {
    technology_id: 'netlify',
    display_name: 'Netlify',
    category: 'service',
    confidence: 0.9,
    source: 'header',
    signal: 'x-nf-request-id',
    match_type: 'exists',
    note: 'x-nf-request-id header exists'
  },
  {
    technology_id: 'heroku',
    display_name: 'Heroku',
    category: 'service',
    confidence: 0.86,
    source: 'header',
    signal: 'x-request-id',
    match_type: 'regex',
    match_regex: /^[a-f0-9-]{20,}$/i,
    note: 'request id resembles heroku header pattern'
  },
  {
    technology_id: 'render',
    display_name: 'Render',
    category: 'service',
    confidence: 0.88,
    source: 'header',
    signal: 'x-render-origin-server',
    match_type: 'exists',
    note: 'x-render-origin-server header exists'
  },
  {
    technology_id: 'azure_front_door',
    display_name: 'Azure Front Door',
    category: 'service',
    confidence: 0.88,
    source: 'header',
    signal: 'x-azure-ref',
    match_type: 'exists',
    note: 'x-azure-ref header exists'
  },
  {
    technology_id: 'varnish',
    display_name: 'Varnish',
    category: 'service',
    confidence: 0.86,
    source: 'header',
    signal: 'via',
    match_type: 'contains',
    match_value: 'varnish',
    note: 'via header includes varnish'
  },
  {
    technology_id: 'mod_pagespeed',
    display_name: 'mod_pagespeed',
    category: 'service',
    confidence: 0.86,
    source: 'header',
    signal: 'x-mod-pagespeed',
    match_type: 'exists',
    note: 'x-mod-pagespeed header exists'
  },
  {
    technology_id: 'wordpress',
    display_name: 'WordPress',
    category: 'cms',
    confidence: 0.86,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'wp-content',
    note: 'body contains wp-content'
  },
  {
    technology_id: 'wordpress',
    display_name: 'WordPress',
    category: 'cms',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'wp-includes',
    note: 'body contains wp-includes'
  },
  {
    technology_id: 'wordpress',
    display_name: 'WordPress',
    category: 'cms',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '/wp-json/',
    note: 'body contains wp-json endpoint'
  },
  {
    technology_id: 'drupal',
    display_name: 'Drupal',
    category: 'cms',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '/sites/default/files',
    note: 'body references drupal default files path'
  },
  {
    technology_id: 'drupal',
    display_name: 'Drupal',
    category: 'cms',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'drupal-settings-json',
    note: 'body includes drupal-settings-json'
  },
  {
    technology_id: 'drupal',
    display_name: 'Drupal',
    category: 'cms',
    confidence: 0.8,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'data-drupal-selector',
    note: 'body includes data-drupal-selector'
  },
  {
    technology_id: 'joomla',
    display_name: 'Joomla',
    category: 'cms',
    confidence: 0.86,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '/media/system/js/core.js',
    note: 'body references joomla core.js'
  },
  {
    technology_id: 'joomla',
    display_name: 'Joomla',
    category: 'cms',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'option=com_',
    note: 'body contains joomla option query marker'
  },
  {
    technology_id: 'magento',
    display_name: 'Magento',
    category: 'cms',
    confidence: 0.86,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'mage/cookies.js',
    note: 'body references magento script'
  },
  {
    technology_id: 'magento',
    display_name: 'Magento',
    category: 'cms',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'magento_ui/js',
    note: 'body references magento ui assets'
  },
  {
    technology_id: 'shopify',
    display_name: 'Shopify',
    category: 'service',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'cdn.shopify.com',
    note: 'body references shopify cdn'
  },
  {
    technology_id: 'shopify',
    display_name: 'Shopify',
    category: 'service',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'shopify.theme',
    note: 'body includes shopify.theme object'
  },
  {
    technology_id: 'wix',
    display_name: 'Wix',
    category: 'service',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'wixstatic.com',
    note: 'body references wixstatic'
  },
  {
    technology_id: 'squarespace',
    display_name: 'Squarespace',
    category: 'service',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'static.squarespace.com',
    note: 'body references squarespace static assets'
  },
  {
    technology_id: 'ghost',
    display_name: 'Ghost',
    category: 'cms',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'ghost/content',
    note: 'body references ghost content api'
  },
  {
    technology_id: 'django',
    display_name: 'Django',
    category: 'application_framework',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'csrfmiddlewaretoken',
    note: 'body includes django csrf middleware token field'
  },
  {
    technology_id: 'django',
    display_name: 'Django',
    category: 'application_framework',
    confidence: 0.78,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'django-admin',
    note: 'body references django-admin'
  },
  {
    technology_id: 'laravel',
    display_name: 'Laravel',
    category: 'application_framework',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'name="csrf-token"',
    note: 'body includes laravel csrf-token meta'
  },
  {
    technology_id: 'laravel',
    display_name: 'Laravel',
    category: 'application_framework',
    confidence: 0.78,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '/vendor/laravel/',
    note: 'body references laravel vendor path'
  },
  {
    technology_id: 'spring',
    display_name: 'Spring',
    category: 'application_framework',
    confidence: 0.86,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'whitelabel error page',
    note: 'body contains spring boot whitelabel page marker'
  },
  {
    technology_id: 'spring',
    display_name: 'Spring',
    category: 'application_framework',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'there was an unexpected error (type=',
    note: 'body contains common spring boot error format'
  },
  {
    technology_id: 'rails',
    display_name: 'Ruby on Rails',
    category: 'application_framework',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'csrf-param',
    note: 'body contains rails csrf-param'
  },
  {
    technology_id: 'rails',
    display_name: 'Ruby on Rails',
    category: 'application_framework',
    confidence: 0.78,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'actioncable',
    note: 'body contains rails actioncable marker'
  },
  {
    technology_id: 'php',
    display_name: 'PHP',
    category: 'language_runtime',
    confidence: 0.8,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'phpsessid=',
    note: 'cookie contains phpsessid'
  },
  {
    technology_id: 'php',
    display_name: 'PHP',
    category: 'language_runtime',
    confidence: 0.65,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'phpinfo()',
    note: 'body contains phpinfo marker'
  },
  {
    technology_id: 'flask',
    display_name: 'Flask',
    category: 'application_framework',
    confidence: 0.78,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'werkzeug debugger',
    note: 'body contains werkzeug debugger marker'
  },
  {
    technology_id: 'flask',
    display_name: 'Flask',
    category: 'application_framework',
    confidence: 0.74,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'flask',
    note: 'body contains flask marker'
  },
  {
    technology_id: 'phoenix',
    display_name: 'Phoenix',
    category: 'application_framework',
    confidence: 0.78,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'data-phx-main',
    note: 'body contains phoenix liveview marker'
  },
  {
    technology_id: 'meteor',
    display_name: 'Meteor',
    category: 'application_framework',
    confidence: 0.8,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '__meteor_runtime_config__',
    note: 'body contains meteor runtime config marker'
  },
  {
    technology_id: 'nextjs',
    display_name: 'Next.js',
    category: 'application_framework',
    confidence: 0.88,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'id="__next"',
    note: 'body contains next.js root element'
  },
  {
    technology_id: 'nextjs',
    display_name: 'Next.js',
    category: 'application_framework',
    confidence: 0.86,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '__next_data__',
    note: 'body contains __next_data__ marker'
  },
  {
    technology_id: 'nuxtjs',
    display_name: 'Nuxt',
    category: 'application_framework',
    confidence: 0.86,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'window.__nuxt__',
    note: 'body contains nuxt bootstrap object'
  },
  {
    technology_id: 'gatsby',
    display_name: 'Gatsby',
    category: 'application_framework',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'gatsby-browser.js',
    note: 'body references gatsby-browser.js'
  },
  {
    technology_id: 'remix',
    display_name: 'Remix',
    category: 'application_framework',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '__remix_context__',
    note: 'body contains remix runtime context'
  },
  {
    technology_id: 'angular',
    display_name: 'Angular',
    category: 'application_framework',
    confidence: 0.8,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'ng-version=',
    note: 'body contains angular ng-version marker'
  },
  {
    technology_id: 'react',
    display_name: 'React',
    category: 'application_framework',
    confidence: 0.74,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'data-reactroot',
    note: 'body contains data-reactroot marker'
  },
  {
    technology_id: 'vue',
    display_name: 'Vue',
    category: 'application_framework',
    confidence: 0.74,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'data-v-app',
    note: 'body contains data-v-app marker'
  },
  {
    technology_id: 'sveltekit',
    display_name: 'SvelteKit',
    category: 'application_framework',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '__sveltekit',
    note: 'body contains sveltekit runtime marker'
  },
  {
    technology_id: 'blazor',
    display_name: 'Blazor',
    category: 'application_framework',
    confidence: 0.84,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '_framework/blazor',
    note: 'body references blazor framework assets'
  },
  {
    technology_id: 'strapi',
    display_name: 'Strapi',
    category: 'service',
    confidence: 0.75,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'strapi',
    note: 'body contains strapi marker'
  },
  {
    technology_id: 'prestashop',
    display_name: 'PrestaShop',
    category: 'cms',
    confidence: 0.8,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: '/modules/ps_',
    note: 'body references prestashop module path'
  },
  {
    technology_id: 'typo3',
    display_name: 'TYPO3',
    category: 'cms',
    confidence: 0.8,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'typo3',
    note: 'body contains typo3 marker'
  },
  {
    technology_id: 'opencart',
    display_name: 'OpenCart',
    category: 'cms',
    confidence: 0.78,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'index.php?route=',
    note: 'body contains opencart route query'
  },
  {
    technology_id: 'mediawiki',
    display_name: 'MediaWiki',
    category: 'cms',
    confidence: 0.82,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'mediawiki.page.startup',
    note: 'body includes mediawiki startup marker'
  },
  {
    technology_id: 'moodle',
    display_name: 'Moodle',
    category: 'cms',
    confidence: 0.8,
    source: 'body',
    signal: 'body',
    match_type: 'contains',
    match_value: 'moodle',
    note: 'body contains moodle marker'
  },
  {
    technology_id: 'express',
    display_name: 'Express',
    category: 'application_framework',
    confidence: 0.78,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'connect.sid=',
    note: 'cookie contains connect.sid'
  },
  {
    technology_id: 'koa',
    display_name: 'Koa',
    category: 'application_framework',
    confidence: 0.78,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'koa:sess=',
    note: 'cookie contains koa:sess'
  },
  {
    technology_id: 'sails',
    display_name: 'Sails.js',
    category: 'application_framework',
    confidence: 0.78,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'sails.sid=',
    note: 'cookie contains sails.sid'
  },
  {
    technology_id: 'nextjs',
    display_name: 'Next.js',
    category: 'application_framework',
    confidence: 0.78,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: '__next_preview_data=',
    note: 'cookie contains __next_preview_data'
  },
  {
    technology_id: 'nextjs',
    display_name: 'Next.js',
    category: 'application_framework',
    confidence: 0.78,
    source: 'cookie',
    signal: 'set-cookie',
    match_type: 'contains',
    match_value: 'next-auth.session-token=',
    note: 'cookie contains next-auth session token'
  }
];

function SleepMilliseconds(params: {
  duration_miliseconds: number;
}): Promise<void> {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, params.duration_miliseconds);
  });
}

function CalculateBackoffDelay(params: {
  initial_backoff_miliseconds: number;
  max_backoff_miliseconds: number;
  backoff_multiplier: number;
  retry_index: number;
}): number {
  if (params.initial_backoff_miliseconds === 0) {
    return 0;
  }

  const exponential_delay =
    params.initial_backoff_miliseconds *
    params.backoff_multiplier ** Math.max(0, params.retry_index);
  return Math.min(
    params.max_backoff_miliseconds,
    Math.round(exponential_delay)
  );
}

function EnsureInteger(params: { value: number; field_name: string }): number {
  if (!Number.isInteger(params.value)) {
    throw new Error(`${params.field_name} must contain only integers.`);
  }
  return params.value;
}

function NormalizeHttpMethod(params: { method: string }): string {
  const normalized_method = params.method.trim().toUpperCase();
  if (normalized_method.length === 0) {
    throw new Error('methods cannot include empty entries.');
  }
  if (!/^[A-Z-]+$/.test(normalized_method)) {
    throw new Error(`Invalid HTTP method: ${params.method}`);
  }
  return normalized_method;
}

function NormalizePath(params: { path: string }): string {
  const trimmed_path = params.path.trim();
  if (trimmed_path.length === 0) {
    throw new Error('paths cannot include empty entries.');
  }
  if (trimmed_path.startsWith('/')) {
    return trimmed_path;
  }
  return `/${trimmed_path}`;
}

function NormalizeHeaders(params: {
  headers: http.IncomingHttpHeaders;
}): Record<string, string> {
  const normalized_headers: Record<string, string> = {};
  for (const header_key of Object.keys(params.headers)) {
    const header_value = params.headers[header_key];
    if (typeof header_value === 'undefined') {
      continue;
    }
    if (Array.isArray(header_value)) {
      normalized_headers[header_key.toLowerCase()] = header_value.join(', ');
      continue;
    }
    normalized_headers[header_key.toLowerCase()] = header_value;
  }
  return normalized_headers;
}

function DetermineSchemeOrderForPort(params: {
  tcp_port: number;
}): [scheme_t, scheme_t] {
  if (KNOWN_TLS_PORTS.has(params.tcp_port)) {
    return ['https', 'http'];
  }
  return ['http', 'https'];
}

function PushRawTechnologyFinding(params: {
  findings: raw_technology_finding_t[];
  finding: raw_technology_finding_t;
}): void {
  params.findings.push(params.finding);
}

function MatchFingerprintSignature(params: {
  signature: fingerprint_signature_t;
  signal_present: boolean;
  normalized_signal_value: string;
}): boolean {
  if (!params.signal_present) {
    return false;
  }

  if (params.signature.match_type === 'exists') {
    return true;
  }

  if (params.signature.match_type === 'contains') {
    if (typeof params.signature.match_value === 'undefined') {
      return false;
    }
    return params.normalized_signal_value.includes(
      params.signature.match_value
    );
  }

  if (params.signature.match_type === 'regex') {
    if (typeof params.signature.match_regex === 'undefined') {
      return false;
    }
    return params.signature.match_regex.test(params.normalized_signal_value);
  }

  return false;
}

function BuildMatchedFingerprintValue(params: {
  signature: fingerprint_signature_t;
  raw_signal_value: string;
}): string {
  if (params.signature.match_type === 'contains') {
    return params.signature.match_value ?? params.raw_signal_value;
  }

  if (params.signature.match_type === 'regex') {
    return params.signature.match_regex
      ? params.signature.match_regex.source
      : params.raw_signal_value;
  }

  if (params.raw_signal_value.length === 0) {
    return params.signature.signal;
  }

  return params.raw_signal_value;
}

function BuildTechnologiesFromHttpSignals(params: {
  response_headers: Record<string, string>;
  body_preview: string;
}): technology_finding_t[] {
  const raw_findings: raw_technology_finding_t[] = [];
  const normalized_body_preview = params.body_preview.toLowerCase();
  const normalized_headers: Record<string, string> = {};
  for (const header_key of Object.keys(params.response_headers)) {
    normalized_headers[header_key] =
      params.response_headers[header_key].toLowerCase();
  }

  for (const signature of FINGERPRINT_SIGNATURES) {
    const raw_signal_value =
      signature.source === 'body'
        ? params.body_preview
        : (params.response_headers[signature.signal] ?? '');
    const normalized_signal_value =
      signature.source === 'body'
        ? normalized_body_preview
        : (normalized_headers[signature.signal] ?? '');
    const signal_present =
      signature.source === 'body'
        ? normalized_body_preview.length > 0
        : typeof params.response_headers[signature.signal] !== 'undefined';

    if (
      !MatchFingerprintSignature({
        signature,
        signal_present,
        normalized_signal_value
      })
    ) {
      continue;
    }

    PushRawTechnologyFinding({
      findings: raw_findings,
      finding: {
        technology_id: signature.technology_id,
        display_name: signature.display_name,
        category: signature.category,
        confidence: signature.confidence,
        evidence: {
          source: signature.source,
          signal: signature.signal,
          matched_value: BuildMatchedFingerprintValue({
            signature,
            raw_signal_value
          }),
          confidence: signature.confidence,
          note: signature.note
        }
      }
    });
  }

  return MergeTechnologyFindings({
    technology_findings: raw_findings.map((finding) => ({
      technology_id: finding.technology_id,
      display_name: finding.display_name,
      category: finding.category,
      confidence: finding.confidence,
      evidences: [finding.evidence]
    }))
  });
}

function MergeTechnologyFindings(params: {
  technology_findings: technology_finding_t[];
}): technology_finding_t[] {
  const merged_technology_map = new Map<string, technology_finding_t>();
  for (const current_finding of params.technology_findings) {
    const existing_finding = merged_technology_map.get(
      current_finding.technology_id
    );
    if (!existing_finding) {
      merged_technology_map.set(current_finding.technology_id, {
        technology_id: current_finding.technology_id,
        display_name: current_finding.display_name,
        category: current_finding.category,
        confidence: current_finding.confidence,
        evidences: [...current_finding.evidences]
      });
      continue;
    }

    existing_finding.confidence = Math.min(
      0.99,
      existing_finding.confidence +
        (1 - existing_finding.confidence) * current_finding.confidence
    );

    for (const evidence of current_finding.evidences) {
      const duplicate_evidence = existing_finding.evidences.find(
        (existing_evidence) =>
          existing_evidence.signal === evidence.signal &&
          existing_evidence.matched_value === evidence.matched_value
      );
      if (!duplicate_evidence) {
        existing_finding.evidences.push(evidence);
      }
    }
  }

  return Array.from(merged_technology_map.values()).sort(
    (a, b) => b.confidence - a.confidence
  );
}

function BuildPortResults(params: {
  tcp_ports: number[];
  request_results: request_discovery_result_t[];
}): port_discovery_result_t[] {
  const port_results: port_discovery_result_t[] = [];
  for (const tcp_port of params.tcp_ports) {
    const request_results_for_port = params.request_results.filter(
      (request_result) => request_result.tcp_port === tcp_port
    );
    const successful_requests = request_results_for_port.filter(
      (request_result) => request_result.is_http_responsive
    );

    const detected_scheme_set = new Set<scheme_t>();
    for (const successful_request of successful_requests) {
      if (successful_request.final_scheme) {
        detected_scheme_set.add(successful_request.final_scheme);
      }
    }

    const inferred_technologies = MergeTechnologyFindings({
      technology_findings: request_results_for_port.flatMap(
        (request_result) => request_result.technologies
      )
    });

    port_results.push({
      tcp_port,
      successful_requests: successful_requests.length,
      failed_requests:
        request_results_for_port.length - successful_requests.length,
      http_responsive: successful_requests.length > 0,
      detected_schemes: Array.from(detected_scheme_set.values()),
      inferred_technologies
    });
  }

  return port_results;
}

function BuildSummary(params: {
  port_results: port_discovery_result_t[];
  request_results: request_discovery_result_t[];
  started_at_miliseconds: number;
  finished_at_miliseconds: number;
}): web_server_discovery_summary_t {
  const successful_requests = params.request_results.filter(
    (request_result) => request_result.is_http_responsive
  ).length;

  const responsive_ports = params.port_results.filter(
    (port_result) => port_result.http_responsive
  ).length;

  return {
    total_requests: params.request_results.length,
    successful_requests,
    failed_requests: params.request_results.length - successful_requests,
    responsive_ports,
    unresponsive_ports: params.port_results.length - responsive_ports,
    duration_miliseconds: Math.round(
      params.finished_at_miliseconds - params.started_at_miliseconds
    )
  };
}

export class WebServerDiscovery {
  private rate_limit_gate_promise: Promise<void> = Promise.resolve();

  private next_allowed_request_start_miliseconds = 0;

  async discover(
    params: web_server_discovery_params_t
  ): Promise<web_server_discovery_result_t> {
    const normalized_params = this.validateDiscoverParams({ params });
    const request_tasks = this.buildRequestTasks({ params: normalized_params });

    this.rate_limit_gate_promise = Promise.resolve();
    this.next_allowed_request_start_miliseconds = 0;

    const started_at_miliseconds = performance.now();
    const request_results = await this.executeRequestTasks({
      request_tasks,
      params: normalized_params
    });
    const finished_at_miliseconds = performance.now();

    const port_results = BuildPortResults({
      tcp_ports: normalized_params.tcp_ports,
      request_results
    });

    const identified_technologies = MergeTechnologyFindings({
      technology_findings: request_results.flatMap(
        (request_result) => request_result.technologies
      )
    });

    return {
      host: normalized_params.host,
      request_count: request_tasks.length,
      request_results,
      port_results,
      identified_technologies,
      summary: BuildSummary({
        port_results,
        request_results,
        started_at_miliseconds,
        finished_at_miliseconds
      })
    };
  }

  private validateDiscoverParams(params: {
    params: web_server_discovery_params_t;
  }): normalized_web_server_discovery_params_t {
    const host = params.params.host.trim();
    if (host.length === 0) {
      throw new Error('host is required.');
    }

    const tcp_ports = Array.from(
      new Set(
        params.params.tcp_ports.map((port) =>
          EnsureInteger({ value: port, field_name: 'tcp_ports' })
        )
      )
    );
    if (tcp_ports.length === 0) {
      throw new Error('tcp_ports must include at least one port.');
    }
    for (const tcp_port of tcp_ports) {
      if (tcp_port < 1 || tcp_port > 65535) {
        throw new Error(`Invalid tcp port: ${tcp_port}.`);
      }
    }

    const methods = Array.from(
      new Set(
        params.params.methods.map((method) => NormalizeHttpMethod({ method }))
      )
    );
    if (methods.length === 0) {
      throw new Error('methods must include at least one HTTP method.');
    }

    const paths = Array.from(
      new Set(params.params.paths.map((path) => NormalizePath({ path })))
    );
    if (paths.length === 0) {
      throw new Error('paths must include at least one URL path.');
    }

    const timeout_miliseconds =
      typeof params.params.timeout_miliseconds === 'undefined'
        ? DEFAULT_TIMEOUT_MILISECONDS
        : EnsureInteger({
            value: params.params.timeout_miliseconds,
            field_name: 'timeout_miliseconds'
          });
    if (timeout_miliseconds <= 0) {
      throw new Error('timeout_miliseconds must be greater than 0.');
    }

    const rejectUnauthorized =
      typeof params.params.rejectUnauthorized === 'boolean'
        ? params.params.rejectUnauthorized
        : true;

    const concurrency =
      typeof params.params.concurrency === 'undefined'
        ? DEFAULT_CONCURRENCY
        : EnsureInteger({
            value: params.params.concurrency,
            field_name: 'concurrency'
          });
    if (concurrency <= 0) {
      throw new Error('concurrency must be greater than 0.');
    }

    const rate_limit_per_second =
      typeof params.params.rate_limit_per_second === 'undefined'
        ? null
        : params.params.rate_limit_per_second;
    if (rate_limit_per_second !== null) {
      if (
        !Number.isFinite(rate_limit_per_second) ||
        rate_limit_per_second <= 0
      ) {
        throw new Error(
          'rate_limit_per_second must be greater than 0 when provided.'
        );
      }
    }

    const max_body_preview_bytes =
      typeof params.params.max_body_preview_bytes === 'undefined'
        ? DEFAULT_MAX_BODY_PREVIEW_BYTES
        : EnsureInteger({
            value: params.params.max_body_preview_bytes,
            field_name: 'max_body_preview_bytes'
          });
    if (max_body_preview_bytes <= 0) {
      throw new Error('max_body_preview_bytes must be greater than 0.');
    }

    const retry_policy_params = params.params.retry_policy ?? {};
    const max_retries_per_scheme =
      typeof retry_policy_params.max_retries_per_scheme === 'undefined'
        ? DEFAULT_MAX_RETRIES_PER_SCHEME
        : EnsureInteger({
            value: retry_policy_params.max_retries_per_scheme,
            field_name: 'retry_policy.max_retries_per_scheme'
          });
    if (max_retries_per_scheme < 0) {
      throw new Error('retry_policy.max_retries_per_scheme must be >= 0.');
    }

    const initial_backoff_miliseconds =
      typeof retry_policy_params.initial_backoff_miliseconds === 'undefined'
        ? DEFAULT_INITIAL_BACKOFF_MILISECONDS
        : EnsureInteger({
            value: retry_policy_params.initial_backoff_miliseconds,
            field_name: 'retry_policy.initial_backoff_miliseconds'
          });
    if (initial_backoff_miliseconds < 0) {
      throw new Error('retry_policy.initial_backoff_miliseconds must be >= 0.');
    }

    const max_backoff_miliseconds =
      typeof retry_policy_params.max_backoff_miliseconds === 'undefined'
        ? DEFAULT_MAX_BACKOFF_MILISECONDS
        : EnsureInteger({
            value: retry_policy_params.max_backoff_miliseconds,
            field_name: 'retry_policy.max_backoff_miliseconds'
          });
    if (max_backoff_miliseconds < 0) {
      throw new Error('retry_policy.max_backoff_miliseconds must be >= 0.');
    }
    if (max_backoff_miliseconds < initial_backoff_miliseconds) {
      throw new Error(
        'retry_policy.max_backoff_miliseconds must be >= retry_policy.initial_backoff_miliseconds.'
      );
    }

    const backoff_multiplier =
      typeof retry_policy_params.backoff_multiplier === 'undefined'
        ? DEFAULT_BACKOFF_MULTIPLIER
        : retry_policy_params.backoff_multiplier;
    if (!Number.isFinite(backoff_multiplier) || backoff_multiplier < 1) {
      throw new Error('retry_policy.backoff_multiplier must be >= 1.');
    }

    const retryable_error_types =
      typeof retry_policy_params.retryable_error_types === 'undefined'
        ? [...DEFAULT_RETRYABLE_ERROR_TYPES]
        : Array.from(new Set(retry_policy_params.retryable_error_types));
    for (const retryable_error_type of retryable_error_types) {
      if (!KNOWN_RETRY_ERROR_TYPES.has(retryable_error_type)) {
        throw new Error(
          `retry_policy.retryable_error_types includes unsupported type: ${retryable_error_type}`
        );
      }
    }

    return {
      host,
      tcp_ports,
      methods,
      paths,
      timeout_miliseconds,
      rejectUnauthorized,
      concurrency,
      rate_limit_per_second,
      max_body_preview_bytes,
      retry_policy: {
        max_retries_per_scheme,
        initial_backoff_miliseconds,
        max_backoff_miliseconds,
        backoff_multiplier,
        retryable_error_types
      }
    };
  }

  private buildRequestTasks(params: {
    params: normalized_web_server_discovery_params_t;
  }): request_task_t[] {
    const request_tasks: request_task_t[] = [];
    for (const tcp_port of params.params.tcp_ports) {
      const [preferred_scheme, fallback_scheme] = DetermineSchemeOrderForPort({
        tcp_port
      });
      for (const method of params.params.methods) {
        for (const path of params.params.paths) {
          request_tasks.push({
            host: params.params.host,
            tcp_port,
            method,
            path,
            preferred_scheme,
            fallback_scheme
          });
        }
      }
    }
    return request_tasks;
  }

  private async executeRequestTasks(params: {
    request_tasks: request_task_t[];
    params: normalized_web_server_discovery_params_t;
  }): Promise<request_discovery_result_t[]> {
    const request_results: request_discovery_result_t[] = new Array(
      params.request_tasks.length
    );
    let next_task_index = 0;
    const worker_count = Math.min(
      params.params.concurrency,
      params.request_tasks.length
    );

    const workers: Promise<void>[] = [];
    for (let worker_index = 0; worker_index < worker_count; worker_index += 1) {
      workers.push(
        (async () => {
          while (true) {
            const current_task_index = next_task_index;
            next_task_index += 1;

            if (current_task_index >= params.request_tasks.length) {
              return;
            }

            await this.waitForRateLimit({
              rate_limit_per_second: params.params.rate_limit_per_second
            });

            const request_task = params.request_tasks[current_task_index];
            request_results[current_task_index] = await this.executeSingleTask({
              request_task,
              timeout_miliseconds: params.params.timeout_miliseconds,
              rejectUnauthorized: params.params.rejectUnauthorized,
              max_body_preview_bytes: params.params.max_body_preview_bytes,
              retry_policy: params.params.retry_policy
            });
          }
        })()
      );
    }

    await Promise.all(workers);
    return request_results;
  }

  private async waitForRateLimit(params: {
    rate_limit_per_second: number | null;
  }): Promise<void> {
    if (params.rate_limit_per_second === null) {
      return;
    }

    const minimum_spacing_miliseconds = 1000 / params.rate_limit_per_second;
    let release_gate: () => void = () => {};

    const previous_gate = this.rate_limit_gate_promise;
    this.rate_limit_gate_promise = new Promise<void>((resolve) => {
      release_gate = resolve;
    });

    await previous_gate;

    try {
      const now_miliseconds = Date.now();
      const wait_miliseconds = Math.max(
        0,
        this.next_allowed_request_start_miliseconds - now_miliseconds
      );
      if (wait_miliseconds > 0) {
        await SleepMilliseconds({ duration_miliseconds: wait_miliseconds });
      }
      this.next_allowed_request_start_miliseconds =
        Date.now() + minimum_spacing_miliseconds;
    } finally {
      release_gate();
    }
  }

  private async executeSingleTask(params: {
    request_task: request_task_t;
    timeout_miliseconds: number;
    rejectUnauthorized: boolean;
    max_body_preview_bytes: number;
    retry_policy: required_retry_policy_t;
  }): Promise<request_discovery_result_t> {
    const attempted_schemes: scheme_t[] = [];
    const attempts: request_attempt_t[] = [];
    const scheme_attempt_order: scheme_t[] = [
      params.request_task.preferred_scheme,
      params.request_task.fallback_scheme
    ];

    for (const scheme of scheme_attempt_order) {
      attempted_schemes.push(scheme);
      let low_level_result: low_level_request_result_t | null = null;
      for (
        let retry_index = 0;
        retry_index <= params.retry_policy.max_retries_per_scheme;
        retry_index += 1
      ) {
        low_level_result = await this.executeHttpRequest({
          scheme,
          host: params.request_task.host,
          tcp_port: params.request_task.tcp_port,
          path: params.request_task.path,
          method: params.request_task.method,
          timeout_miliseconds: params.timeout_miliseconds,
          rejectUnauthorized: params.rejectUnauthorized,
          max_body_preview_bytes: params.max_body_preview_bytes
        });

        attempts.push({
          scheme,
          attempt_number: retry_index + 1,
          successful_response: low_level_result.successful_response,
          error_type: low_level_result.error_type,
          error_message: low_level_result.error_message
        });

        if (low_level_result.successful_response) {
          const technologies = BuildTechnologiesFromHttpSignals({
            response_headers: low_level_result.response_headers,
            body_preview: low_level_result.body_preview
          });

          const content_length_header =
            low_level_result.response_headers['content-length'];
          const content_length =
            typeof content_length_header === 'string' &&
            Number.isFinite(Number(content_length_header))
              ? Number(content_length_header)
              : null;

          return {
            host: params.request_task.host,
            tcp_port: params.request_task.tcp_port,
            method: params.request_task.method,
            path: params.request_task.path,
            final_scheme: scheme,
            attempted_schemes,
            attempts,
            is_http_responsive: true,
            status_code: low_level_result.status_code,
            status_message: low_level_result.status_message,
            response_headers: low_level_result.response_headers,
            response_time_miliseconds:
              low_level_result.response_time_miliseconds,
            body_preview: low_level_result.body_preview,
            body_bytes_received: low_level_result.body_bytes_received,
            content_type:
              low_level_result.response_headers['content-type'] ?? null,
            content_length,
            technologies,
            error_type: null,
            error_message: null
          };
        }

        const retryable_error =
          low_level_result.error_type !== null &&
          params.retry_policy.retryable_error_types.includes(
            low_level_result.error_type as retry_error_type_t
          );
        const has_retries_remaining =
          retry_index < params.retry_policy.max_retries_per_scheme;
        const should_retry_same_scheme =
          low_level_result.should_try_fallback &&
          retryable_error &&
          has_retries_remaining;

        if (!should_retry_same_scheme) {
          break;
        }

        const backoff_delay_miliseconds = CalculateBackoffDelay({
          initial_backoff_miliseconds:
            params.retry_policy.initial_backoff_miliseconds,
          max_backoff_miliseconds: params.retry_policy.max_backoff_miliseconds,
          backoff_multiplier: params.retry_policy.backoff_multiplier,
          retry_index
        });
        if (backoff_delay_miliseconds > 0) {
          await SleepMilliseconds({
            duration_miliseconds: backoff_delay_miliseconds
          });
        }
      }

      if (!low_level_result) {
        continue;
      }

      if (!low_level_result.should_try_fallback) {
        return {
          host: params.request_task.host,
          tcp_port: params.request_task.tcp_port,
          method: params.request_task.method,
          path: params.request_task.path,
          final_scheme: null,
          attempted_schemes,
          attempts,
          is_http_responsive: false,
          status_code: null,
          status_message: null,
          response_headers: {},
          response_time_miliseconds: low_level_result.response_time_miliseconds,
          body_preview: '',
          body_bytes_received: 0,
          content_type: null,
          content_length: null,
          technologies: [],
          error_type: low_level_result.error_type,
          error_message: low_level_result.error_message
        };
      }
    }

    const final_attempt = attempts[attempts.length - 1];
    return {
      host: params.request_task.host,
      tcp_port: params.request_task.tcp_port,
      method: params.request_task.method,
      path: params.request_task.path,
      final_scheme: null,
      attempted_schemes,
      attempts,
      is_http_responsive: false,
      status_code: null,
      status_message: null,
      response_headers: {},
      response_time_miliseconds: null,
      body_preview: '',
      body_bytes_received: 0,
      content_type: null,
      content_length: null,
      technologies: [],
      error_type: final_attempt ? final_attempt.error_type : 'unknown',
      error_message: final_attempt
        ? final_attempt.error_message
        : 'Unknown request error.'
    };
  }

  private async executeHttpRequest(params: {
    scheme: scheme_t;
    host: string;
    tcp_port: number;
    path: string;
    method: string;
    timeout_miliseconds: number;
    rejectUnauthorized: boolean;
    max_body_preview_bytes: number;
  }): Promise<low_level_request_result_t> {
    const request_module = params.scheme === 'https' ? https : http;
    const started_at = performance.now();

    return new Promise<low_level_request_result_t>((resolve) => {
      let request_timed_out = false;

      const request = request_module.request(
        {
          hostname: params.host,
          port: params.tcp_port,
          method: params.method,
          path: params.path,
          timeout: params.timeout_miliseconds,
          rejectUnauthorized: params.rejectUnauthorized,
          headers: {
            Accept: '*/*',
            'User-Agent': '@opsimathically/webdiscovery'
          }
        },
        (response) => {
          const chunks: Buffer[] = [];
          let body_bytes_received = 0;
          let buffered_preview_bytes = 0;

          response.on('data', (chunk: Buffer) => {
            body_bytes_received += chunk.length;

            if (buffered_preview_bytes >= params.max_body_preview_bytes) {
              return;
            }

            const remaining_bytes =
              params.max_body_preview_bytes - buffered_preview_bytes;
            const preview_chunk = chunk.subarray(0, remaining_bytes);
            chunks.push(preview_chunk);
            buffered_preview_bytes += preview_chunk.length;
          });

          response.on('end', () => {
            const response_time_miliseconds = Math.round(
              performance.now() - started_at
            );
            resolve({
              successful_response: true,
              status_code: response.statusCode ?? null,
              status_message: response.statusMessage ?? null,
              response_headers: NormalizeHeaders({ headers: response.headers }),
              response_time_miliseconds,
              body_preview: Buffer.concat(chunks).toString('utf8'),
              body_bytes_received,
              error_type: null,
              error_message: null,
              should_try_fallback: false
            });
          });
        }
      );

      request.on('timeout', () => {
        request_timed_out = true;
        request.destroy(
          new Error(
            `Request timeout after ${params.timeout_miliseconds} miliseconds.`
          )
        );
      });

      request.on('error', (error: Error & { code?: string }) => {
        const response_time_miliseconds = Math.round(
          performance.now() - started_at
        );
        const classified_error = this.classifyError({
          error,
          request_timed_out
        });
        resolve({
          successful_response: false,
          status_code: null,
          status_message: null,
          response_headers: {},
          response_time_miliseconds,
          body_preview: '',
          body_bytes_received: 0,
          error_type: classified_error.error_type,
          error_message: error.message,
          should_try_fallback: classified_error.should_try_fallback
        });
      });

      request.end();
    });
  }

  private classifyError(params: {
    error: Error & { code?: string };
    request_timed_out: boolean;
  }): { error_type: string; should_try_fallback: boolean } {
    if (params.request_timed_out || params.error.code === 'ETIMEDOUT') {
      return { error_type: 'timeout', should_try_fallback: true };
    }

    const lower_message = params.error.message.toLowerCase();
    if (
      params.error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
      params.error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
      params.error.code === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
      lower_message.includes('tls') ||
      lower_message.includes('ssl') ||
      lower_message.includes('certificate')
    ) {
      return { error_type: 'tls', should_try_fallback: true };
    }

    if (
      params.error.code === 'ECONNREFUSED' ||
      params.error.code === 'ECONNRESET' ||
      params.error.code === 'EHOSTUNREACH' ||
      params.error.code === 'ENETUNREACH' ||
      params.error.code === 'ENOTFOUND'
    ) {
      return { error_type: 'connection', should_try_fallback: true };
    }

    return { error_type: 'unknown', should_try_fallback: false };
  }
}
