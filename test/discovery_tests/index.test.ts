import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert';
import type { AddressInfo } from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { WebServerDiscovery } from '../../src/classes/webserverdiscovery/WebServerDiscovery.class';

// Generate this test-only TLS identity for this process; retain no static key.
function CreateTestTLSFixture(): { key: Buffer; cert: Buffer } {
  const directory = mkdtempSync(join(tmpdir(), 'webdiscovery-tls-test-'));
  try {
    const keyPath = join(directory, 'key.pem');
    const certPath = join(directory, 'cert.pem');
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1',
      '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'
    ], { stdio: 'ignore' });
    return { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
const { key: TEST_PRIVATE_KEY, cert: TEST_CERTIFICATE } = CreateTestTLSFixture();


function GetListeningPort(params: {
  server: http.Server | https.Server;
}): number {
  const address_info = params.server.address() as AddressInfo | null;
  if (!address_info || typeof address_info.port !== 'number') {
    throw new Error('Failed to retrieve listening port.');
  }
  return address_info.port;
}

function ListenServer(params: {
  server: http.Server | https.Server;
  tcp_port?: number;
}): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    params.server.once('error', reject);
    params.server.listen(params.tcp_port ?? 0, '127.0.0.1', () => {
      params.server.off('error', reject);
      resolve();
    });
  });
}

function CloseServer(params: { server: http.Server | https.Server }): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    params.server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

test('discover identifies responsive services and technologies', async function () {
  const http_server = http.createServer((request, response) => {
    response.setHeader('Server', 'nginx/1.24.0');
    response.setHeader('X-Powered-By', 'PHP/8.2');
    response.setHeader('Set-Cookie', 'wordpress_test=1; Path=/');
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (request.url === '/admin' && request.method === 'POST') {
      response.statusCode = 403;
      response.end('<html><body>wp-content denied</body></html>');
      return;
    }
    response.statusCode = 200;
    response.end('<html><body><a href="/wp-content/themes/default">site</a></body></html>');
  });

  await ListenServer({ server: http_server });
  try {
    const webserverdiscovery = new WebServerDiscovery();
    const discovery_result = await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [GetListeningPort({ server: http_server })],
      methods: ['GET', 'POST'],
      paths: ['/', '/admin'],
      timeout_miliseconds: 1000,
      rejectUnauthorized: false,
      concurrency: 4,
      rate_limit_per_second: 50
    });

    assert.equal(discovery_result.request_count, 4);
    assert.equal(discovery_result.summary.successful_requests, 4);
    assert.equal(discovery_result.summary.failed_requests, 0);
    assert.equal(discovery_result.summary.responsive_ports, 1);

    assert.ok(
      discovery_result.identified_technologies.some(
        (technology) => technology.technology_id === 'nginx'
      )
    );
    assert.ok(
      discovery_result.identified_technologies.some(
        (technology) => technology.technology_id === 'php'
      )
    );
    assert.ok(
      discovery_result.identified_technologies.some(
        (technology) => technology.technology_id === 'wordpress'
      )
    );
  } finally {
    await CloseServer({ server: http_server });
  }
});

test('discover supports fallback from http to https on the same tcp port', async function () {
  const https_server = https.createServer(
    {
      key: TEST_PRIVATE_KEY,
      cert: TEST_CERTIFICATE
    },
    (request, response) => {
      response.setHeader('Server', 'Microsoft-IIS/10.0');
      response.setHeader('X-Powered-By', 'ASP.NET');
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      response.statusCode = 200;
      response.end(`<html><body>secure endpoint ${request.url}</body></html>`);
    }
  );

  await ListenServer({ server: https_server });
  try {
    const webserverdiscovery = new WebServerDiscovery();
    const discovery_result = await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [GetListeningPort({ server: https_server })],
      methods: ['GET'],
      paths: ['/'],
      timeout_miliseconds: 1000,
      rejectUnauthorized: false
    });

    assert.equal(discovery_result.summary.successful_requests, 1);
    assert.equal(discovery_result.request_results[0].final_scheme, 'https');
    assert.deepEqual(discovery_result.request_results[0].attempted_schemes, [
      'http',
      'https'
    ]);
    assert.ok(
      discovery_result.identified_technologies.some(
        (technology) => technology.technology_id === 'iis'
      )
    );
    assert.ok(
      discovery_result.identified_technologies.some(
        (technology) => technology.technology_id === 'asp_net'
      )
    );
  } finally {
    await CloseServer({ server: https_server });
  }
});

test('discover reports tls failures when rejectUnauthorized is true against self-signed certs', async function () {
  const https_server = https.createServer(
    {
      key: TEST_PRIVATE_KEY,
      cert: TEST_CERTIFICATE
    },
    (_request, response) => {
      response.statusCode = 200;
      response.end('ok');
    }
  );

  await ListenServer({ server: https_server });
  try {
    const webserverdiscovery = new WebServerDiscovery();
    const discovery_result = await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [GetListeningPort({ server: https_server })],
      methods: ['GET'],
      paths: ['/'],
      timeout_miliseconds: 1000,
      rejectUnauthorized: true
    });

    assert.equal(discovery_result.summary.successful_requests, 0);
    assert.equal(discovery_result.summary.failed_requests, 1);
    assert.equal(discovery_result.request_results[0].error_type, 'tls');
  } finally {
    await CloseServer({ server: https_server });
  }
});

test('discover captures timeout attempts', async function () {
  const timeout_server = http.createServer((_request, response) => {
    setTimeout(() => {
      response.statusCode = 200;
      response.end('slow');
    }, 250);
  });

  await ListenServer({ server: timeout_server });
  try {
    const timeout_server_port = GetListeningPort({ server: timeout_server });
    const webserverdiscovery = new WebServerDiscovery();
    const discovery_result = await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [timeout_server_port],
      methods: ['GET'],
      paths: ['/'],
      timeout_miliseconds: 40,
      rejectUnauthorized: false
    });

    assert.equal(discovery_result.summary.failed_requests, 1);
    assert.ok(
      discovery_result.request_results[0].attempts.some(
        (attempt) => attempt.error_type === 'timeout'
      )
    );
  } finally {
    await CloseServer({ server: timeout_server });
  }
});

test('discover validates required inputs', async function () {
  const webserverdiscovery = new WebServerDiscovery();
  await assert.rejects(async () => {
    await webserverdiscovery.discover({
      host: '',
      tcp_ports: [80],
      methods: ['GET'],
      paths: ['/']
    });
  });
  await assert.rejects(async () => {
    await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [],
      methods: ['GET'],
      paths: ['/']
    });
  });
  await assert.rejects(async () => {
    await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [80],
      methods: [''],
      paths: ['/']
    });
  });
  await assert.rejects(async () => {
    await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [80],
      methods: ['GET'],
      paths: ['/'],
      retry_policy: {
        max_retries_per_scheme: -1
      }
    });
  });
});

test('discover enforces rate limiting even when concurrency is high', async function () {
  const request_start_timestamps: number[] = [];
  let active_request_count = 0;
  let max_active_request_count = 0;

  const http_server = http.createServer((_request, response) => {
    request_start_timestamps.push(Date.now());
    active_request_count += 1;
    max_active_request_count = Math.max(max_active_request_count, active_request_count);

    setTimeout(() => {
      active_request_count -= 1;
      response.statusCode = 200;
      response.end('ok');
    }, 120);
  });

  await ListenServer({ server: http_server });
  try {
    const webserverdiscovery = new WebServerDiscovery();
    const discovery_result = await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [GetListeningPort({ server: http_server })],
      methods: ['GET'],
      paths: ['/one', '/two', '/three', '/four'],
      timeout_miliseconds: 1000,
      rejectUnauthorized: false,
      concurrency: 4,
      rate_limit_per_second: 5
    });

    assert.equal(discovery_result.summary.successful_requests, 4);
    assert.equal(request_start_timestamps.length, 4);

    const request_span_miliseconds =
      request_start_timestamps[request_start_timestamps.length - 1] -
      request_start_timestamps[0];
    assert.ok(request_span_miliseconds >= 450);
    assert.equal(max_active_request_count, 1);
  } finally {
    await CloseServer({ server: http_server });
  }
});

test('discover uses concurrency when rate limiting is disabled', async function () {
  let active_request_count = 0;
  let max_active_request_count = 0;

  const http_server = http.createServer((_request, response) => {
    active_request_count += 1;
    max_active_request_count = Math.max(max_active_request_count, active_request_count);

    setTimeout(() => {
      active_request_count -= 1;
      response.statusCode = 200;
      response.end('ok');
    }, 120);
  });

  await ListenServer({ server: http_server });
  try {
    const webserverdiscovery = new WebServerDiscovery();
    const discovery_result = await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [GetListeningPort({ server: http_server })],
      methods: ['GET'],
      paths: ['/one', '/two', '/three', '/four'],
      timeout_miliseconds: 1000,
      rejectUnauthorized: false,
      concurrency: 4,
      rate_limit_per_second: null
    });

    assert.equal(discovery_result.summary.successful_requests, 4);
    assert.ok(max_active_request_count >= 2);
  } finally {
    await CloseServer({ server: http_server });
  }
});

test('discover retries per scheme with exponential backoff and recovers from transient errors', async function () {
  let request_count = 0;
  const http_server = http.createServer((request, response) => {
    request_count += 1;
    if (request_count < 3) {
      request.socket.destroy();
      return;
    }
    response.statusCode = 200;
    response.end('ok');
  });

  await ListenServer({ server: http_server });
  try {
    const webserverdiscovery = new WebServerDiscovery();
    const started_at_miliseconds = Date.now();
    const discovery_result = await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [GetListeningPort({ server: http_server })],
      methods: ['GET'],
      paths: ['/'],
      timeout_miliseconds: 1000,
      rejectUnauthorized: false,
      retry_policy: {
        max_retries_per_scheme: 3,
        initial_backoff_miliseconds: 40,
        max_backoff_miliseconds: 200,
        backoff_multiplier: 2,
        retryable_error_types: ['connection']
      }
    });
    const finished_at_miliseconds = Date.now();

    assert.equal(discovery_result.summary.successful_requests, 1);
    assert.equal(discovery_result.request_results[0].attempts.length, 3);
    assert.deepEqual(
      discovery_result.request_results[0].attempts.map(
        (attempt) => attempt.attempt_number
      ),
      [1, 2, 3]
    );
    assert.ok(finished_at_miliseconds - started_at_miliseconds >= 100);
  } finally {
    await CloseServer({ server: http_server });
  }
});

test('discover identifies expanded framework and cms fingerprints', async function () {
  const http_server = http.createServer((_request, response) => {
    response.setHeader('Server', 'gunicorn');
    response.setHeader('X-Powered-By', 'Express Fastify NestJS Node.js');
    response.setHeader(
      'X-Generator',
      'Joomla! - Open Source Content Management'
    );
    response.setHeader('X-Django-Version', '5.1');
    response.setHeader('X-Laravel-Version', '11');
    response.setHeader('X-Application-Context', 'application:prod');
    response.setHeader(
      'Set-Cookie',
      'csrftoken=abc; laravel_session=def; connect.sid=ghi; __next_preview_data=123'
    );
    response.statusCode = 200;
    response.setHeader('Content-Type', 'text/html');
    response.end(`
      <html>
        <head>
          <meta name="csrf-token" content="token" />
          <script src="/media/system/js/core.js"></script>
        </head>
        <body>
          <input type="hidden" name="csrfmiddlewaretoken" value="token" />
          <div id="__next">app</div>
          Whitelabel Error Page
        </body>
      </html>
    `);
  });

  await ListenServer({ server: http_server });
  try {
    const webserverdiscovery = new WebServerDiscovery();
    const discovery_result = await webserverdiscovery.discover({
      host: '127.0.0.1',
      tcp_ports: [GetListeningPort({ server: http_server })],
      methods: ['GET'],
      paths: ['/'],
      timeout_miliseconds: 1000,
      rejectUnauthorized: false
    });

    const technology_ids = discovery_result.identified_technologies.map(
      (technology) => technology.technology_id
    );
    assert.ok(technology_ids.includes('joomla'));
    assert.ok(technology_ids.includes('django'));
    assert.ok(technology_ids.includes('laravel'));
    assert.ok(technology_ids.includes('spring'));
    assert.ok(technology_ids.includes('express'));
    assert.ok(technology_ids.includes('fastify'));
    assert.ok(technology_ids.includes('nestjs'));
    assert.ok(technology_ids.includes('nextjs'));
  } finally {
    await CloseServer({ server: http_server });
  }
});
