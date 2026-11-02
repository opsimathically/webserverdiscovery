import { WebServerDiscovery } from '@src/classes/webserverdiscovery/WebServerDiscovery.class';

(async function () {
  const webserverdiscovery = new WebServerDiscovery();
  const discovery_result = await webserverdiscovery.discover({
    host: process.env.WEBDISCOVERY_HOST ?? '127.0.0.1',
    tcp_ports: [22, 80, 443, 1716],
    methods: ['GET', 'POST', 'OPTIONS'],
    paths: ['/', '/admin', '/info'],
    timeout_miliseconds: 2000,
    rejectUnauthorized: false,
    concurrency: 10,
    rate_limit_per_second: 25
  });
  debugger;
})();
